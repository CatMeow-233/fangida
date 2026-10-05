"""与 ``json.JSONEncoder.iterencode`` 逐字节一致的分块 JSON 流式编码（包内私有实现）。

本模块只供 Fangida 包内使用（CLI 导出、测速摘要、数据库/项目快照输出），不属于公开 API，
可随实现调整。包内调用方依赖的接口：``dump``、``iterencode``、``iterencode_with``、
``c_indent_supported``、``c_compact_supported`` 与 ``DEFAULT_CHUNK_SIZE``。

标准库 ``JSONEncoder.iterencode`` 为了“流式”总是走纯 Python 生成器编码器：每个标点、
每个标量都会产生一次 ``yield``，调用方再做一次 ``write``。完整分析结果有数百 MB、
数千万个 token，这条路径比分析本身还慢。

本模块的做法：

* 只在“大”容器上做结构化下钻（纯 Python，但只涉及少量顶层节点），且最多下钻
  ``_MAX_DESCENT`` 层，更深的子树整体交给单元编码器；
* 对规模可控的子树（下文称“单元”）调用一次性编码器：
  - CPython 的 C 编码器支持当前参数时（紧凑格式在 3.11+ 都支持；带 ``indent`` 只有
    3.13+ 支持），直接调用 ``json.encoder.c_make_encoder``，并把当前缩进层级与
    ``markers``（循环引用检测表）传进去，因此缩进与循环检测语义都与标准库完全一致；
    两种格式在首次使用时都会与标准库纯 Python 输出逐字节自检，构造失败或自检不一致
    （私有接口变化、3.11/3.12 忽略缩进参数等）都会自动回退；
  - 否则（例如 3.11/3.12 + indent）使用本模块的纯 Python 单元编码器：它逐条移植
    ``json.encoder._make_iterencode`` 的分支顺序与输出格式，但用递归 + list.append
    代替多层 ``yield from`` 生成器，并为精确内置类型提供快速分支；
* 列表按自适应切片批量编码，输出合并成约 ``chunk_size`` 字符的块，额外峰值内存约为
  ``max(chunk_size, 最大单个元素的编码)``，不会一次性生成完整字符串；
* ``check_circular=False`` 时完全沿用标准库流式编码，只把小片段合并成块：没有循环检测时，
  单元编码会在遇到环之前把整段输出累积在内存里，而标准库是边产出边在递归上限处报错。

已知差异（只影响异常路径或极端类型）：

* 编码中途抛出异常时，已经交给调用方的前缀长度与标准库不同（标准库逐 token 输出）；
* C 单元编码器判断容器是否为空时看底层存储的元素数，纯 Python 标准库调用
  ``__len__``/``__bool__``；因此“覆写了 ``__len__``/``__bool__`` 的 list/dict 子类”
  输出可能不同——这与 ``json.dumps`` 在 C/纯 Python 之间的既有差异相同（覆写
  ``__iter__`` 的子类两边都会调用 ``__iter__``，没有差异）。Fangida 结果只包含内置精确
  类型，不受影响；
* 嵌套极深的数据：C 编码器使用 C 递归上限，而标准库纯 Python 编码器受
  ``sys.getrecursionlimit()`` 约束；C 单元抛出 ``RecursionError`` 时本模块会用纯 Python
  单元编码器重试一次该单元，从而不会比标准库更早失败。
"""
from __future__ import annotations

from itertools import islice
import json
from json import encoder as _std
from typing import Any, Callable, Iterable, Iterator

#: 默认输出块大小（字符数）。1 MiB 在写文件/计算摘要时已经足够摊薄调用开销。
DEFAULT_CHUNK_SIZE = 1 << 20
#: 判断一个容器是否“足够小、可直接整体编码”时最多访问的节点数。
_SMALL_BUDGET = 64
#: 单次切片的最大元素数，防止由极小元素推算出过大的切片。
_MAX_SLICE = 1 << 16
#: 达到这个元素数的字典才考虑按条目切片批量编码；小字典逐项处理更简单。
_DICT_SLICE_MIN = 256
#: 只在前几层下钻；更深的子树整体交给单元编码器，使深嵌套的递归行为接近标准库。
_MAX_DESCENT = 8

# C 编码器自检结果缓存（None 表示尚未探测）；测试可直接改写它们来强制走纯 Python 单元。
_C_INDENT_OK: bool | None = None
_C_COMPACT_OK: bool | None = None


def _default_raise(o: Any) -> Any:
    """与 ``JSONEncoder.default`` 相同的错误信息，供自检使用。"""
    raise TypeError(f"Object of type {o.__class__.__name__} is not JSON serializable")


def _make_floatstr(allow_nan: bool) -> Callable[[float], str]:
    """逐行移植标准库 ``iterencode`` 内部的 ``floatstr``，保证 NaN/Infinity 文本一致。"""
    _repr = float.__repr__
    _inf = float("inf")
    _neginf = -_inf

    def floatstr(o: float) -> str:
        if o != o:
            text = "NaN"
        elif o == _inf:
            text = "Infinity"
        elif o == _neginf:
            text = "-Infinity"
        else:
            return _repr(o)
        if not allow_nan:
            raise ValueError("Out of range float values are not JSON compliant: " + repr(o))
        return text
    return floatstr


def _probe() -> Any:
    """覆盖空容器、tuple、非 str 键、转义、Unicode、浮点特殊值和多层嵌套的自检样本。"""
    return {"a": [1, -2.5, 1e300, 0.1, float("inf"), float("-inf"), float("nan"),
                  True, False, None, "x\n\"\\\x01é 😀"],
            "": {}, "b": [], "c": ({"d": [[], [{}], (2, 3)]},), 7: "int key",
            2.5: "float key", None: 0, True: [0], "z": {"y": {"x": [[[1]]]}}}


def _check_c_indent() -> bool:
    """确认 C 编码器能按给定层级输出与标准库纯 Python 完全一致的缩进文本。

    参照输出只使用公开 API：``JSONEncoder(indent=...).iterencode`` 在非 one-shot
    模式下始终是纯 Python 实现；层级 L 的期望文本等于层级 0 文本把每个换行替换为
    “换行 + L 份缩进”（JSON 字符串中的换行一定被转义，替换是安全的）。
    """
    make = getattr(_std, "c_make_encoder", None)
    if make is None:
        return False
    probe = _probe()
    for indent in ("  ", "\t", ""):
        for ensure_ascii in (True, False):
            reference = "".join(json.JSONEncoder(indent=indent, ensure_ascii=ensure_ascii)
                                .iterencode(probe))
            str_encoder = (_std.encode_basestring_ascii if ensure_ascii
                           else _std.encode_basestring)
            for level in (0, 3):
                try:
                    fast = make({}, _default_raise, str_encoder, indent, ": ", ",",
                                False, False, True)
                    text = "".join(fast(probe, level))
                except Exception:  # 旧版本可能拒绝 str 缩进参数，视为不支持
                    return False
                if text != reference.replace("\n", "\n" + indent * level):
                    return False
    return True


def c_compact_supported() -> bool:
    """紧凑格式下 C 编码器（按本模块的调用方式）是否与标准库纯 Python 输出一致（结果缓存）。"""
    global _C_COMPACT_OK
    if _C_COMPACT_OK is None:
        make = getattr(_std, "c_make_encoder", None)
        ok = make is not None
        probe = _probe()
        for ensure_ascii in (True, False):
            if not ok:
                break
            for seps in ((", ", ": "), (",", ":")):
                reference = "".join(json.JSONEncoder(ensure_ascii=ensure_ascii, separators=seps)
                                    .iterencode(probe))
                str_encoder = (_std.encode_basestring_ascii if ensure_ascii
                               else _std.encode_basestring)
                try:
                    text = "".join(make({}, _default_raise, str_encoder, None, seps[1], seps[0],
                                        False, False, True)(probe, 0))
                except Exception:
                    ok = False
                    break
                if text != reference:
                    ok = False
                    break
        _C_COMPACT_OK = ok
    return _C_COMPACT_OK


def c_indent_supported() -> bool:
    """当前解释器的 C 编码器是否可用于带缩进的单元编码（结果缓存）。"""
    global _C_INDENT_OK
    if _C_INDENT_OK is None:
        _C_INDENT_OK = _check_c_indent()
    return _C_INDENT_OK


class _Streamer:
    """一次编码调用的状态：选项、共享 markers、单元编码器和换行缓存。"""

    def __init__(self, encoder: json.JSONEncoder, chunk_size: int) -> None:
        self.chunk_size = _check_chunk_size(chunk_size)
        # 与标准库 iterencode 完全相同的参数归一化方式。
        self.markers: dict[int, Any] | None = {} if encoder.check_circular else None
        indent = encoder.indent
        if indent is not None and not isinstance(indent, str):
            indent = " " * indent
        self.indent: str | None = indent
        self.key_sep = encoder.key_separator
        self.item_sep = encoder.item_separator
        self.sort_keys = encoder.sort_keys
        self.skipkeys = encoder.skipkeys
        self.allow_nan = encoder.allow_nan
        self.default = encoder.default
        self.str_encoder = (_std.encode_basestring_ascii if encoder.ensure_ascii
                            else _std.encode_basestring)
        self.floatstr = _make_floatstr(encoder.allow_nan)
        self._newlines: list[str] = []
        self.python_unit = self._make_python_unit()
        self.c_unit = self._make_c_unit()

    # ------------------------------------------------------------------ helpers
    def newline(self, level: int) -> str:
        """返回 '\\n' + indent*level；紧凑模式返回空串。"""
        if self.indent is None:
            return ""
        cache = self._newlines
        while len(cache) <= level:
            cache.append("\n" + self.indent * len(cache))
        return cache[level]

    def key_text(self, key: Any) -> str | None:
        """按标准库规则把字典键转换成 JSON 字符串；返回 None 表示 skipkeys 跳过。"""
        if isinstance(key, str):
            pass
        elif isinstance(key, float):
            key = self.floatstr(key)
        elif key is True:
            key = "true"
        elif key is False:
            key = "false"
        elif key is None:
            key = "null"
        elif isinstance(key, int):
            key = int.__repr__(key)
        elif self.skipkeys:
            return None
        else:
            raise TypeError(f"keys must be str, int, float, bool or None, "
                            f"not {key.__class__.__name__}")
        return self.str_encoder(key)

    def unit(self, value: Any, level: int) -> str:
        """一次性编码一个子树，层级为 ``level``。"""
        if self.c_unit is not None:
            markers = self.markers
            depth = len(markers) if markers is not None else 0
            try:
                return self.c_unit(value, level)
            except RecursionError:
                # C 递归上限与 Python 不同；退回纯 Python 以免比标准库更早失败。
                # C 编码器出错时不清理 markers：只保留调用前的祖先条目（插入有序）。
                if markers is not None:
                    for stale in list(markers)[depth:]:
                        del markers[stale]
        return self.python_unit(value, level)

    def _make_c_unit(self) -> Callable[[Any, int], str] | None:
        make = getattr(_std, "c_make_encoder", None)
        if make is None or not (c_indent_supported() if self.indent is not None
                                else c_compact_supported()):
            return None
        try:
            encode = make(self.markers, self.default, self.str_encoder, self.indent,
                          self.key_sep, self.item_sep, self.sort_keys, self.skipkeys,
                          self.allow_nan)
        except (TypeError, ValueError):  # 私有接口签名变化：退回纯 Python 单元
            return None
        join = "".join

        def c_unit(value: Any, level: int) -> str:
            # 3.13+ 返回单元素 tuple，3.11/3.12 返回列表；join 单元素时不复制。
            return join(encode(value, level))
        return c_unit

    def _make_python_unit(self) -> Callable[[Any, int], str]:
        """纯 Python 单元编码器：逐条移植 ``_make_iterencode`` 的分支顺序。

        对精确内置类型（str/int/dict/list/tuple）先走 ``type(x) is ...`` 快速分支，
        其余对象（bool/None/float/子类/需要 default 的对象）走与标准库同序的
        isinstance 判断链，因此输出逐字节一致。用递归 + list.append 代替多层
        ``yield from``，并缓存每一层的括号/分隔符文本与常用键的编码结果。
        """
        markers = self.markers
        enc = self.str_encoder
        floatstr = self.floatstr
        key_text = self.key_text
        default = self.default
        indent = self.indent
        key_sep = self.key_sep
        item_sep = self.item_sep
        sort_keys = self.sort_keys
        intstr = int.__repr__
        _str, _int, _dict, _list, _tuple = str, int, dict, list, tuple
        # frames[level] = (元素分隔符, '[' 开头, ']' 结尾, '{' 开头, '}' 结尾)，
        # 对应“位于 level 层的容器”，其成员位于 level+1 层。
        frames: list[tuple[str, str, str, str, str]] = []
        # 精确 str 键 -> 编码后的 '"key"' + key_separator；容量有上限，避免键空间很大时无界增长。
        key_cache: dict[str, str] = {}
        key_cache_limit = 4096

        def frame(level: int) -> tuple[str, str, str, str, str]:
            while len(frames) <= level:
                depth = len(frames)
                inner = "" if indent is None else "\n" + indent * (depth + 1)
                outer = "" if indent is None else "\n" + indent * depth
                frames.append((item_sep + inner, "[" + inner, outer + "]",
                               "{" + inner, outer + "}"))
            return frames[level]

        def encode_any(o: Any, level: int, append: Callable[[str], Any]) -> None:
            # 与标准库 _iterencode 相同的判断顺序。
            if isinstance(o, _str):
                append(enc(o))
            elif o is None:
                append("null")
            elif o is True:
                append("true")
            elif o is False:
                append("false")
            elif isinstance(o, _int):
                append(intstr(o))
            elif isinstance(o, float):
                append(floatstr(o))
            elif isinstance(o, (_list, _tuple)):
                encode_list(o, level, append)
            elif isinstance(o, _dict):
                encode_dict(o, level, append)
            else:
                if markers is not None:
                    markerid = id(o)
                    if markerid in markers:
                        raise ValueError("Circular reference detected")
                    markers[markerid] = o
                encode_any(default(o), level, append)
                if markers is not None:
                    del markers[markerid]

        def encode_list(lst: Any, level: int, append: Callable[[str], Any]) -> None:
            if not lst:
                append("[]")
                return
            if markers is not None:
                markerid = id(lst)
                if markerid in markers:
                    raise ValueError("Circular reference detected")
                markers[markerid] = lst
            try:
                separator, opening, closing = frames[level][:3]
            except IndexError:
                separator, opening, closing = frame(level)[:3]
            kind = type(lst)
            if (kind is _list or kind is _tuple) and type(lst[0]) is _str:
                # 纯字符串列表（操作数/寄存器列表）整体交给 C 级 map/join。
                try:
                    body = separator.join(map(enc, lst))
                except TypeError:
                    pass  # 混合类型：落回逐项编码，此前没有写出任何内容
                else:
                    append(opening + body + closing)
                    if markers is not None:
                        del markers[markerid]
                    return
            inner = level + 1
            prefix = opening
            for value in lst:
                kind = type(value)
                if kind is _str:
                    append(prefix + enc(value))
                elif kind is _int:
                    append(prefix + intstr(value))
                else:
                    append(prefix)
                    if kind is _dict:
                        encode_dict(value, inner, append)
                    elif kind is _list or kind is _tuple:
                        encode_list(value, inner, append)
                    else:
                        encode_any(value, inner, append)
                prefix = separator
            append(closing)
            if markers is not None:
                del markers[markerid]

        def encode_dict(dct: Any, level: int, append: Callable[[str], Any]) -> None:
            if not dct:
                append("{}")
                return
            if markers is not None:
                markerid = id(dct)
                if markerid in markers:
                    raise ValueError("Circular reference detected")
                markers[markerid] = dct
            try:
                separator, _, _, opening, closing = frames[level]
            except IndexError:
                separator, _, _, opening, closing = frame(level)
            inner = level + 1
            prefix = opening
            emitted = False
            items = sorted(dct.items()) if sort_keys else dct.items()
            for key, value in items:
                if type(key) is _str:
                    text = key_cache.get(key)
                    if text is None:
                        text = enc(key) + key_sep
                        if len(key_cache) < key_cache_limit:
                            key_cache[key] = text
                else:
                    text = key_text(key)
                    if text is None:
                        continue  # skipkeys
                    text += key_sep
                kind = type(value)
                if kind is _str:
                    append(prefix + text + enc(value))
                elif kind is _int:
                    append(prefix + text + intstr(value))
                else:
                    append(prefix + text)
                    if kind is _dict:
                        encode_dict(value, inner, append)
                    elif kind is _list or kind is _tuple:
                        encode_list(value, inner, append)
                    else:
                        encode_any(value, inner, append)
                prefix = separator
                emitted = True
            if not emitted:
                # 所有键都被 skipkeys 跳过：标准库仍会输出 '{' 和换行缩进。
                append(opening)
            append(closing)
            if markers is not None:
                del markers[markerid]

        def python_unit(value: Any, level: int) -> str:
            parts: list[str] = []
            encode_any(value, level, parts.append)
            return "".join(parts)
        return python_unit

    # ----------------------------------------------------------------- descent
    def small(self, value: Any) -> bool:
        """在 ``_SMALL_BUDGET`` 个节点的访问预算内判断子树是否足够小。"""
        budget = _SMALL_BUDGET
        stack = [value]
        pop, extend = stack.pop, stack.extend
        while stack:
            item = pop()
            kind = type(item)
            if kind is dict:
                budget -= len(item) + 1
                if budget < 0:
                    return False
                extend(item.values())
            elif kind is list or kind is tuple:
                budget -= len(item) + 1
                if budget < 0:
                    return False
                extend(item)
        return True

    def walk(self, value: Any, level: int) -> Iterator[str]:
        kind = type(value)
        if (level < _MAX_DESCENT and (kind is dict or kind is list or kind is tuple)
                and value and not self.small(value)):
            if kind is dict:
                yield from self.walk_dict(value, level)
            else:
                yield from self.walk_list(value, level)
        else:
            yield self.unit(value, level)

    def _enter(self, container: Any) -> int | None:
        if self.markers is None:
            return None
        markerid = id(container)
        if markerid in self.markers:
            raise ValueError("Circular reference detected")
        self.markers[markerid] = container
        return markerid

    def _leave(self, markerid: int | None) -> None:
        if markerid is not None:
            del self.markers[markerid]  # type: ignore[union-attr]

    def _next_slice(self, size: int, count: int) -> int:
        """根据上一组的实际输出长度调整下一组元素数（慢启动，最多翻倍）。"""
        target = self.chunk_size
        if size >= target * count:
            return 1  # 单个元素已经很大：逐个下钻，避免一次性编码巨型子树
        estimate = (target * count) // max(size, 1)
        return max(1, min(count * 2, estimate, _MAX_SLICE))

    def walk_list(self, lst: Any, level: int) -> Iterator[str]:
        markerid = self._enter(lst)
        inner = level + 1
        nl = self.newline(inner)
        opening, separator, closing = "[" + nl, self.item_sep + nl, self.newline(level) + "]"
        yield opening
        total, index, step = len(lst), 0, 1
        head, tail = len(opening), len(closing)
        while index < total:
            if index:
                yield separator
            if step == 1:
                size = 0
                for piece in self.walk(lst[index], inner):
                    size += len(piece)
                    yield piece
                count = 1
            else:
                group = lst[index:index + step]
                count = len(group)
                text = self.unit(group, level)
                body = text[head:len(text) - tail]  # 去掉切片自身的 '[' 与 ']' 外壳
                size = len(body)
                yield body
            index += count
            step = self._next_slice(size, count)
        yield closing
        self._leave(markerid)

    def walk_dict(self, dct: dict, level: int) -> Iterator[str]:
        markerid = self._enter(dct)
        inner = level + 1
        nl = self.newline(inner)
        opening, separator, closing = "{" + nl, self.item_sep + nl, self.newline(level) + "}"
        key_sep = self.key_sep
        prefix = opening
        emitted = False
        # 排序或 skipkeys 时逐项处理，保证顺序/跳过规则与标准库一字不差。
        sliceable = (not self.sort_keys and not self.skipkeys and len(dct) >= _DICT_SLICE_MIN)
        items = iter(sorted(dct.items()) if self.sort_keys else dct.items())
        step = 1
        head, tail = len(opening), len(closing)
        while True:
            if sliceable and step > 1:
                group = dict(islice(items, step))
                if not group:
                    break
                text = self.unit(group, level)
                body = text[head:len(text) - tail]
                yield prefix
                prefix = separator
                emitted = True
                yield body
                step = self._next_slice(len(body), len(group))
                continue
            entry = next(items, None)
            if entry is None:
                break
            key, value = entry
            key = self.key_text(key)
            if key is None:
                continue
            yield prefix + key + key_sep
            prefix = separator
            emitted = True
            size = 0
            for piece in self.walk(value, inner):
                size += len(piece)
                yield piece
            if sliceable:
                step = self._next_slice(size, 1)
        if not emitted:
            # 非空字典但所有键都被跳过：标准库输出 '{' + 换行缩进 + 换行 + '}'。
            yield opening
        yield closing
        self._leave(markerid)

    def run(self, obj: Any) -> Iterator[str]:
        """把下钻产生的片段合并成约 chunk_size 的块。"""
        target = self.chunk_size
        buffer: list[str] = []
        pending = 0
        join = "".join
        for piece in self.walk(obj, 0):
            length = len(piece)
            if length >= target:
                if buffer:
                    yield join(buffer)
                    buffer, pending = [], 0
                yield piece  # 大单元直接交出，避免再拼接复制
                continue
            if length:
                buffer.append(piece)
                pending += length
                if pending >= target:
                    yield join(buffer)
                    buffer, pending = [], 0
        if buffer:
            yield join(buffer)


def _check_chunk_size(chunk_size: Any) -> int:
    """块大小必须是正的精确 int（拒绝 bool 等子类），在调用时立即校验而不是推迟到首次迭代。"""
    if type(chunk_size) is not int or chunk_size <= 0:
        raise ValueError("chunk_size must be a positive integer")
    return chunk_size


def iterencode_with(encoder: json.JSONEncoder, obj: Any, *,
                    chunk_size: int = DEFAULT_CHUNK_SIZE) -> Iterator[str]:
    """使用现有 ``JSONEncoder`` 实例的选项（含子类覆写的 ``default``）分块编码。"""
    _check_chunk_size(chunk_size)
    if not encoder.check_circular:
        # 无循环检测时，单元编码会在遇到环之前把整段输出累积在内存中（标准库是逐 token
        # 产出并在递归上限处报错）；这种情况直接沿用标准库流式编码，只做合并写出。
        return _buffered(encoder.iterencode(obj), chunk_size)
    return _Streamer(encoder, chunk_size).run(obj)


def _buffered(chunks: Iterable[str], chunk_size: int) -> Iterator[str]:
    """把标准库逐 token 产出的小片段合并成约 ``chunk_size`` 字符的块（不产出空块）。"""
    buffer: list[str] = []
    pending = 0
    for piece in chunks:
        if piece:
            buffer.append(piece)
            pending += len(piece)
            if pending >= chunk_size:
                yield "".join(buffer)
                buffer, pending = [], 0
    if buffer:
        yield "".join(buffer)


def iterencode(obj: Any, *, chunk_size: int = DEFAULT_CHUNK_SIZE, **options: Any) -> Iterator[str]:
    """按块产出 ``json.JSONEncoder(**options).iterencode(obj)`` 的同一段文本。"""
    return iterencode_with(json.JSONEncoder(**options), obj, chunk_size=chunk_size)


def dumps(obj: Any, **options: Any) -> str:
    """返回与 ``json.dumps(obj, **options)`` 相同的完整字符串。

    C 编码器支持当前参数时直接调用 ``json.dumps``；只有带 ``indent`` 而 C 编码器不支持
    （3.11/3.12）时，才用分块编码器拼出同一段文本。调用方先拿到完整字符串再写出，
    因此序列化或输出编码失败时不会留下半截内容，与原来的 ``print(json.dumps(...))`` 一致。
    """
    if options.get("indent") is None or c_indent_supported():
        return json.dumps(obj, **options)
    return "".join(iterencode(obj, **options))


def dump(obj: Any, stream: Any, *, chunk_size: int = DEFAULT_CHUNK_SIZE, **options: Any) -> None:
    """把 ``obj`` 以较大的块写入文本流，内容与标准库流式编码逐字节一致。"""
    write = stream.write
    for chunk in iterencode(obj, chunk_size=chunk_size, **options):
        write(chunk)
