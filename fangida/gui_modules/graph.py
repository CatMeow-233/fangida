"""只读 CFG 布局与按视口绘制的桌面图形视图。

本模块不加载文件、不解码指令、不推导新的控制流。布局保留所有输入
基本块；Canvas 项目数只由当前视口决定。指令对象保持引用，避免复制 IR。
"""
from __future__ import annotations

from bisect import bisect_right
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable


BLOCK_WIDTH = 330.0
COLUMN_GAP = 80.0
ROW_GAP = 95.0
LINE_HEIGHT = 19.0
PREVIEW_INSTRUCTIONS = 6
MAX_RENDER_BLOCKS = 350
MAX_RENDER_EDGES = 900
MIN_SCALE = 0.25
MAX_SCALE = 2.5


def _address(value: Any) -> bool:
    return type(value) is int and value >= 0


def _records(value: Any) -> list:
    return value if isinstance(value, list) else []


def _instruction_line(instruction: dict) -> str:
    location = instruction.get("addr")
    address = f"{location:x}" if _address(location) else "?"
    operands = instruction.get("operands", [])
    operands = ", ".join(map(str, operands)) if isinstance(operands, list) else str(operands)
    text = f"{address}  {instruction.get('mnemonic', '?')} {operands}".rstrip()
    return text if len(text) <= 62 else text[:59] + "…"


@dataclass(frozen=True)
class GraphBlock:
    start: int
    block: dict[str, Any] = field(compare=False, repr=False)
    x: float
    y: float
    width: float
    height: float
    # Only the small visual preview is materialized, not the original IR.
    lines: tuple[tuple[int | None, str], ...]

    @property
    def bounds(self) -> tuple[float, float, float, float]:
        return self.x, self.y, self.x + self.width, self.y + self.height


@dataclass(frozen=True)
class GraphPath:
    source: int | None
    target: int | None
    kind: str
    conditional: bool
    unresolved: bool
    reason: str
    points: tuple[float, ...]

    @property
    def bounds(self) -> tuple[float, float, float, float]:
        if not self.points:
            return 0.0, 0.0, 0.0, 0.0
        return (min(self.points[::2]), min(self.points[1::2]),
                max(self.points[::2]), max(self.points[1::2]))

    @property
    def color(self) -> str:
        if self.unresolved:
            return "#d69442"
        if self.conditional:
            return "#62b98a" if self.kind == "branch" else "#d47b7b"
        return "#7c9ed1"


def _intersects(bounds: tuple, viewport: tuple) -> bool:
    return (bounds[0] <= viewport[2] and bounds[2] >= viewport[0]
            and bounds[1] <= viewport[3] and bounds[3] >= viewport[1])


class _PathIndex:
    """Interval tree: long back edges occupy one record, not thousands of tiles."""

    def __init__(self, paths: tuple[GraphPath, ...]):
        self.paths = paths
        self.bounds = tuple(path.bounds for path in paths)
        drawable = [index for index, path in enumerate(paths) if path.points]
        self.root = self._build(drawable)

    def _build(self, indices: list[int]):
        if not indices:
            return None
        centers = sorted((self.bounds[index][1] + self.bounds[index][3]) / 2
                         for index in indices)
        center = centers[len(centers) // 2]
        before, crossing, after = [], [], []
        for index in indices:
            bounds = self.bounds[index]
            if bounds[3] < center:
                before.append(index)
            elif bounds[1] > center:
                after.append(index)
            else:
                crossing.append(index)
        return (center,
                tuple(sorted(crossing, key=lambda index: (self.bounds[index][1], index))),
                tuple(sorted(crossing, key=lambda index: (-self.bounds[index][3], index))),
                self._build(before), self._build(after))

    def query(self, viewport: tuple[float, float, float, float], limit: int) -> list[int]:
        result = []
        stack = [self.root] if self.root else []
        while stack and len(result) < limit:
            center, by_start, by_end, before, after = stack.pop()
            if viewport[3] < center:
                candidates = by_start
                for index in candidates:
                    if self.bounds[index][1] > viewport[3]:
                        break
                    if _intersects(self.bounds[index], viewport):
                        result.append(index)
                        if len(result) == limit:
                            break
                if before:
                    stack.append(before)
            elif viewport[1] > center:
                for index in by_end:
                    if self.bounds[index][3] < viewport[1]:
                        break
                    if _intersects(self.bounds[index], viewport):
                        result.append(index)
                        if len(result) == limit:
                            break
                if after:
                    stack.append(after)
            else:
                for index in by_start:
                    if _intersects(self.bounds[index], viewport):
                        result.append(index)
                        if len(result) == limit:
                            break
                if after:
                    stack.append(after)
                if before:
                    stack.append(before)
        return result


@dataclass
class GraphLayout:
    blocks: dict[int, GraphBlock]
    paths: tuple[GraphPath, ...]
    address_blocks: dict[int, int]
    rows: tuple[tuple[float, float, tuple[int, ...]], ...]
    width: float
    height: float
    complete: bool | None
    invalid_blocks: int = 0
    _row_starts: tuple[float, ...] = field(init=False, repr=False)
    _path_index: _PathIndex = field(init=False, repr=False)
    unresolved_count: int = field(init=False)
    orphaned_count: int = field(init=False)

    def __post_init__(self):
        self._row_starts = tuple(row[0] for row in self.rows)
        self._path_index = _PathIndex(self.paths)
        self.unresolved_count = sum(path.unresolved for path in self.paths)
        self.orphaned_count = sum(path.unresolved and path.source is None for path in self.paths)

    @property
    def unresolved(self) -> tuple[GraphPath, ...]:
        return tuple(path for path in self.paths if path.unresolved)

    def block_for_address(self, address: int) -> GraphBlock | None:
        if not _address(address):
            return None
        start = self.address_blocks.get(address)
        return self.blocks.get(start) if start is not None else None

    def visible_blocks(self, viewport: tuple, limit: int = MAX_RENDER_BLOCKS) -> list[GraphBlock]:
        if limit <= 0:
            return []
        first = max(0, bisect_right(self._row_starts, viewport[1]) - 1)
        result = []
        for index in range(first, len(self.rows)):
            top, bottom, addresses = self.rows[index]
            if top > viewport[3]:
                break
            if bottom < viewport[1]:
                continue
            for address in addresses:
                block = self.blocks[address]
                if _intersects(block.bounds, viewport):
                    result.append(block)
                    if len(result) >= limit:
                        return result
        return result

    def visible_paths(self, viewport: tuple, limit: int = MAX_RENDER_EDGES) -> list[GraphPath]:
        if limit <= 0:
            return []
        return [self.paths[index] for index in self._path_index.query(viewport, limit)]


def _route(source: GraphBlock | None, target: GraphBlock | None,
           ordinal: int) -> tuple[float, ...]:
    if source is None:
        return ()
    sx, sy = source.x + source.width / 2, source.y + source.height
    if target is None:
        return (sx, sy, sx, sy + 17, sx + 68, sy + 17, sx + 68, sy + 45)
    tx, ty = target.x + target.width / 2, target.y
    if ty > sy + 35:
        middle = (sy + ty) / 2
        return (sx, sy, sx, middle, tx, middle, tx, ty)
    # Same-layer, backward and self-loop paths visibly run around the blocks.
    side = max(source.x + source.width, target.x + target.width) + 20 + ordinal % 5 * 10
    return (sx, sy, sx, sy + 18, side, sy + 18,
            side, ty - 18, tx, ty - 18, tx, ty)


def build_layout(cfg: dict[str, Any] | None) -> GraphLayout:
    """Layout every declared block; infer neither missing blocks nor missing edges."""
    cfg = cfg if isinstance(cfg, dict) else {}
    original_blocks: dict[int, dict] = {}
    addresses: dict[int, int] = {}
    conditional_sources: set[int] = set()
    invalid = 0
    for block in _records(cfg.get("blocks")):
        if not isinstance(block, dict) or not _address(block.get("start")):
            invalid += 1
            continue
        start = block["start"]
        if start in original_blocks:
            invalid += 1
            continue
        original_blocks[start] = block
        addresses.setdefault(start, start)
        for instruction in _records(block.get("instructions")):
            if isinstance(instruction, dict) and _address(instruction.get("addr")):
                addresses.setdefault(instruction["addr"], start)
                branch = instruction.get("branch_info")
                if isinstance(branch, dict) and branch.get("conditional") is True:
                    conditional_sources.add(instruction["addr"])
    # Explicit block boundaries take precedence over an overlapping IR record.
    addresses.update((start, start) for start in original_blocks)
    ordered = sorted(original_blocks)
    adjacency: dict[int, list[int]] = {start: [] for start in ordered}
    records: list[tuple[int | None, int | None, str, bool, bool, str]] = []
    for edge in _records(cfg.get("edges")):
        if not isinstance(edge, dict):
            records.append((None, None, "edge", False, True, "malformed_edge"))
            continue
        raw_source, raw_target = edge.get("src"), edge.get("dst")
        source = addresses.get(raw_source) if _address(raw_source) else None
        target = raw_target if _address(raw_target) else None
        reason = ""
        if source is None:
            reason = "source_not_in_graph"
        elif target not in original_blocks:
            reason = "target_not_a_block"
        conditional = _address(raw_source) and raw_source in conditional_sources
        kind = str(edge.get("kind", "edge"))
        records.append((source, target, kind, conditional, bool(reason), reason))
        if not reason:
            adjacency[source].append(target)
    for frontier in _records(cfg.get("frontier")):
        if not isinstance(frontier, dict):
            records.append((None, None, "frontier", False, True, "malformed_frontier"))
            continue
        raw_source, target = frontier.get("from"), frontier.get("to")
        source = addresses.get(raw_source) if _address(raw_source) else None
        target = target if _address(target) else None
        records.append((source, target, "frontier", False, True,
                        str(frontier.get("reason") or "unresolved")))

    ranks: dict[int, int] = {}
    entry = cfg.get("entry")
    first = entry if _address(entry) and entry in original_blocks else None
    roots = ([first] if first is not None else []) + ordered
    next_rank = 0
    for root in roots:
        if root in ranks:
            continue
        ranks[root] = next_rank
        queue = deque([root])
        deepest = next_rank
        while queue:
            source = queue.popleft()
            for target in sorted(set(adjacency[source])):
                if target not in ranks:
                    ranks[target] = ranks[source] + 1
                    deepest = max(deepest, ranks[target])
                    queue.append(target)
        next_rank = deepest + 2
    by_rank: dict[int, list[int]] = {}
    for start in ordered:
        by_rank.setdefault(ranks[start], []).append(start)
    placed: dict[int, GraphBlock] = {}
    rows = []
    y = 30.0
    for rank in sorted(by_rank):
        layer = by_rank[rank]
        for offset in range(0, len(layer), 8):
            row_addresses = layer[offset:offset + 8]
            max_height = 0.0
            for column, start in enumerate(row_addresses):
                block = original_blocks[start]
                instructions = _records(block.get("instructions"))
                preview = []
                for instruction in instructions[:PREVIEW_INSTRUCTIONS]:
                    if isinstance(instruction, dict):
                        address = instruction.get("addr")
                        preview.append((address if _address(address) else None,
                                        _instruction_line(instruction)))
                if len(instructions) > PREVIEW_INSTRUCTIONS:
                    preview.append((None, f"… 共 {len(instructions)} 条指令；双击进入文本视图"))
                if not preview:
                    preview.append((None, "指令不可用"))
                height = 38 + len(preview) * LINE_HEIGHT + 10
                node = GraphBlock(start, block, 35 + column * (BLOCK_WIDTH + COLUMN_GAP),
                                  y, BLOCK_WIDTH, height, tuple(preview))
                placed[start] = node
                max_height = max(max_height, height)
            rows.append((y, y + max_height, tuple(row_addresses)))
            y += max_height + ROW_GAP
    paths = []
    for ordinal, (source, target, kind, conditional, unresolved, reason) in enumerate(records):
        # A frontier remains unresolved even when its address exists elsewhere.
        destination = None if unresolved else placed.get(target)
        paths.append(GraphPath(source, target, kind, conditional, unresolved, reason,
                               _route(placed.get(source), destination, ordinal)))
    max_x = max((block.x + block.width for block in placed.values()), default=365)
    max_y = max((block.y + block.height for block in placed.values()), default=95)
    if paths:
        max_x = max(max_x, max((path.bounds[2] for path in paths), default=0))
        max_y = max(max_y, max((path.bounds[3] for path in paths), default=0))
    complete = cfg.get("complete")
    complete = complete if type(complete) is bool else None
    return GraphLayout(placed, tuple(paths), addresses, tuple(rows),
                       max_x + 40, max_y + 65, complete, invalid)


class GraphView:
    """Tk adapter with independently reusable and testable graph layout.

    Embed ``frame`` in any geometry manager. ``on_navigate`` receives an integer
    address only on explicit double-click/Return; selection alone never navigates.
    """

    def __init__(self, parent, tk, ttk, on_navigate: Callable[[int], None] | None = None,
                 *, on_select: Callable[[int], None] | None = None):
        self.tk, self.ttk = tk, ttk
        self.on_navigate = on_navigate
        self.on_select = on_select
        self.frame = ttk.Frame(parent)
        self.frame.rowconfigure(1, weight=1)
        self.frame.columnconfigure(0, weight=1)
        toolbar = ttk.Frame(self.frame)
        toolbar.grid(row=0, column=0, columnspan=2, sticky="ew", padx=4, pady=3)
        for label, callback in (("−", lambda: self.zoom(1 / 1.2)),
                                ("+", lambda: self.zoom(1.2)),
                                ("适应视图", self.fit_view),
                                ("当前块", self.center_selection),
                                ("未解析路径", self.show_unresolved)):
            ttk.Button(toolbar, text=label, command=callback).pack(side="left", padx=2)
        self.scale_text = tk.StringVar(master=self.frame, value="100%")
        ttk.Label(toolbar, textvariable=self.scale_text).pack(side="right", padx=8)
        self.canvas = tk.Canvas(self.frame, background="#20242c", highlightthickness=0,
                                takefocus=True, xscrollincrement=20, yscrollincrement=20)
        self.canvas.grid(row=1, column=0, sticky="nsew")
        horizontal = ttk.Scrollbar(self.frame, orient="horizontal", command=self._scroll_x)
        vertical = ttk.Scrollbar(self.frame, orient="vertical", command=self._scroll_y)
        horizontal.grid(row=2, column=0, sticky="ew")
        vertical.grid(row=1, column=1, sticky="ns")
        self.canvas.configure(xscrollcommand=horizontal.set, yscrollcommand=vertical.set)
        self.status = tk.StringVar(master=self.frame, value="没有控制流图")
        ttk.Label(self.frame, textvariable=self.status, anchor="w").grid(
            row=3, column=0, columnspan=2, sticky="ew", padx=5, pady=3)
        self.layout = build_layout(None)
        self.scale = 1.0
        self.selected_address: int | None = None
        self._items: dict[int, tuple[int, int | None]] = {}
        self._pending = None
        self._destroyed = False
        self._auto_fit = False
        self._initial_focus_pending = False
        self.canvas.bind("<Configure>", self._configured)
        self.canvas.bind("<Map>", self._mapped)
        self.canvas.bind("<Button-1>", self._click)
        self.canvas.bind("<Double-Button-1>", self._activate)
        self.canvas.bind("<Return>", self._activate)
        self.canvas.bind("<MouseWheel>", self._wheel)
        self.canvas.bind("<Shift-MouseWheel>", self._horizontal_wheel)
        self.canvas.bind("<Control-MouseWheel>", self._zoom_wheel)
        self.canvas.bind("<Button-4>", lambda event: self._wheel_units(-3))
        self.canvas.bind("<Button-5>", lambda event: self._wheel_units(3))
        self.canvas.bind("<Button-2>", lambda event: self.canvas.scan_mark(event.x, event.y))
        self.canvas.bind("<B2-Motion>", self._drag)
        self.canvas.bind("<Destroy>", self._destroy)

    def set_cfg(self, cfg: dict | None, selected_address: int | None = None) -> None:
        self.layout = build_layout(cfg)
        self.selected_address = None
        self._items.clear()
        self.canvas.delete("all")
        # Reading the current block is the default. Fitting the entire graph
        # would hide instruction text for even a modest vertically laid-out CFG.
        self.scale = 1.0
        self._auto_fit = False
        self._initial_focus_pending = True
        self._region()
        self.canvas.xview_moveto(0)
        self.canvas.yview_moveto(0)
        entry = cfg.get("entry") if isinstance(cfg, dict) else None
        candidate = selected_address if _address(selected_address) else entry
        if not self.select_address(candidate) and self.layout.blocks:
            self.select_address(next(iter(self.layout.blocks)))
        self._schedule_render()

    def select_address(self, address: int | None) -> bool:
        block = self.layout.block_for_address(address)
        if block is None:
            return False
        self.selected_address = address
        self.center_selection()
        self._schedule_render()
        return True

    def center_selection(self) -> None:
        block = self.layout.block_for_address(self.selected_address)
        if block is None:
            return
        width, height = self._viewport_size()
        x = (block.x + block.width / 2) * self.scale - width / 2
        y = (block.y + block.height / 2) * self.scale - height / 2
        self._region()
        self._position_view(x, y)
        if self.canvas.winfo_ismapped():
            self._initial_focus_pending = False
        self._schedule_render()

    def _viewport_size(self) -> tuple[int, int]:
        return max(100, self.canvas.winfo_width()), max(100, self.canvas.winfo_height())

    def _scroll_region(self) -> tuple[float, float, float, float]:
        width, height = self._viewport_size()
        graph_width, graph_height = self.layout.width * self.scale, self.layout.height * self.scale
        # A one-column graph should occupy the middle of a wide canvas, rather
        # than leave all spare space to its right. Coordinates remain in the
        # original layout space, including for viewport queries and hit testing.
        left = min(0.0, (graph_width - width) / 2)
        return left, 0.0, left + max(width, graph_width), max(height, graph_height)

    def _region(self) -> None:
        self.canvas.configure(scrollregion=self._scroll_region())
        self.scale_text.set(f"{self.scale:.0%}")

    def _position_view(self, x: float, y: float) -> None:
        width, height = self._viewport_size()
        left, top, right, bottom = self._scroll_region()
        x = min(max(left, x), max(left, right - width))
        y = min(max(top, y), max(top, bottom - height))
        self.canvas.xview_moveto((x - left) / max(1, right - left))
        self.canvas.yview_moveto((y - top) / max(1, bottom - top))

    def fit_view(self) -> None:
        self._auto_fit = True
        self._initial_focus_pending = False
        width, height = self._viewport_size()
        self.scale = max(MIN_SCALE, min(1.0, (width - 20) / max(1, self.layout.width),
                                        (height - 20) / max(1, self.layout.height)))
        self._region()
        self.center_selection()
        self._schedule_render()

    def zoom(self, factor: float, x: float | None = None, y: float | None = None) -> None:
        if factor <= 0:
            return
        self._auto_fit = False
        self._initial_focus_pending = False
        width, height = self._viewport_size()
        x, y = width / 2 if x is None else x, height / 2 if y is None else y
        anchor_x, anchor_y = self.canvas.canvasx(x) / self.scale, self.canvas.canvasy(y) / self.scale
        self.scale = min(MAX_SCALE, max(MIN_SCALE, self.scale * factor))
        self._region()
        self._position_view(anchor_x * self.scale - x, anchor_y * self.scale - y)
        self._schedule_render()

    def _configured(self, event) -> None:
        # A hidden notebook panel reports 1×1. Locate the selected block once
        # its real dimensions are known; resizing never changes reading zoom.
        if self._auto_fit:
            self.fit_view()
        elif self._initial_focus_pending:
            self.center_selection()
        else:
            self._region()
            self._schedule_render()

    def _mapped(self, event) -> None:
        if self._auto_fit:
            self.fit_view()
        elif self._initial_focus_pending:
            self.center_selection()

    def _schedule_render(self) -> None:
        if not self._destroyed and self._pending is None:
            self._pending = self.canvas.after_idle(self._render)

    def _render(self) -> None:
        self._pending = None
        if self._destroyed:
            return
        self._region()
        width, height = self._viewport_size()
        viewport = (self.canvas.canvasx(0) / self.scale - 25,
                    self.canvas.canvasy(0) / self.scale - 25,
                    self.canvas.canvasx(width) / self.scale + 25,
                    self.canvas.canvasy(height) / self.scale + 25)
        blocks = self.layout.visible_blocks(viewport, MAX_RENDER_BLOCKS + 1)
        paths = self.layout.visible_paths(viewport, MAX_RENDER_EDGES + 1)
        limited = len(blocks) > MAX_RENDER_BLOCKS or len(paths) > MAX_RENDER_EDGES
        self.canvas.delete("all")
        self._items.clear()
        for path in paths[:MAX_RENDER_EDGES]:
            options = {"fill": path.color, "width": max(1, 1.6 * self.scale),
                       "arrow": "last", "arrowshape": (7, 9, 3)}
            if path.unresolved:
                options["dash"] = (4, 3)
            self.canvas.create_line(*(coordinate * self.scale for coordinate in path.points),
                                    **options)
            if path.unresolved:
                x, y = path.points[-2:]
                target = f"{path.target:#x}" if path.target is not None else "?"
                self.canvas.create_text(x * self.scale, (y + 7) * self.scale, anchor="n",
                                        text=f"未解析 → {target}", fill=path.color,
                                        font=("TkFixedFont", max(7, int(9 * self.scale))))
        selected = self.layout.block_for_address(self.selected_address)
        for block in blocks[:MAX_RENDER_BLOCKS]:
            active = selected is not None and selected.start == block.start
            x1, y1, x2, y2 = (coordinate * self.scale for coordinate in block.bounds)
            rectangle = self.canvas.create_rectangle(
                x1, y1, x2, y2, fill="#313b4b" if active else "#2a303a",
                outline="#8cc6ff" if active else "#5d6a80", width=2 if active else 1)
            self._items[rectangle] = block.start, None
            header = self.canvas.create_text(
                x1 + 10 * self.scale, y1 + 17 * self.scale, anchor="w",
                text=f"loc_{block.start:x}", fill="#b8d9fc",
                font=("TkFixedFont", max(7, int(11 * self.scale)), "bold"))
            self._items[header] = block.start, block.start
            self.canvas.create_line(x1, y1 + 32 * self.scale, x2, y1 + 32 * self.scale,
                                    fill="#475167")
            if self.scale >= 0.4:
                for index, (address, line) in enumerate(block.lines):
                    item = self.canvas.create_text(
                        x1 + 10 * self.scale, y1 + (45 + index * LINE_HEIGHT) * self.scale,
                        anchor="w", text=line,
                        fill="#f5df9c" if address == self.selected_address else "#d5dce7",
                        font=("TkFixedFont", max(7, int(10 * self.scale))))
                    self._items[item] = block.start, address
        unresolved = self.layout.unresolved_count
        orphaned = self.layout.orphaned_count
        message = f"{len(self.layout.blocks)} 个基本块 · {len(self.layout.paths)} 条路径 · {unresolved} 条未解析"
        if orphaned:
            message += f"（{orphaned} 条源地址缺失，见未解析路径）"
        if self.layout.complete is False:
            message += " · 分析不完整"
        if self.layout.invalid_blocks:
            message += f" · {self.layout.invalid_blocks} 条无效基本块记录"
        if limited:
            message += " · 当前视口过密，请放大或跳转到基本块"
        if not self.layout.blocks:
            self.canvas.create_text(width / 2, height / 2, text="没有控制流图", fill="#b6bfcc")
        self.status.set(message)

    def _hit(self, event) -> tuple[int, int | None] | None:
        x, y = self.canvas.canvasx(event.x), self.canvas.canvasy(event.y)
        for item in reversed(self.canvas.find_overlapping(x - 2, y - 2, x + 2, y + 2)):
            if item in self._items:
                return self._items[item]
        return None

    def _click(self, event):
        self.canvas.focus_set()
        hit = self._hit(event)
        if hit:
            self.selected_address = hit[1] if hit[1] is not None else hit[0]
            if self.on_select:
                self.on_select(self.selected_address)
            self._schedule_render()
        return "break"

    def _activate(self, event):
        if getattr(event, "keysym", "") != "Return":
            hit = self._hit(event)
            if not hit:
                return "break"
            self.selected_address = hit[1] if hit[1] is not None else hit[0]
        if self.on_navigate and self.selected_address is not None:
            self.on_navigate(self.selected_address)
        return "break"

    def _scroll_x(self, *args):
        self.canvas.xview(*args)
        self._schedule_render()

    def _scroll_y(self, *args):
        self.canvas.yview(*args)
        self._schedule_render()

    def _wheel_units(self, units: int):
        self.canvas.yview_scroll(units, "units")
        self._schedule_render()
        return "break"

    def _wheel(self, event):
        delta = event.delta
        return self._wheel_units(-max(1, int(abs(delta) / 120)) if delta > 0
                                 else max(1, int(abs(delta) / 120)))

    def _horizontal_wheel(self, event):
        self.canvas.xview_scroll(-3 if event.delta > 0 else 3, "units")
        self._schedule_render()
        return "break"

    def _zoom_wheel(self, event):
        self.zoom(1.15 if event.delta > 0 else 1 / 1.15, event.x, event.y)
        return "break"

    def _drag(self, event):
        self.canvas.scan_dragto(event.x, event.y, gain=1)
        self._schedule_render()

    def _destroy(self, event):
        if event.widget is self.canvas:
            self._destroyed = True
            if self._pending is not None:
                self.canvas.after_cancel(self._pending)
                self._pending = None

    def show_unresolved(self) -> None:
        """Paginate all unresolved records, including paths without a valid source."""
        records = self.layout.unresolved
        window = self.tk.Toplevel(self.frame)
        window.title("CFG 未解析路径")
        window.geometry("760x440")
        window.transient(self.frame.winfo_toplevel())
        tree = self.ttk.Treeview(window, columns=("source", "target", "reason"),
                                 show="headings", selectmode="browse")
        for column, title in (("source", "源基本块"), ("target", "目标"), ("reason", "原因")):
            tree.heading(column, text=title)
            tree.column(column, width=150 if column != "reason" else 350)
        tree.pack(fill="both", expand=True, padx=6, pady=6)
        controls = self.ttk.Frame(window)
        controls.pack(fill="x", padx=6, pady=6)
        status = self.tk.StringVar(master=window)
        page = [0]

        def refresh(change=0):
            page[0] = min(max(0, page[0] + change), max(0, (len(records) - 1) // 200))
            tree.delete(*tree.get_children())
            for index in range(page[0] * 200, min(len(records), (page[0] + 1) * 200)):
                record = records[index]
                tree.insert("", "end", iid=str(index), values=(
                    f"{record.source:#x}" if record.source is not None else "源不在当前图中",
                    f"{record.target:#x}" if record.target is not None else "未知目标",
                    record.reason))
            status.set(f"{len(records)} 条未解析路径 · 第 {page[0] + 1}/{max(1, (len(records) + 199) // 200)} 页")

        def navigate(event):
            selected = tree.selection()
            if selected:
                record = records[int(selected[0])]
                if record.source is not None:
                    self.select_address(record.source)

        self.ttk.Button(controls, text="上一页", command=lambda: refresh(-1)).pack(side="left")
        self.ttk.Button(controls, text="下一页", command=lambda: refresh(1)).pack(side="left", padx=4)
        self.ttk.Label(controls, textvariable=status).pack(side="right")
        tree.bind("<Double-Button-1>", navigate)
        refresh()
