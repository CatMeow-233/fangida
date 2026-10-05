"""扫描字符串并附上 Loader 声明的地址映射，不产生代码引用。"""
from __future__ import annotations

import heapq
import re
from typing import Any

from ...addresses import NativeAddressMap
from ...loaders.models import BinaryImage

MAX_STRING_BYTES = 512
MAX_BOUNDED_STRINGS = 1000
_ASCII = re.compile(rb"[\x20-\x7e]{4,}")


def scan_native_strings(data: bytes, image: BinaryImage | None = None, *,
                        full_analysis: bool = False) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """优先返回映射数据中的字符串；完整模式不受旧的 1000 条上限限制。

    常规模式的结果数量和候选保留量仍有界。原有 offset/value/length 字段保留；
    未映射的文件文本没有虚构地址，多映射保留全部 VA 而不任意选择。
    """
    sections = image.sections if image is not None else ()
    kind = image.format if image is not None else ""
    mapped = NativeAddressMap(sections, kind=kind)
    data_mapped = NativeAddressMap((section for section in sections if not section.get("executable")),
                                   kind=kind)
    candidates = 0

    def records():
        nonlocal candidates
        for match in _ASCII.finditer(data):
            candidates += 1
            offset = match.start()
            length = match.end() - offset
            address_ranges = mapped.ranges_for_offset(offset, length)
            data_ranges = data_mapped.ranges_for_offset(offset, length)
            addresses = tuple(address for address, _ in address_ranges)
            data_addresses = tuple(address for address, _ in data_ranges)
            record: dict[str, Any] = {
                "offset": offset, "value": data[offset:min(match.end(), offset + MAX_STRING_BYTES)].decode("ascii"),
                "length": length,
            }
            if addresses:
                record["addresses"] = list(addresses)
                record["address_ranges"] = [list(item) for item in address_ranges]
                record["address_space"] = "native"
                if len(addresses) == 1:
                    record["address"] = addresses[0]
            if data_addresses:
                record["data_addresses"] = list(data_addresses)
                record["data_ranges"] = [list(item) for item in data_ranges]
            # 代码字节中的偶然可打印片段不能挤掉真正数据段中的字符串。
            priority = 0 if data_addresses else 1 if addresses else 2
            yield priority, offset, record

    chosen = (sorted(records(), key=lambda item: item[:2]) if full_analysis else
              heapq.nsmallest(MAX_BOUNDED_STRINGS, records(), key=lambda item: item[:2]))
    strings = [record for _, _, record in chosen]
    return strings, {"scope": "scanned_file_ascii", "candidate_count": candidates,
                     "returned_count": len(strings), "truncated": len(strings) < candidates,
                     "value_limit": MAX_STRING_BYTES, "priority": "mapped_data"}
