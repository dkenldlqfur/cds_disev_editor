"""Shared CDS_95.EXE discovery-record parsing helpers.

This module deliberately contains only read-only discovery-table metadata.
Image encoding, DSTILL archive writes, and backups belong to
``insert_discovery_still.py`` so DISEV analysis does not depend on injection
functionality or Pillow.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


RECORD_SIZE = 0x5C
NO_MEDIA = 0xFFFFFFFF
STILL_OFFSET = 0x0C
AVI_OFFSET = 0x10
CG_OFFSET = 0x14


@dataclass(frozen=True)
class PeSection:
    rva: int
    virtual_size: int
    raw_offset: int
    raw_size: int


def u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def parse_pe_sections(exe: bytes) -> tuple[int, list[PeSection]]:
    if exe[:2] != b"MZ":
        raise ValueError("PE 실행 파일이 아닙니다.")
    pe_offset = u32(exe, 0x3C)
    if exe[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("PE 헤더를 찾지 못했습니다.")
    section_count = struct.unpack_from("<H", exe, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", exe, pe_offset + 20)[0]
    optional = pe_offset + 24
    magic = struct.unpack_from("<H", exe, optional)[0]
    if magic == 0x10B:
        image_base = u32(exe, optional + 28)
    elif magic == 0x20B:
        image_base = struct.unpack_from("<Q", exe, optional + 24)[0]
    else:
        raise ValueError("지원하지 않는 PE 선택 헤더입니다.")
    first_section = optional + optional_size
    sections = []
    for index in range(section_count):
        offset = first_section + index * 40
        sections.append(
            PeSection(
                rva=u32(exe, offset + 12),
                virtual_size=u32(exe, offset + 8),
                raw_offset=u32(exe, offset + 20),
                raw_size=u32(exe, offset + 16),
            )
        )
    return image_base, sections


def va_to_file_offset(va: int, image_base: int, sections: list[PeSection]) -> int | None:
    if va < image_base:
        return None
    rva = va - image_base
    for section in sections:
        section_size = max(section.virtual_size, section.raw_size)
        if section.rva <= rva < section.rva + section_size:
            offset = section.raw_offset + rva - section.rva
            if offset < section.raw_offset + section.raw_size:
                return offset
    return None


def record_has_name(exe: bytes, offset: int, image_base: int, sections: list[PeSection]) -> bool:
    if offset < 0 or offset + RECORD_SIZE > len(exe):
        return False
    category = u32(exe, offset + 4)
    game_id = u32(exe, offset + 8)
    name_offset = va_to_file_offset(u32(exe, offset), image_base, sections)
    if category > 7 or game_id > 10000 or name_offset is None:
        return False
    terminator = exe.find(b"\0", name_offset, min(name_offset + 96, len(exe)))
    return terminator > name_offset


def locate_discovery_record(exe: bytes, name: str, game_id: int) -> tuple[int, int, list[PeSection]]:
    image_base, sections = parse_pe_sections(exe)
    target_name = name.encode("cp949") + b"\0"
    game_id_bytes = struct.pack("<I", game_id)
    matches: list[int] = []
    cursor = 0
    while True:
        id_offset = exe.find(game_id_bytes, cursor)
        if id_offset < 0:
            break
        cursor = id_offset + 1
        record_offset = id_offset - 8
        if not record_has_name(exe, record_offset, image_base, sections):
            continue
        name_offset = va_to_file_offset(u32(exe, record_offset), image_base, sections)
        if name_offset is not None and exe.startswith(target_name, name_offset):
            matches.append(record_offset)
    if len(matches) != 1:
        raise ValueError(f"'{name}' (게임 ID {game_id}) 레코드를 하나로 특정하지 못했습니다: {matches}")
    return matches[0], image_base, sections


def discovery_table(exe: bytes, target_offset: int, image_base: int, sections: list[PeSection]) -> list[int]:
    """Expand the contiguous discovery-record table surrounding a target."""
    first = target_offset
    while record_has_name(exe, first - RECORD_SIZE, image_base, sections):
        first -= RECORD_SIZE
    rows: list[int] = []
    offset = first
    while record_has_name(exe, offset, image_base, sections):
        rows.append(offset)
        offset += RECORD_SIZE
    if target_offset not in rows or len(rows) < 100:
        raise ValueError("발견물 테이블 범위를 검증하지 못했습니다.")
    return rows
