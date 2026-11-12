"""RAR 与 7-Zip 的 hashcat 哈希提取和结构校验。"""

import re
from io import StringIO


def _uint(value: str, field: str, maximum: int) -> int:
    if not value.isascii() or not value.isdigit():
        raise ValueError(f"{field} 必须是十进制数字。")
    number = int(value)
    if number > maximum:
        raise ValueError(f"{field} 超出 hashcat 7.1.2 支持范围。")
    return number


def _hex(value: str, field: str, length: int | None = None) -> None:
    if (length is not None and len(value) != length) or len(value) % 2 or not re.fullmatch(r"[0-9a-fA-F]*", value):
        raise ValueError(f"{field} 的长度或十六进制格式无效。")


def parse_archive_hash(output: str) -> tuple[str | None, int | None]:
    """从工具输出中逐行提取首个受支持的 RAR 或 7z 哈希。"""
    for raw_line in StringIO(output):
        line = raw_line.strip()
        match = re.search(r"\$(?:RAR3|rar5|7z)\$", line, re.IGNORECASE)
        if not match:
            continue
        # rar2john 常用 archive:hash 形式，冒号后的字段才是 hash。
        value = line[match.start():].split(":", 1)[0].strip()
        if value.lower().startswith("$rar3$"):
            value = "$RAR3$" + value[6:]
        elif value.lower().startswith("$rar5$"):
            value = "$rar5$" + value[6:]
        elif value.lower().startswith("$7z$"):
            value = "$7z$" + value[4:]
        lower = value.lower()
        if lower.startswith("$rar3$"):
            return _parse_rar3(value)
        if lower.startswith("$rar5$"):
            return _parse_rar5(value)
        if lower.startswith("$7z$"):
            return _parse_7z(value), 11600
    return None, None


def _parse_rar3(value: str) -> tuple[str, int]:
    fields = value.split("*")
    if not fields or fields[0] != "$RAR3$" or len(fields) < 2:
        raise ValueError("RAR3 哈希字段或类型无效。")
    if fields[1] == "0":
        if len(fields) != 4:
            raise ValueError("RAR3 类型 0 哈希字段数量无效。")
        _hex(fields[2], "RAR3 盐", 16)
        _hex(fields[3], "RAR3 校验数据", 32)
        return value, 12500
    if len(fields) >= 7 and fields[6] == "0":
        raise ValueError("RAR3 哈希引用外部数据文件，hashcat 不支持。")
    if fields[1] != "1" or len(fields) != 9:
        raise ValueError("RAR3 类型 1 哈希字段数量无效。")
    salt_hex, crc_hex, packed_text, unpacked_text, has_inline_data, data_hex, method_text = fields[2:]
    if not 1 <= len(packed_text) <= 7 or not 1 <= len(unpacked_text) <= 6 or len(method_text) != 2:
        raise ValueError("RAR3 大小或方法字段宽度无效。")
    _hex(salt_hex, "RAR3 盐", 16)
    _hex(crc_hex, "RAR3 CRC", 8)
    packed_size = _uint(packed_text, "RAR3 压缩大小", 327680)
    unpacked_size = _uint(unpacked_text, "RAR3 解压大小", 655360)
    if not packed_size or packed_size % 16 or not unpacked_size:
        raise ValueError("RAR3 压缩/解压大小不受 hashcat 支持。")
    if has_inline_data != "1":
        raise ValueError("RAR3 哈希引用外部数据文件，hashcat 不支持。")
    _hex(data_hex, "RAR3 加密数据")
    if len(data_hex) != packed_size * 2 or len(data_hex) > 655056:
        raise ValueError("RAR3 加密数据长度与压缩大小不符。")
    method = _uint(method_text, "RAR3 方法", 99)
    if method == 30:
        if unpacked_size > packed_size:
            raise ValueError("RAR3 未压缩数据的解压大小不能大于压缩大小。")
        return value, 23700
    if 31 <= method <= 35:
        return value, 23800
    raise ValueError(f"RAR3 方法 {method} 不受 hashcat 7.1.2 支持。")


def _parse_rar5(value: str) -> tuple[str, int]:
    fields = value.split("$")
    if len(fields) != 8 or fields[0] or fields[1] != "rar5":
        raise ValueError("RAR5 哈希字段数量无效。")
    if fields[2] != "16" or fields[6] != "8":
        raise ValueError("RAR5 盐或校验字段长度不受 hashcat 支持。")
    _hex(fields[3], "RAR5 盐", 32)
    if len(fields[4]) != 2:
        raise ValueError("RAR5 成本因子必须恰好为两位数字。")
    iterations = _uint(fields[4], "RAR5 成本因子", 31)
    if iterations == 0:
        raise ValueError("RAR5 成本因子不能为 0。")
    _hex(fields[5], "RAR5 IV", 32)
    _hex(fields[7], "RAR5 密码校验值", 16)
    return value, 13000


def _parse_7z(value: str) -> str:
    f = value.split("$")
    if len(f) < 12 or f[0] or f[1].lower() != "7z":
        raise ValueError("7z 哈希字段数量无效。")
    kind = _uint(f[2], "7z 数据类型", 255)
    if kind not in (0, 1, 2, 7):
        names = {3: "PPMd", 6: "BZip2", 128: "截断数据"}
        note = "；该类型可能包含预处理过滤器或组合编码" if kind not in names else ""
        raise ValueError(f"7z 数据类型 {kind}{'（'+names[kind]+'）' if kind in names else ''}不受 hashcat 7.1.2 支持{note}。")
    if kind == 0 and len(f) != 12 or kind != 0 and len(f) != 14:
        raise ValueError("7z 哈希压缩附加字段数量无效。")
    if len(f[2]) != 1 or not 1 <= len(f[3]) <= 2 or len(f[4]) != 1 or not 1 <= len(f[6]) <= 2:
        raise ValueError("7z 类型、成本因子、盐长度或 IV 长度字段宽度无效。")
    if not 1 <= len(f[8]) <= 10 or not 1 <= len(f[9]) <= 8 or not 1 <= len(f[10]) <= 8:
        raise ValueError("7z CRC、加密数据长度或解压大小字段宽度无效。")
    cost = _uint(f[3], "7z 成本因子", 31)
    salt_len = _uint(f[4], "7z 盐长度", 64)
    _hex(f[5], "7z 盐", salt_len * 2)
    if salt_len != 0:
        raise ValueError("hashcat 7.1.2 的 7z 模式要求盐长度为 0。")
    iv_len = _uint(f[6], "7z IV 长度", 16)
    _hex(f[7], "7z IV", 32)
    _uint(f[8], "7z CRC", 0xFFFFFFFF)
    data_len = _uint(f[9], "7z 加密数据长度", 0x800000)
    unpack = _uint(f[10], "7z 解压大小", data_len)
    _hex(f[11], "7z 加密数据", data_len * 2)
    if data_len < 16 or data_len % 16 or unpack > data_len:
        raise ValueError("7z 加密数据长度或解压大小无效。")
    if kind:
        if not 1 <= len(f[12]) <= 7:
            raise ValueError("7z CRC 长度字段宽度无效。")
        _uint(f[12], "7z CRC 长度", 9999999)
        _hex(f[13], "7z coder 属性")
        attr_len = len(f[13]) // 2
        if attr_len > 5 or (kind == 1 and attr_len != 5) or (kind == 2 and attr_len != 1):
            raise ValueError("7z 压缩 CRC 长度或 coder 属性不受 hashcat 支持。")
    return value
