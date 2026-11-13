"""翻译解析器产生的已知错误，不修改未知异常或外部工具输出。"""

import re


_MESSAGES = {
    "PKZIP 哈希缺少记录结束分隔符。": "PKZIP hash is missing the record terminator.",
    "PKZIP 哈希包含空字段或截断字段。": "PKZIP hash contains an empty or truncated field.",
    "PKZIP 哈希中的记录数或校验和长度无效。": "Invalid record count or checksum length in PKZIP hash.",
    "此 ZIP 哈希引用外部数据文件，当前不支持该 zip2john 输出格式。": "This ZIP hash refers to an external data file; this zip2john format is not supported.",
    "PKZIP 哈希包含未识别的尾随字段。": "PKZIP hash contains unrecognized trailing fields.",
    "此 ZIP 哈希只有校验和数据且记录数不足 3，无法可靠验证密码。": "This ZIP hash contains only checksum data and fewer than 3 records, so passwords cannot be reliably verified.",
    "RAR3 哈希字段或类型无效。": "Invalid RAR3 hash fields or type.",
    "RAR3 类型 0 哈希字段数量无效。": "Invalid number of fields in RAR3 type 0 hash.",
    "RAR3 哈希引用外部数据文件，hashcat 不支持。": "RAR3 hash refers to an external data file, which hashcat does not support.",
    "RAR3 类型 1 哈希字段数量无效。": "Invalid number of fields in RAR3 type 1 hash.",
    "RAR3 大小或方法字段宽度无效。": "Invalid width of RAR3 size or method field.",
    "RAR3 压缩/解压大小不受 hashcat 支持。": "RAR3 compressed or uncompressed size is not supported by hashcat.",
    "RAR3 加密数据长度与压缩大小不符。": "RAR3 encrypted data length does not match the compressed size.",
    "RAR3 未压缩数据的解压大小不能大于压缩大小。": "RAR3 stored data cannot have an uncompressed size larger than its compressed size.",
    "RAR5 哈希字段数量无效。": "Invalid number of RAR5 hash fields.",
    "RAR5 盐或校验字段长度不受 hashcat 支持。": "RAR5 salt or verification field length is not supported by hashcat.",
    "RAR5 成本因子必须恰好为两位数字。": "RAR5 cost factor must contain exactly two digits.",
    "RAR5 成本因子不能为 0。": "RAR5 cost factor cannot be 0.",
    "7z 哈希字段数量无效。": "Invalid number of 7z hash fields.",
    "7z 哈希压缩附加字段数量无效。": "Invalid number of additional compression fields in 7z hash.",
    "7z 类型、成本因子、盐长度或 IV 长度字段宽度无效。": "Invalid width of 7z type, cost factor, salt length or IV length field.",
    "7z CRC、加密数据长度或解压大小字段宽度无效。": "Invalid width of 7z CRC, encrypted data length or unpacked size field.",
    "hashcat 7.1.2 的 7z 模式要求盐长度为 0。": "The 7z mode in hashcat 7.1.2 requires a salt length of 0.",
    "7z 加密数据长度或解压大小无效。": "Invalid 7z encrypted data length or unpacked size.",
    "7z CRC 长度字段宽度无效。": "Invalid width of 7z CRC length field.",
    "7z 压缩 CRC 长度或 coder 属性不受 hashcat 支持。": "7z compression CRC length or coder properties are not supported by hashcat.",
}
_FIELDS = {
    "RAR3 盐": "RAR3 salt", "RAR3 校验数据": "RAR3 verification data", "RAR3 CRC": "RAR3 CRC",
    "RAR3 压缩大小": "RAR3 compressed size", "RAR3 解压大小": "RAR3 unpacked size", "RAR3 加密数据": "RAR3 encrypted data", "RAR3 方法": "RAR3 method",
    "RAR5 盐": "RAR5 salt", "RAR5 成本因子": "RAR5 cost factor", "RAR5 IV": "RAR5 IV", "RAR5 密码校验值": "RAR5 password verification value",
    "7z 数据类型": "7z data type", "7z 成本因子": "7z cost factor", "7z 盐长度": "7z salt length", "7z 盐": "7z salt", "7z IV 长度": "7z IV length", "7z IV": "7z IV", "7z CRC": "7z CRC", "7z 加密数据长度": "7z encrypted data length", "7z 解压大小": "7z unpacked size", "7z 加密数据": "7z encrypted data", "7z CRC 长度": "7z CRC length", "7z coder 属性": "7z coder properties",
    "记录数": "record count", "校验和长度": "checksum length", "CRC 校验和": "CRC checksum", "时间戳校验和": "timestamp checksum",
}
_RECORD_FIELDS = {
    "记录类型": "record type", "记录 magic 类型": "record magic type", "压缩长度": "compressed length", "解压长度": "unpacked length", "CRC": "CRC", "偏移": "offset", "附加偏移": "additional offset", "压缩方式": "compression method", "数据长度": "data length", "CRC 校验和": "CRC checksum", "时间戳校验和": "timestamp checksum", "数据": "data",
}


def _field_name(field: str) -> str | None:
    if field in _FIELDS:
        return _FIELDS[field]
    match = re.fullmatch(r"第 ([0-9]+) 条(.+)", field)
    if match and match.group(2) in _RECORD_FIELDS:
        return f"record {match.group(1)} {_RECORD_FIELDS[match.group(2)]}"
    return None


def translate_parse_error(message: str, language: str) -> str:
    if language != "en":
        return message
    if message in _MESSAGES:
        return _MESSAGES[message]
    match = re.fullmatch(r"ZIP 哈希格式不完整：缺少结束标记 (\$/zip2\$|\$/pkzip2\$|\$/pkzip\$)", message)
    if match:
        return f"Incomplete ZIP hash: missing closing marker {match.group(1)}"
    match = re.fullmatch(r"(.+)( 必须是十进制数字。| 超出 hashcat 7\.1\.2 支持范围。| 的长度或十六进制格式无效。)", message)
    if match and match.group(1) in _FIELDS:
        suffixes = {" 必须是十进制数字。": " must be a decimal number.", " 超出 hashcat 7.1.2 支持范围。": " is outside the range supported by hashcat 7.1.2.", " 的长度或十六进制格式无效。": " has an invalid length or hexadecimal format."}
        return _FIELDS[match.group(1)] + suffixes[match.group(2)]
    match = re.fullmatch(r"PKZIP 哈希截断：缺少(.+)。", message)
    if match and (field := _field_name(match.group(1))):
        return f"Truncated PKZIP hash: missing {field}."
    match = re.fullmatch(r"PKZIP 哈希中的(.+?)(格式无效|不是有效数字|超出有效范围)。", message)
    if match and (field := _field_name(match.group(1))):
        reasons = {"格式无效": "has an invalid format", "不是有效数字": "is not a valid number", "超出有效范围": "is outside the valid range"}
        return f"The {field} in the PKZIP hash {reasons[match.group(2)]}."
    match = re.fullmatch(r"PKZIP 哈希中的第 ([0-9]+) 条(数据不是完整十六进制字节|数据长度与字段不符|数据不足 12 字节加密头|完整数据被截断)。", message)
    if match:
        reasons = {"数据不是完整十六进制字节": "data is not a sequence of complete hexadecimal bytes", "数据长度与字段不符": "data length does not match its field", "数据不足 12 字节加密头": "data is shorter than the 12-byte encryption header", "完整数据被截断": "complete data is truncated"}
        return f"PKZIP record {match.group(1)} {reasons[match.group(2)]}."
    match = re.fullmatch(r"不支持 ZIP 压缩方式 ([0-9]+)，无法安全选择 hashcat 模式。", message)
    if match:
        return f"ZIP compression method {match.group(1)} is unsupported; cannot safely select a hashcat mode."
    match = re.fullmatch(r"RAR3 方法 ([0-9]+) 不受 hashcat 7\.1\.2 支持。", message)
    if match:
        return f"RAR3 method {match.group(1)} is not supported by hashcat 7.1.2."
    match = re.fullmatch(r"7z 数据类型 ([0-9]+)(（PPMd）|（BZip2）|（截断数据）)?不受 hashcat 7\.1\.2 支持(；该类型可能包含预处理过滤器或组合编码)?。", message)
    if match:
        name = {None: "", "（PPMd）": " (PPMd)", "（BZip2）": " (BZip2)", "（截断数据）": " (truncated data)"}[match.group(2)]
        note = "; this type may contain preprocessing filters or combined encoding" if match.group(3) else ""
        return f"7z data type {match.group(1)}{name} is not supported by hashcat 7.1.2{note}."
    return message
