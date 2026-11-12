"""识别 zip2john 输出并映射到 hashcat ZIP 模式。"""

from __future__ import annotations

import re
from pathlib import Path


MAX_PKZIP_DATA = 320 * 1024


def parse_zip_hash(output: str) -> tuple[str | None, int | None, bool]:
    """返回 ZIP 哈希、hashcat 模式及是否需要对原 ZIP 验证候选。"""
    for signature, closing in (("$zip2$", "$/zip2$"), ("$pkzip2$", "$/pkzip2$"), ("$pkzip$", "$/pkzip$")):
        start = output.find(signature)
        if start < 0:
            continue
        end = output.find(closing, start + len(signature))
        if end < 0:
            raise ValueError(f"ZIP 哈希格式不完整：缺少结束标记 {closing}")
        archive_hash = output[start : end + len(closing)]
        if signature == "$zip2$":
            return archive_hash, 13600, False
        mode, validate = _parse_pkzip_hash(archive_hash, signature, closing)
        return archive_hash, mode, validate
    return None, None, False


def effective_hashcat_zip_mode(mode: int, hashcat_dir: Path) -> tuple[int, bool]:
    """仅规避随附 7.1.2 的 17220 缺失 include 文件问题。"""
    if mode != 17220:
        return mode, False
    kernel_path = hashcat_dir / "OpenCL" / "m17220_a3-pure.cl"
    include_path = hashcat_dir / "OpenCL" / "inc_checksum_crc32.cl"
    try:
        kernel_source = kernel_path.read_text(encoding="utf-8")
    except OSError:
        return mode, False
    if re.search(r"#include\s+[^\r\n]*inc_checksum_crc32\.cl", kernel_source) and not include_path.exists():
        return 17225, True
    return mode, False




def _parse_pkzip_hash(archive_hash: str, signature: str, closing: str) -> tuple[int, bool]:
    body = archive_hash[len(signature) : -len(closing)]
    if not body.endswith("*"):
        raise ValueError("PKZIP 哈希缺少记录结束分隔符。")
    body = body[:-1]
    fields = body.split("*")
    if any(field == "" for field in fields):
        raise ValueError("PKZIP 哈希包含空字段或截断字段。")
    position = 0

    def take(label: str) -> str:
        nonlocal position
        if position >= len(fields):
            raise ValueError(f"PKZIP 哈希截断：缺少{label}。")
        field = fields[position]
        position += 1
        return field

    def integer(label: str, base: int, maximum: int | None = None) -> int:
        value = take(label)
        pattern = r"[0-9]+" if base == 10 else r"[0-9a-fA-F]+"
        if not re.fullmatch(pattern, value):
            raise ValueError(f"PKZIP 哈希中的{label}格式无效。")
        try:
            parsed = int(value, base)
        except ValueError as error:
            raise ValueError(f"PKZIP 哈希中的{label}不是有效数字。") from error
        if parsed < 0 or (maximum is not None and parsed > maximum):
            raise ValueError(f"PKZIP 哈希中的{label}超出有效范围。")
        return parsed

    count = integer("记录数", 10, 8)
    checksum_size = integer("校验和长度", 10, 2)
    if count < 1 or checksum_size not in (1, 2):
        raise ValueError("PKZIP 哈希中的记录数或校验和长度无效。")

    versions: list[tuple[int, int, int, int]] = []
    is_v2 = signature == "$pkzip2$"
    for record_index in range(count):
        data_type = integer(f"第 {record_index + 1} 条记录类型", 10, 3)
        if data_type == 3:
            raise ValueError("此 ZIP 哈希引用外部数据文件，当前不支持该 zip2john 输出格式。")
        integer(f"第 {record_index + 1} 条记录 magic 类型", 10)
        compressed_length = None
        if data_type > 1:
            compressed_length = integer(f"第 {record_index + 1} 条压缩长度", 16, MAX_PKZIP_DATA)
            integer(f"第 {record_index + 1} 条解压长度", 16)
            integer(f"第 {record_index + 1} 条 CRC", 16)
            integer(f"第 {record_index + 1} 条偏移", 16)
            integer(f"第 {record_index + 1} 条附加偏移", 16)

        compression_type = integer(f"第 {record_index + 1} 条压缩方式", 10)
        data_length = integer(f"第 {record_index + 1} 条数据长度", 16, MAX_PKZIP_DATA)
        for checksum_field in ("CRC 校验和", "时间戳校验和")[: 2 if is_v2 else 1]:
            checksum = take(f"第 {record_index + 1} 条{checksum_field}")
            if not re.fullmatch(r"[0-9a-fA-F]{4}", checksum):
                raise ValueError(f"PKZIP 哈希中的{checksum_field}格式无效。")

        data = take(f"第 {record_index + 1} 条数据")
        if not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", data):
            raise ValueError(f"PKZIP 哈希中的第 {record_index + 1} 条数据不是完整十六进制字节。")
        if len(data) != data_length * 2:
            raise ValueError(f"PKZIP 哈希中的第 {record_index + 1} 条数据长度与字段不符。")
        if data_length < 12:
            raise ValueError(f"PKZIP 哈希中的第 {record_index + 1} 条数据不足 12 字节加密头。")
        if data_type == 2 and data_length != compressed_length:
            raise ValueError(f"PKZIP 哈希中的第 {record_index + 1} 条完整数据被截断。")
        if compression_type not in (0, 8):
            raise ValueError(f"不支持 ZIP 压缩方式 {compression_type}，无法安全选择 hashcat 模式。")
        versions.append((data_type, compression_type, data_length, compressed_length or 0))

    if position != len(fields):
        raise ValueError("PKZIP 哈希包含未识别的尾随字段。")

    if all(data_type <= 1 for data_type, *_ in versions):
        if count < 3:
            raise ValueError("此 ZIP 哈希只有校验和数据且记录数不足 3，无法可靠验证密码。")
        return 17230, True

    compression_types = {compression for _, compression, _, _ in versions}
    if count == 1:
        return (17200 if compression_types == {8} else 17210), False
    if compression_types == {8}:
        return 17220, False
    return 17225, False
