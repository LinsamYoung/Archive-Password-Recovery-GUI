import unittest
from unittest.mock import patch

from archive_hash import parse_archive_hash


class ArchiveHashTests(unittest.TestCase):
    def test_hashcat_official_examples(self):
        examples = (
            ("$RAR3$*0*45109af8ab5f297a*adbf6c5385d7a40373e8f77d7b89d317", 12500),
            ("$RAR3$*1*e54a73729887cb53*49b0a846*16*14*1*34620bcca8176642a210b1051901921e*30", 23700),
            ("$RAR3$*1*ad56eb40219c9da2*834064ce*32*13*1*eb47b1abe17a1a75bce6c92ab1cef3f4126035ea95deaf08b3f32a0c7b8078e1*33", 23800),
            ("$rar5$16$38466361001011015181344360681307$15$00000000000000000000000000000000$8$cc7a30583e62676a", 13000),
            ("$7z$0$14$0$$11$33363437353138333138300000000000$2365089182$16$12$d00321533b483f54a523f624a5f63269", 11600),
        )
        for line, mode in examples:
            with self.subTest(mode=mode):
                self.assertEqual(parse_archive_hash(line), (line, mode))

    def test_rar3_line_metadata_is_excluded_and_method_selects_mode(self):
        line = "$RAR3$*1*e54a73729887cb53*49b0a846*16*14*1*" + "00" * 16 + "*30"
        self.assertEqual(parse_archive_hash("archive.rar:" + line + ":archive.rar"), (line, 23700))

    def test_rar3_external_or_bad_fields_are_rejected(self):
        line = "$RAR3$*1*e54a73729887cb53*49b0a846*16*14*1*" + "00" * 16 + "*30"
        with self.assertRaisesRegex(ValueError, "外部数据"):
            parse_archive_hash(line.replace("*14*1*", "*14*0*"))
        with self.assertRaises(ValueError):
            parse_archive_hash(line.replace("*30", "*36"))

    def test_seven_zip_supported_and_unsupported_data_types(self):
        for data_type in (0, 1, 2, 7):
            # 测试压缩类型附加字段数量和 coder 属性长度。
            raw = "$7z$%d$14$0$$11$33363437353138333138300000000000$2365089182$16$12$d00321533b483f54a523f624a5f63269" % data_type
            if data_type:
                raw += "$12$" + ("00" * (5 if data_type == 1 else 1))
            self.assertEqual(parse_archive_hash(raw)[1], 11600)
        for data_type in (3, 6, 128, 131):
            raw = "$7z$%d$14$0$$11$33363437353138333138300000000000$2365089182$16$12$d00321533b483f54a523f624a5f63269" % data_type
            with self.subTest(data_type=data_type), self.assertRaisesRegex(ValueError, "不受 hashcat"):
                parse_archive_hash(raw)
        combined = "$7z$17$14$0$$11$33363437353138333138300000000000$2365089182$16$12$d00321533b483f54a523f624a5f63269"
        with self.assertRaisesRegex(ValueError, "预处理过滤器或组合编码"):
            parse_archive_hash(combined)

    def test_seven_zip_rejects_salt_and_malformed_data(self):
        line = "$7z$0$14$0$$11$33363437353138333138300000000000$2365089182$16$12$d00321533b483f54a523f624a5f63269"
        with self.assertRaisesRegex(ValueError, "盐长度"):
            parse_archive_hash(line.replace("$14$0$$", "$14$1$00$"))
        with self.assertRaisesRegex(ValueError, "长度或十六进制"):
            parse_archive_hash(line.replace("$16$12$", "$17$12$"))

    def test_extraction_stdout_is_complete_and_diagnostics_are_bounded(self):
        from main import ArchiveCracker

        payload = b"x" * (10 * 1024 * 1024)

        class FakeProcess:
            def readAllStandardOutput(self):
                return payload

        cracker = ArchiveCracker.__new__(ArchiveCracker)
        cracker.process = FakeProcess()
        cracker._status_updates_enabled = False
        cracker._extraction_output = bytearray()
        cracker._stdout_buffer = bytearray()
        cracker._stderr_buffer = bytearray()
        cracker._process_output_truncated = False
        cracker._on_standard_output_ready()
        self.assertEqual(len(cracker._extraction_output), len(payload))
        self.assertEqual(len(cracker._stdout_buffer), 0)
        diagnostic = cracker._format_process_diagnostics(payload.decode(), "")
        self.assertLess(len(diagnostic), 70 * 1024)
        self.assertIn("诊断输出已省略", diagnostic)

    def test_generated_over_8_mib_7z_hash_survives_extraction_buffer(self):
        from main import ArchiveCracker

        data_len = 5 * 1024 * 1024
        payload = (
            f"$7z$0$19$0$$16${'00' * 16}$0${data_len}${data_len}$".encode()
            + b"00" * data_len
        )

        class FakeProcess:
            def readAllStandardOutput(self):
                return payload

        cracker = ArchiveCracker.__new__(ArchiveCracker)
        cracker.process = FakeProcess()
        cracker._status_updates_enabled = False
        cracker._extraction_output = bytearray()
        cracker._on_standard_output_ready()
        output = cracker._extraction_output.decode()
        archive_hash, mode, verify = cracker._parse_hash(output)
        self.assertGreater(len(archive_hash), 8 * 1024 * 1024)
        self.assertEqual((mode, verify), (11600, False))

    def test_hashcat_partial_status_line_is_bounded_without_false_truncation(self):
        from main import ArchiveCracker

        cracker = ArchiveCracker.__new__(ArchiveCracker)
        cracker._status_updates_enabled = True
        cracker._status_line_buffer = ""
        cracker._stdout_buffer = bytearray()
        cracker._process_output_truncated = False
        with patch("main.MAX_PROCESS_OUTPUT_BYTES", 100_000):
            cracker._consume_status_output(b"x" * (64 * 1024 + 1))
        self.assertEqual(len(cracker._status_line_buffer), 0)
        self.assertEqual(len(cracker._stdout_buffer), 64 * 1024 + 1)
        self.assertFalse(cracker._process_output_truncated)
        with patch("main.MAX_PROCESS_OUTPUT_BYTES", 32):
            cracker._append_process_output(cracker._stdout_buffer, b"y" * 40)
        self.assertTrue(cracker._process_output_truncated)


if __name__ == "__main__":
    unittest.main()
