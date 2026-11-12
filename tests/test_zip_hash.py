import json
import unittest
from pathlib import Path

from zip_hash import effective_hashcat_zip_mode, parse_zip_hash


DATA_DIR = Path(__file__).parent / "data"


class ZipHashParsingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.official = json.loads((DATA_DIR / "official_zip_hashes.json").read_text(encoding="utf-8"))
        cls.real = json.loads((DATA_DIR / "zip2john_real_outputs.json").read_text(encoding="utf-8"))

    def test_official_examples_map_to_all_requested_modes(self):
        for expected_mode in (17200, 17210, 17220, 17225, 17230):
            with self.subTest(mode=expected_mode):
                archive_hash, mode, verify = parse_zip_hash(self.official[str(expected_mode)])
                self.assertTrue(archive_hash)
                self.assertEqual(mode, expected_mode)
                self.assertEqual(verify, expected_mode == 17230)

    def test_official_winzip_aes_maps_to_13600(self):
        archive_hash, mode, verify = parse_zip_hash(self.official["13600"])
        self.assertTrue(archive_hash.endswith("$/zip2$"))
        self.assertEqual((mode, verify), (13600, False))

    def test_real_zip2john_output_maps_store_deflate_multi_mixed_and_aes(self):
        expected = {
            "store": (17210, False),
            "deflate": (17200, False),
            "multi": (17220, False),
            "mixed": (17225, False),
            "mixed-store": (17225, False),
            "aes": (13600, False),
            "checksum": (17230, True),
        }
        for name, result in expected.items():
            with self.subTest(name=name):
                archive_hash, mode, verify = parse_zip_hash(self.real[name])
                self.assertTrue(archive_hash)
                self.assertEqual((mode, verify), result)

    def test_truncation_invalid_fields_external_data_and_checksum_limits_fail(self):
        valid = self.official["17200"]
        damaged_inputs = (
            valid.replace("$/pkzip2$", "", 1),
            valid.replace("$pkzip2$1*", "$pkzip2$+1*", 1),
            valid.replace("$pkzip2$1*", "$pkzip2$9*", 1),
            valid.replace("*28*8*", "*28*3*", 1),
            self.official["17230"].replace("$pkzip2$8*", "$pkzip2$2*", 1),
        )
        for damaged in damaged_inputs:
            with self.subTest(sample=damaged[:40]):
                with self.assertRaises(ValueError):
                    parse_zip_hash(damaged)

        with self.assertRaisesRegex(ValueError, "引用外部数据文件"):
            parse_zip_hash(self.official["17200"].replace("$pkzip2$1*1*2*", "$pkzip2$1*1*3*", 1))
        with self.assertRaisesRegex(ValueError, "完整数据被截断"):
            parse_zip_hash(self.official["17200"].replace("*e3*1c5*", "*e2*1c5*", 1))

    def test_missing_winzip_closing_marker_is_reported(self):
        with self.assertRaisesRegex(ValueError, "缺少结束标记"):
            parse_zip_hash(self.official["13600"].replace("$/zip2$", ""))

    def test_runtime_fallback_only_applies_to_known_missing_17220_include(self):
        import tempfile

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            opencl = root / "OpenCL"
            opencl.mkdir()
            kernel = opencl / "m17220_a3-pure.cl"
            kernel.write_text('#include M2S(INCLUDE_PATH/inc_checksum_crc32.cl)\n', encoding="utf-8")
            self.assertEqual(effective_hashcat_zip_mode(17220, root), (17225, True))
            self.assertEqual(effective_hashcat_zip_mode(17200, root), (17200, False))
            (opencl / "inc_checksum_crc32.cl").write_text("", encoding="utf-8")
            self.assertEqual(effective_hashcat_zip_mode(17220, root), (17220, False))


if __name__ == "__main__":
    unittest.main()
