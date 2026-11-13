import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from PySide6.QtWidgets import QApplication

import main


class UiLocalizationDependencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.window = main.ArchiveCracker()
        self.addCleanup(self.window.close)

    def _tool_paths(self, root):
        return {key: root / f"{key}.exe" for key in main.ArchiveCracker._tool_requirements()}

    def test_language_round_trip_keeps_file_path_password_and_tooltip_data(self):
        archive_path = r"C:\Users\测试\backup 密码.zip"
        password = "原文-Pä$$/密码"
        self.window.filename_label.setTextWithData("文件名：", Path(archive_path).name)
        self.window.filepath_label.setTextWithData("路径：", archive_path)
        self.window.password_label.setTextWithData("密码：", password)
        self.window.tool_status_labels["zip2john"].setToolTipWithData("预期路径：", archive_path)

        self.window.language_combo.setCurrentIndex(1)
        self.assertEqual(self.window.windowTitle(), "Archive Password Recovery")
        self.assertEqual(self.window.select_button.text(), "Select RAR / ZIP / 7Z file")
        self.assertIn("Each job creates a separate subfolder", self.window.cache_directory_input.toolTip())
        self.assertIn(Path(archive_path).name, self.window.filename_label.text())
        self.assertIn(archive_path, self.window.filepath_label.text())
        self.assertIn(password, self.window.password_label.text())
        self.assertIn(archive_path, self.window.tool_status_labels["zip2john"].toolTip())

        self.window.language_combo.setCurrentIndex(0)
        self.assertEqual(self.window.windowTitle(), "加密压缩包密码恢复工具")
        self.assertEqual(self.window.select_button.text(), "选择 RAR / ZIP / 7Z 文件")
        self.assertIn("每次任务会在此目录下创建独立子目录", self.window.cache_directory_input.toolTip())
        self.assertIn(archive_path, self.window.filepath_label.text())
        self.assertIn(password, self.window.password_label.text())

    def test_independent_missing_status_and_recheck_all_present_all_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self._tool_paths(Path(directory))
            paths["rar2john"].touch()
            paths["7z2hashcat"].touch()
            with patch.object(main.ArchiveCracker, "_tool_paths", return_value=paths):
                status = self.window._refresh_tool_status()
                self.assertEqual(status, {"hashcat": False, "rar2john": True, "zip2john": False, "7z2hashcat": True})
                self.assertTrue(self.window.tool_download_buttons["rar2john"].isHidden())
                self.assertFalse(self.window.tool_download_buttons["hashcat"].isHidden())
                self.assertFalse(self.window.tool_download_buttons["zip2john"].isHidden())
                self.assertTrue(self.window.tool_download_buttons["7z2hashcat"].isHidden())

                for path in paths.values():
                    path.touch()
                self.assertTrue(all(self.window._refresh_tool_status().values()))
                self.assertTrue(all(button.isHidden() for button in self.window.tool_download_buttons.values()))

                for path in paths.values():
                    path.unlink()
                self.assertFalse(any(self.window._refresh_tool_status().values()))
                self.assertTrue(all(not button.isHidden() for button in self.window.tool_download_buttons.values()))

    def test_download_buttons_open_the_matching_official_page(self):
        expected_urls = {
            "hashcat": "https://hashcat.net/hashcat/",
            "rar2john": "https://www.openwall.com/john/",
            "zip2john": "https://www.openwall.com/john/",
            "7z2hashcat": "https://github.com/philsmd/7z2hashcat/releases/tag/2.0",
        }
        with patch.object(main.QDesktopServices, "openUrl", return_value=True) as open_url, patch.object(
            main.DownloadInfoDialog, "show"
        ) as show_dialog:
            for index, (key, expected_url) in enumerate(expected_urls.items(), start=1):
                with self.subTest(tool=key):
                    open_url.reset_mock()
                    self.window.tool_download_buttons[key].click()
                    self.assertEqual(open_url.call_args.args[0].toString(), expected_url)
                    self.assertEqual(open_url.call_count, 1)
                    self.assertEqual(show_dialog.call_count, index)
            self.assertTrue(all(url.startswith("https://") for url in expected_urls.values()))

    def test_download_failure_shows_copyable_url_and_dialog_retranslates(self):
        url = "https://hashcat.net/hashcat/"
        with patch.object(main.QDesktopServices, "openUrl", return_value=False) as open_url:
            self.window._open_tool_download("hashcat")
        dialog = self.window.findChild(main.DownloadInfoDialog)
        self.assertIsNotNone(dialog)
        self.assertFalse(dialog.opened)
        self.assertEqual(dialog.textInteractionFlags(), main.Qt.TextInteractionFlag.TextSelectableByMouse)
        self.assertIn(url, dialog.text())
        self.assertIn("无法打开浏览器", dialog.text())
        self.assertEqual(open_url.call_args.args[0].toString(), url)

        self.window.language_combo.setCurrentIndex(1)
        self.assertIn("Could not open the browser", dialog.text())
        self.assertIn(url, dialog.text())
        self.assertIn("Check again", dialog.text())

    def test_diagnostic_output_keeps_chinese_tool_stdout_and_stderr_verbatim(self):
        with patch.object(main, "_language", "en"):
            diagnostic = self.window._format_process_diagnostics("工具输出：中文密码", "错误输出：保留原文")
        self.assertIn("stdout:\n工具输出：中文密码", diagnostic)
        self.assertIn("stderr:\n错误输出：保留原文", diagnostic)

    def test_progress_format_retranslates_when_language_changes_back_and_forth(self):
        self.window.language_combo.setCurrentIndex(1)
        self.window._update_hashcat_progress({
            "progress": [500, 1000],
            "guess": {"guess_mask_length": 2},
            "devices": [{"speed": 1234}],
        })
        english = self.window.progress_bar.format()
        self.assertIn("Round 2/4", english)
        self.assertIn("50.0%", english)
        self.assertIn("Speed: 1.2 kH/s", english)
        self.assertIn("ETA: Calculating", english)

        self.window.language_combo.setCurrentIndex(0)
        chinese = self.window.progress_bar.format()
        self.assertIn("轮次 2/4", chinese)
        self.assertIn("50.0%", chinese)
        self.assertIn("速度：1.2 kH/s", chinese)
        self.assertIn("预计剩余：计算中", chinese)

        self.window.language_combo.setCurrentIndex(1)
        self.assertEqual(self.window.progress_bar.format(), english)

    def test_file_dialog_and_warning_messages_are_translated(self):
        self.window.language_combo.setCurrentIndex(1)
        with patch.object(main.QtFileDialog, "getOpenFileName", return_value=("", "")) as file_dialog:
            self.window.select_file()
        self.assertEqual(file_dialog.call_args.args[1], "Select encrypted archive")
        self.assertEqual(file_dialog.call_args.args[3], "Archives (*.rar *.zip *.7z)")

        with patch.object(main.QtMessageBox, "warning") as warning:
            self.window.start_cracking()
        self.assertEqual(warning.call_args.args[1], "No file selected")
        self.assertEqual(warning.call_args.args[2], "Select a RAR, ZIP or 7Z file first.")

    def test_parse_error_is_translated_but_tool_output_remains_original(self):
        class FakeProcess:
            pass

        self.window.process = FakeProcess()
        self.window._extraction_output = bytearray("提取器输出：原始中文", encoding="utf-8")
        self.window._stderr_buffer = bytearray("提取器错误：原始诊断", encoding="utf-8")
        self.window._drain_process_output = lambda: None
        self.window._parse_hash = lambda _output: (_ for _ in ()).throw(
            ValueError("ZIP 哈希格式不完整：缺少结束标记 $/zip2$")
        )
        failures = []
        self.window._fail = lambda message, detail="": failures.append((main.translate(message), detail))

        self.window.language_combo.setCurrentIndex(1)
        self.window._on_hash_extracted(0, None)

        self.assertEqual(len(failures), 1)
        message, detail = failures[0]
        self.assertEqual(message, "Unrecognized archive hash structure.")
        self.assertIn("Incomplete ZIP hash: missing closing marker $/zip2$", detail)
        self.assertIn("提取器输出：原始中文", detail)
        self.assertIn("提取器错误：原始诊断", detail)

    def test_hash_recovery_handoff_stays_mocked_and_preserves_workflow(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.window.hash_file = root / "archive.hash"
            self.window.output_file = root / "password.txt"
            self.window.process = object()
            self.window.extracted_hash = None
            self.window._parse_hash = lambda _output: ("$RAR3$fixture", 23700, False)
            self.window._drain_process_output = lambda: None
            self.window._extraction_output = bytearray(b"fixture")
            self.window._stderr_buffer = bytearray()
            with patch.object(self.window, "_run_process") as run_process:
                self.window._on_hash_extracted(0, None)

            self.assertEqual(self.window.hash_file.read_text(encoding="utf-8"), "$RAR3$fixture\n")
            self.assertEqual(run_process.call_count, 1)
            executable, arguments = run_process.call_args.args[:2]
            self.assertEqual(executable, main.HASHCAT_DIR / "hashcat.exe")
            self.assertIn("23700", arguments)
            self.assertTrue(self.window.progress_bar.format())


if __name__ == "__main__":
    unittest.main()
