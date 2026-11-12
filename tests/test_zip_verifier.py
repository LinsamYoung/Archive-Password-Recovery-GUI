import tempfile
import unittest
from pathlib import Path

from PySide6.QtCore import QEventLoop, QProcess, QTimer
from PySide6.QtWidgets import QApplication

from main import ArchiveCracker, ZipCandidateVerifier


class ZipCandidateVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_wrong_candidate_is_skipped_and_correct_zipcrypto_password_is_validated(self):
        archive = Path(__file__).parent / "data" / "zipcrypto_store.zip"
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "candidates.txt"
            output.write_bytes(b"wrong\n$HEX[31]\n")
            verifier = ZipCandidateVerifier(archive, output)
            loop = QEventLoop()
            result = []
            verifier.finished_check.connect(lambda candidate, detail: (result.append((candidate, detail)), loop.quit()))
            verifier.start()
            QTimer.singleShot(10_000, loop.quit)
            loop.exec()
            verifier.wait()
            self.assertEqual(result, [(b"1", "")])

    def test_hashcat_exit_code_one_without_output_is_normal_exhaustion(self):
        window = ArchiveCracker()
        failures = []
        window._fail = lambda message, detail="": failures.append((message, detail))
        window._on_cracking_finished(1, QProcess.ExitStatus.NormalExit)
        self.assertEqual(failures, [])
        self.assertIn("未找到", window.password_label.text())
        self.assertEqual(window.progress_bar.format(), "任务完成")


if __name__ == "__main__":
    unittest.main()
