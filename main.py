from __future__ import annotations

import ctypes
import json
import re
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

from PySide6.QtCore import QProcess, Qt
from PySide6.QtGui import QCursor, QGuiApplication, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QToolTip,
    QVBoxLayout,
    QWidget,
)


APP_DIR = Path(__file__).resolve().parent
JOHN_RUN_DIR = APP_DIR / "john-1.9.0-jumbo-1-win64" / "run"
HASHCAT_DIR = APP_DIR / "hashcat-7.1.2"
SEVEN_ZIP_EXTRACTOR = APP_DIR / "7z2hashcat64-2.0" / "7z2hashcat64-2.0.exe"
SUPPORTED_SUFFIXES = {".rar", ".zip", ".7z"}
DRIVE_FIXED = 3
SPACE_RESERVE_BYTES = 1024**3


class ArchiveCracker(QMainWindow):
    """Main application window and non-blocking cracking workflow."""

    def __init__(self) -> None:
        super().__init__()
        self.archive_path: Path | None = None
        self.extracted_hash: str | None = None
        self.recovered_password: str | None = None
        self.process: QProcess | None = None
        self.workspace_path: Path | None = None
        self.workspace_root: Path | None = None
        self.tool_archive_path: Path | None = None
        self.output_file: Path | None = None
        self.hash_file: Path | None = None
        self._stdout_buffer = bytearray()
        self._stderr_buffer = bytearray()
        self._status_line_buffer = ""
        self._status_updates_enabled = False

        self.setWindowTitle("加密压缩包密码恢复工具")
        icon_path = APP_DIR / "app.ico"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))
        self.setMinimumSize(680, 460)
        self.resize(760, 540)
        self._build_ui()

    def _build_ui(self) -> None:
        central_widget = QWidget(self)
        layout = QVBoxLayout(central_widget)
        layout.setContentsMargins(28, 24, 28, 20)
        layout.setSpacing(12)

        self.select_button = QPushButton("选择 RAR / ZIP / 7Z 文件")
        self.select_button.clicked.connect(self.select_file)
        layout.addWidget(self.select_button)

        self.filename_label = QLabel("文件名：未选择")
        self.filename_label.setWordWrap(True)
        layout.addWidget(self.filename_label)

        self.filepath_label = QLabel("路径：未选择")
        self.filepath_label.setWordWrap(True)
        self.filepath_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.filepath_label)

        self.start_button = QPushButton("开始找回")
        self.start_button.setEnabled(False)
        self.start_button.clicked.connect(self.start_cracking)
        layout.addWidget(self.start_button)

        charset_layout = QHBoxLayout()
        charset_layout.addWidget(QLabel("暴力字符集："))
        self.digit_checkbox = QCheckBox("数字 (0-9)")
        self.lowercase_checkbox = QCheckBox("小写字母 (a-z)")
        self.uppercase_checkbox = QCheckBox("大写字母 (A-Z)")
        self.special_checkbox = QCheckBox("特殊字符")
        for checkbox in (
            self.digit_checkbox,
            self.lowercase_checkbox,
            self.uppercase_checkbox,
            self.special_checkbox,
        ):
            checkbox.setChecked(True)
            charset_layout.addWidget(checkbox)
        charset_layout.addStretch()
        layout.addLayout(charset_layout)

        length_layout = QHBoxLayout()
        length_layout.addWidget(QLabel("密码长度："))
        length_layout.addWidget(QLabel("最小"))
        self.min_length_input = QSpinBox()
        self.min_length_input.setRange(1, 64)
        self.min_length_input.setValue(1)
        length_layout.addWidget(self.min_length_input)
        length_layout.addWidget(QLabel("最大"))
        self.max_length_input = QSpinBox()
        self.max_length_input.setRange(1, 64)
        self.max_length_input.setValue(4)
        length_layout.addWidget(self.max_length_input)
        length_layout.addStretch()
        layout.addLayout(length_layout)

        self.min_length_input.valueChanged.connect(self._sync_length_range)
        self.max_length_input.valueChanged.connect(self._sync_length_range)

        password_layout = QHBoxLayout()
        self.password_label = QLabel("密码：未开始")
        self.password_label.setWordWrap(True)
        self.password_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        password_layout.addWidget(self.password_label, 1)

        self.copy_button = QPushButton("复制")
        self.copy_button.setEnabled(False)
        self.copy_button.clicked.connect(self.copy_password)
        password_layout.addWidget(self.copy_button)
        layout.addLayout(password_layout)

        cache_layout = QHBoxLayout()
        cache_info_label = QLabel("ⓘ")
        cache_info_label.setToolTip("此缓存文件夹仅用于本次任务，并会在任务结束后自动删除。")
        cache_layout.addWidget(cache_info_label)
        self.cache_path_label = QLabel("缓存文件夹：将在任务开始后创建")
        self.cache_path_label.setWordWrap(True)
        self.cache_path_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        cache_layout.addWidget(self.cache_path_label, 1)
        layout.addLayout(cache_layout)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("等待任务开始")
        layout.addWidget(self.progress_bar)

        self._build_tool_check_panel(layout)

        layout.addStretch()
        version_label = QLabel("版本号：2.0")
        version_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(version_label)

        self.setCentralWidget(central_widget)

    def _build_tool_check_panel(self, parent_layout: QVBoxLayout) -> None:
        """Add the bundled-tool availability panel below the progress bar."""
        tool_group = QGroupBox("工具存在检测")
        tool_layout = QGridLayout(tool_group)
        tool_layout.setColumnStretch(1, 1)

        self.tool_status_labels: dict[str, QLabel] = {}
        for row, (key, name) in enumerate(self._tool_requirements().items()):
            tool_layout.addWidget(QLabel(name), row, 0)
            status_label = QLabel()
            status_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            tool_layout.addWidget(status_label, row, 1)
            self.tool_status_labels[key] = status_label

        refresh_button = QPushButton("重新检测")
        refresh_button.clicked.connect(self._refresh_tool_status)
        tool_layout.addWidget(refresh_button, len(self.tool_status_labels), 1, alignment=Qt.AlignmentFlag.AlignRight)
        parent_layout.addWidget(tool_group)
        self._refresh_tool_status()

    @staticmethod
    def _tool_requirements() -> dict[str, str]:
        return {
            "hashcat": "hashcat.exe",
            "rar2john": "RAR 哈希提取器 (rar2john.exe)",
            "zip2john": "ZIP 哈希提取器 (zip2john.exe)",
            "7z2hashcat": "7Z 哈希提取器 (7z2hashcat64-2.0.exe)",
        }

    @staticmethod
    def _tool_paths() -> dict[str, Path]:
        return {
            "hashcat": HASHCAT_DIR / "hashcat.exe",
            "rar2john": JOHN_RUN_DIR / "rar2john.exe",
            "zip2john": JOHN_RUN_DIR / "zip2john.exe",
            "7z2hashcat": SEVEN_ZIP_EXTRACTOR,
        }

    def _refresh_tool_status(self) -> dict[str, bool]:
        """Show whether every bundled executable needed by the app is available."""
        availability = {key: path.is_file() for key, path in self._tool_paths().items()}
        for key, is_available in availability.items():
            label = self.tool_status_labels[key]
            if is_available:
                label.setText("✓ 已找到")
                label.setStyleSheet("color: #188038;")
                label.setToolTip(str(self._tool_paths()[key]))
            else:
                label.setText("✗ 未找到")
                label.setStyleSheet("color: #c5221f;")
                label.setToolTip(f"预期路径：{self._tool_paths()[key]}")
        return availability

    def select_file(self) -> None:
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "选择加密压缩包",
            str(self.archive_path.parent if self.archive_path else APP_DIR),
            "压缩包 (*.rar *.zip *.7z)",
        )
        if not file_name:
            return

        self.archive_path = Path(file_name)
        self.filename_label.setText(f"文件名：{self.archive_path.name}")
        self.filepath_label.setText(f"路径：{self.archive_path}")
        self.password_label.setText("密码：未开始")
        self.cache_path_label.setText("缓存文件夹：将在任务开始后创建")
        self._set_progress_idle()
        self.start_button.setEnabled(True)
        self.copy_button.setEnabled(False)

    def start_cracking(self) -> None:
        if not self.archive_path:
            QMessageBox.warning(self, "未选择文件", "请先选择一个 RAR、ZIP 或 7Z 文件。")
            return
        if self.archive_path.suffix.lower() not in SUPPORTED_SUFFIXES:
            QMessageBox.warning(self, "不支持的格式", "目前仅支持 RAR、ZIP 和 7Z 文件。")
            return
        tool_status = self._refresh_tool_status()
        required_tools = ["hashcat"]
        suffix = self.archive_path.suffix.lower()
        if suffix == ".rar":
            required_tools.append("rar2john")
        elif suffix == ".zip":
            required_tools.append("zip2john")
        else:
            required_tools.append("7z2hashcat")
        missing_tools = [self._tool_requirements()[key] for key in required_tools if not tool_status[key]]
        if missing_tools:
            QMessageBox.critical(self, "缺少工具", f"找不到以下必需工具：\n{chr(10).join(missing_tools)}")
            return

        try:
            self._prepare_workspace()
        except OSError as error:
            self._cleanup_workspace()
            self._fail("无法准备临时工作目录。", str(error))
            return

        self.extracted_hash = None
        self.recovered_password = None
        self.password_label.setText("密码：正在提取哈希…")
        self.cache_path_label.setText(f"缓存文件夹：{self.workspace_root}")
        self._set_progress_busy("正在提取哈希…")
        self._set_running(True)
        if suffix == ".7z":
            self._run_process(
                SEVEN_ZIP_EXTRACTOR,
                [str(self.tool_archive_path)],
                SEVEN_ZIP_EXTRACTOR.parent,
                self._on_hash_extracted,
            )
            return

        extractor = "rar2john.exe" if suffix == ".rar" else "zip2john.exe"
        self._run_process(
            JOHN_RUN_DIR / extractor,
            [str(self.tool_archive_path)],
            JOHN_RUN_DIR,
            self._on_hash_extracted,
        )

    def _prepare_workspace(self) -> None:
        """Create an ASCII workspace and select an archive path legacy tools can read."""
        assert self.archive_path is not None
        # Prefer an NTFS 8.3 path. It avoids copying potentially large archives,
        # but is unavailable when 8.3 file names are disabled on the volume.
        self.tool_archive_path = self._ascii_short_path(self.archive_path)
        staging_required = self.tool_archive_path is None
        required_space = 0
        if staging_required:
            archive_size = self.archive_path.stat().st_size
            required_space = archive_size + max(SPACE_RESERVE_BYTES, archive_size // 10)

        candidates = self._fixed_drives_by_free_space()
        eligible_drives = [drive for drive, free_space in candidates if free_space >= required_space]
        if not eligible_drives:
            raise OSError(
                "没有可用空间充足的本地固定磁盘。"
                f" 需要至少 {self._format_bytes(required_space)}，"
                "其中包含压缩包大小和安全余量。"
            )

        errors: list[str] = []
        for drive in eligible_drives:
            workspace_root = drive / "ArchiveCrackerTemp"
            try:
                workspace_root.mkdir(parents=True, exist_ok=True)
                if staging_required and shutil.disk_usage(workspace_root).free < required_space:
                    raise OSError("创建临时目录后可用空间不足")
                self.workspace_path = Path(tempfile.mkdtemp(prefix="job-", dir=workspace_root))
                self.workspace_root = workspace_root
                break
            except OSError as error:
                errors.append(f"{drive}：{error}")
                try:
                    workspace_root.rmdir()
                except OSError:
                    pass
        else:
            raise OSError("无法在可用磁盘上创建临时工作目录。\n" + "\n".join(errors))

        if staging_required:
            staged_archive = self.workspace_path / f"archive{self.archive_path.suffix.lower()}"
            shutil.copy2(self.archive_path, staged_archive)
            self.tool_archive_path = staged_archive

        self.hash_file = self.workspace_path / "archive.hash"
        self.output_file = self.workspace_path / "recovered-password.txt"

    @staticmethod
    def _fixed_drives_by_free_space() -> list[tuple[Path, int]]:
        """Return writable local fixed drives ordered by available space."""
        buffer_size = ctypes.windll.kernel32.GetLogicalDriveStringsW(0, None)
        if buffer_size == 0:
            raise OSError("无法枚举本地磁盘。")
        buffer = ctypes.create_unicode_buffer(buffer_size + 1)
        result_size = ctypes.windll.kernel32.GetLogicalDriveStringsW(len(buffer), buffer)
        if result_size == 0:
            raise OSError("无法枚举本地磁盘。")

        drives: list[tuple[Path, int]] = []
        for drive_name in buffer[:result_size].split("\0"):
            if not drive_name or ctypes.windll.kernel32.GetDriveTypeW(drive_name) != DRIVE_FIXED:
                continue
            drive = Path(drive_name)
            try:
                drives.append((drive, shutil.disk_usage(drive).free))
            except OSError:
                continue
        return sorted(drives, key=lambda item: item[1], reverse=True)

    @staticmethod
    def _format_bytes(size: int) -> str:
        return f"{size / 1024**3:.2f} GiB"

    @staticmethod
    def _ascii_short_path(path: Path) -> Path | None:
        """Return a usable DOS 8.3 path, or None when the volume has no ASCII alias."""
        required_size = ctypes.windll.kernel32.GetShortPathNameW(str(path), None, 0)
        if required_size == 0:
            return None
        buffer = ctypes.create_unicode_buffer(required_size + 1)
        result_size = ctypes.windll.kernel32.GetShortPathNameW(str(path), buffer, len(buffer))
        short_path = buffer.value
        if result_size == 0 or not short_path or not short_path.isascii():
            return None
        return Path(short_path)

    def _run_process(
        self,
        program: Path,
        arguments: list[str],
        working_directory: Path,
        on_finished,
        status_updates: bool = False,
    ) -> None:
        self.process = QProcess(self)
        self._stdout_buffer.clear()
        self._stderr_buffer.clear()
        self._status_line_buffer = ""
        self._status_updates_enabled = status_updates
        self.process.setProgram(str(program))
        self.process.setArguments(arguments)
        self.process.setWorkingDirectory(str(working_directory))
        self.process.finished.connect(on_finished)
        self.process.errorOccurred.connect(self._on_process_error)
        self.process.readyReadStandardOutput.connect(self._on_standard_output_ready)
        self.process.readyReadStandardError.connect(self._on_standard_error_ready)
        self.process.start()

    def _on_standard_output_ready(self) -> None:
        if self.process is None:
            return
        output = bytes(self.process.readAllStandardOutput())
        if self._status_updates_enabled:
            self._consume_status_output(output)
        else:
            self._stdout_buffer.extend(output)

    def _on_standard_error_ready(self) -> None:
        if self.process is not None:
            self._stderr_buffer.extend(bytes(self.process.readAllStandardError()))

    def _drain_process_output(self) -> None:
        self._on_standard_output_ready()
        self._on_standard_error_ready()

    def _consume_status_output(self, output: bytes) -> None:
        self._status_line_buffer += output.decode(errors="replace")
        lines = self._status_line_buffer.splitlines(keepends=True)
        self._status_line_buffer = ""
        if lines and not lines[-1].endswith(("\n", "\r")):
            self._status_line_buffer = lines.pop()
        for line in lines:
            try:
                status = json.loads(line)
            except json.JSONDecodeError:
                continue
            self._update_hashcat_progress(status)

    def _update_hashcat_progress(self, status: dict) -> None:
        progress = status.get("progress")
        if not isinstance(progress, list) or len(progress) != 2:
            return
        try:
            completed, total = (int(progress[0]), int(progress[1]))
        except (TypeError, ValueError):
            return
        if total <= 0:
            return

        percent = min(100.0, completed * 100 / total)
        speed = sum(
            device.get("speed", 0)
            for device in status.get("devices", [])
            if isinstance(device, dict) and isinstance(device.get("speed", 0), (int, float))
        )
        estimated_stop = status.get("estimated_stop")
        remaining_seconds = None
        if isinstance(estimated_stop, (int, float)) and estimated_stop > time.time():
            remaining_seconds = round(estimated_stop - time.time())

        eta = self._format_duration(remaining_seconds) if remaining_seconds is not None else "计算中"
        round_text = self._format_round(status)
        self.progress_bar.setRange(0, 1000)
        self.progress_bar.setValue(round(percent * 10))
        self.progress_bar.setFormat(
            f"{round_text} ｜ {percent:.1f}% ｜ 速度：{self._format_rate(speed)} ｜ 预计剩余：{eta}"
        )

    def _format_round(self, status: dict) -> str:
        """Identify the active incremental mask length reported by hashcat."""
        total_rounds = self.max_length_input.value() - self.min_length_input.value() + 1
        guess = status.get("guess")
        current_length = guess.get("guess_mask_length") if isinstance(guess, dict) else None
        if not isinstance(current_length, int):
            return f"轮次 ?/{total_rounds}"
        current_round = current_length - self.min_length_input.value() + 1
        current_round = max(1, min(current_round, total_rounds))
        return f"轮次 {current_round}/{total_rounds}"

    @staticmethod
    def _format_rate(speed: float) -> str:
        units = ("H/s", "kH/s", "MH/s", "GH/s", "TH/s", "PH/s")
        for unit in units:
            if speed < 1000 or unit == units[-1]:
                return f"{speed:.1f} {unit}"
            speed /= 1000
        return "0.0 H/s"

    @staticmethod
    def _format_duration(seconds: int) -> str:
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours >= 24:
            days, hours = divmod(hours, 24)
            return f"{days}天{hours:02d}:{minutes:02d}:{seconds:02d}"
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def _on_hash_extracted(self, exit_code: int, _exit_status: QProcess.ExitStatus) -> None:
        assert self.process is not None
        self._drain_process_output()
        output = bytes(self._stdout_buffer).decode(errors="replace")
        error = bytes(self._stderr_buffer).decode(errors="replace")
        if exit_code != 0:
            self._fail("提取压缩包哈希失败。", error)
            return

        self.extracted_hash, mode = self._parse_hash(output)
        if not self.extracted_hash or mode is None:
            self._fail("未能识别该压缩包的加密格式。", error or output)
            return

        self.password_label.setText("密码：正在找回…")
        self._set_progress_busy("正在找回…")
        assert self.hash_file is not None and self.output_file is not None
        self.hash_file.write_text(self.extracted_hash + "\n", encoding="utf-8")
        charset = self._selected_charset()
        if not charset:
            self._fail("请至少选择一种暴力字符集。")
            return
        min_length = self.min_length_input.value()
        max_length = self.max_length_input.value()
        mask = "?1" * max_length
        self._run_process(
            HASHCAT_DIR / "hashcat.exe",
            ["-m", str(mode), "-a", "3", "-1", charset, str(self.hash_file), mask,
             "--increment", "--increment-min", str(min_length), "--increment-max", str(max_length),
             "-o", str(self.output_file), "--outfile-format", "2", "--potfile-disable",
             "--logfile-disable", "--restore-file-path", str(self.workspace_path / "hashcat.restore"),
             "--status", "--status-json", "--status-timer", "1"],
            HASHCAT_DIR,
            self._on_cracking_finished,
            status_updates=True,
        )

    @staticmethod
    def _parse_hash(output: str) -> tuple[str | None, int | None]:
        rar_match = re.search(r"(\$rar3\$.*|\$rar5\$.*)", output, re.IGNORECASE)
        if rar_match:
            archive_hash = rar_match.group(1).strip()
            return archive_hash, 12500 if archive_hash.lower().startswith("$rar3$") else 13000

        zip2_match = re.search(r"(\$zip2\$.*?\$/zip2\$)", output)
        if zip2_match:
            return zip2_match.group(1), 13600

        pkzip2_match = re.search(r"\$pkzip2\$(.*?)\$/pkzip2\$", output)
        if pkzip2_match:
            return f"$pkzip2${pkzip2_match.group(1)}$/pkzip2$", 17200

        seven_zip_match = re.search(r"(\$7z\$.*)", output)
        if seven_zip_match:
            return seven_zip_match.group(1).strip(), 11600
        return None, None

    def _selected_charset(self) -> str:
        charset_parts = []
        if self.digit_checkbox.isChecked():
            charset_parts.append("?d")
        if self.lowercase_checkbox.isChecked():
            charset_parts.append("?l")
        if self.uppercase_checkbox.isChecked():
            charset_parts.append("?u")
        if self.special_checkbox.isChecked():
            charset_parts.append("?s")
        return "".join(charset_parts)

    def _sync_length_range(self) -> None:
        """Keep the minimum and maximum password length inputs consistent."""
        sender = self.sender()
        if sender is self.min_length_input and self.min_length_input.value() > self.max_length_input.value():
            self.max_length_input.setValue(self.min_length_input.value())
        elif sender is self.max_length_input and self.max_length_input.value() < self.min_length_input.value():
            self.min_length_input.setValue(self.max_length_input.value())

    def _on_cracking_finished(self, exit_code: int, _exit_status: QProcess.ExitStatus) -> None:
        password = self._read_password()
        if password is not None:
            self.recovered_password = password
            self.password_label.setText(f"密码：{password}")
            self.copy_button.setEnabled(True)
        elif exit_code == 0:
            self.password_label.setText("密码：未找到（可尝试调整 hashcat 参数或掩码）")
        else:
            self._drain_process_output()
            error = bytes(self._stderr_buffer).decode(errors="replace")
            self._fail("hashcat 执行失败。", error)
            return
        self._cleanup_workspace()
        self._set_progress_complete()
        self._set_running(False)

    def _read_password(self) -> str | None:
        if self.recovered_password is not None:
            return self.recovered_password
        if self.output_file is None or not self.output_file.exists():
            return None
        line = self.output_file.read_text(encoding="utf-8", errors="replace").strip().splitlines()
        if not line:
            return None
        return line[-1]

    def _on_process_error(self, _error: QProcess.ProcessError) -> None:
        if self.process and self.process.state() == QProcess.ProcessState.NotRunning:
            self._fail("无法启动外部工具。", self.process.errorString())

    def _fail(self, message: str, detail: str = "") -> None:
        self.password_label.setText("密码：操作失败")
        self._cleanup_workspace()
        self._set_progress_failed()
        self._set_running(False)
        QMessageBox.critical(self, "操作失败", f"{message}\n\n{detail}".strip())

    def _cleanup_workspace(self) -> None:
        """Remove this task's temporary files and the empty application root."""
        workspace_path = self.workspace_path
        workspace_root = self.workspace_root
        self.workspace_path = None
        self.workspace_root = None
        self.tool_archive_path = None
        self.hash_file = None
        self.output_file = None

        if workspace_path is not None:
            try:
                shutil.rmtree(workspace_path)
            except OSError:
                pass
        if workspace_root is not None:
            try:
                workspace_root.rmdir()
            except OSError:
                pass
        if workspace_path is not None:
            self.cache_path_label.setText("缓存文件夹：已自动清理")

    def _set_progress_idle(self) -> None:
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("等待任务开始")

    def _set_progress_busy(self, text: str) -> None:
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setFormat(text)

    def _set_progress_complete(self) -> None:
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat("任务完成")

    def _set_progress_failed(self) -> None:
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("任务失败")

    def _set_running(self, running: bool) -> None:
        self.select_button.setEnabled(not running)
        self.start_button.setEnabled(not running and self.archive_path is not None)
        self.copy_button.setEnabled(not running and self._read_password() is not None)

    def copy_password(self) -> None:
        password = self._read_password()
        if password is not None:
            QGuiApplication.clipboard().setText(password)
            QToolTip.showText(QCursor.pos(), "已复制密码", self.copy_button, self.copy_button.rect(), 2000)


def main() -> int:
    app = QApplication(sys.argv)
    window = ArchiveCracker()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
