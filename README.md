# 加密压缩包密码恢复工具 v2.0
*图形用户界面化操作 hashcat 对加密 RAR、ZIP、7Z 文件进行密码恢复。*

*A GUI for operating hashcat to recover passwords from encrypted RAR, ZIP, and 7Z archives.*

## 仅供学习使用，若用于违法使用，后果与作者无关
<img width="1144" height="857" alt="image" src="https://github.com/user-attachments/assets/2f49b57b-9e75-4970-8986-75c99d2c9448" />


## 支持 RAR、ZIP、7Z

可以近乎吃满显卡性能对加密 RAR、ZIP、7Z 文件快速恢复密码，实测4位密码加密在RTX3060 6G Loptop解密时长在50s左右。

It can nearly fully utilize the graphics card's performance for rapid password recovery from encrypted archives. In practical tests, a 4-digit password encrypted file took about 50 seconds to recover on an RTX 3060 6G Laptop.


## 运行方式

需要 Python 3.10 或更高版本：

```powershell
python -m pip install -r requirements.txt
python main.py
```

界面使用 PySide6，外部密码找回命令通过 Qt 的 `QProcess` 异步运行，因此找回过程中窗口仍保持响应。

找回阶段会显示 hashcat 实际报告的候选进度、总速度和预计剩余时间。哈希、结果文件与 hashcat 恢复文件均保存在本次任务的缓存目录中，并会在任务结束后自动清理。

可多选暴力字符集（数字、小写字母、大写字母、特殊字符），并分别设置最小和最大密码长度。程序使用 hashcat 的递增模式，从最小长度依次尝试至最大长度；默认范围为 1～4 位。缩小字符集能显著降低搜索空间。

## 依赖 dependency
  ### 1.9.0-jumbo-1
官网地址：https://www.openwall.com/john/

利用其获得加密 RAR、ZIP 文件的 hash 值。

Utilize it to obtain the hash value of the encrypted RAR file.

  ### hashcat 7.1.2（
官网地址：https://hashcat.net/hashcat/

利用所获hash值进行解密核心。解密速度取决于电脑显卡性能。

Use the obtained hash value for the decryption core. The decryption speed depends on the computer's graphics card performance.

  ### 7z2hashcat 2.0
下载袋子：https://github.com/philsmd/7z2hashcat

`7z2hashcat64-2.0/7z2hashcat64-2.0.exe` 用于提取 7Z 的 hash，随后由 hashcat 的 `-m 11600` 模式恢复密码。该方式不需要安装 Perl。

## 使用的 hashcat 模式

- RAR3：`12500`；RAR5：`13000`
- ZIP：`13600`（WinZip AES）或 `17200`（PKZIP）
- 7Z：`11600`


