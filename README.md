# 加密压缩包密码恢复工具 v2.1.1
*图形用户界面化操作 hashcat 对加密 RAR、ZIP、7Z 文件进行密码恢复。*

*A GUI for operating hashcat to recover passwords from encrypted RAR, ZIP, and 7Z archives.*

## 仅供学习使用，若用于违法使用，后果与作者无关
<img width="1144" height="857" alt="image" src="https://github.com/user-attachments/assets/2f49b57b-9e75-4970-8986-75c99d2c9448" />


## 支持格式

使用随附 hashcat 7.1.2 支持的 RAR3 类型 0、RAR3 类型 1（方法 30～35）、RAR5、ZIP 和 7z。7z 支持 Copy、LZMA、LZMA2、Deflate；PPMd、BZip2、截断数据及其他过滤器组合会在开始搜索前说明不受支持。

It can nearly fully utilize the graphics card's performance for rapid password recovery from encrypted archives. In practical tests, a 4-digit password encrypted file took about 50 seconds to recover on an RTX 3060 6G Laptop.


## 运行方式

需要 Python 3.10 或更高版本：

```powershell
python -m pip install -r requirements.txt
python main.py
```

界面使用 PySide6，外部密码找回命令通过 Qt 的 `QProcess` 异步运行，因此找回过程中窗口仍保持响应。

找回阶段会显示 hashcat 实际报告的候选进度、总速度和预计剩余时间。哈希、结果文件与 hashcat 恢复文件均保存在本次任务的缓存目录中，并会在任务结束后自动清理。

ZIP 模式会根据 `zip2john` 的记录类型和压缩方式自动选择 hashcat 模式：单个 Deflate / Store 文件分别使用 17200 / 17210；多个全 Deflate 文件使用 17220，包含 Store 的多文件使用 17225；WinZip AES 使用 13600。只有校验和的旧式 ZIP 哈希使用 17230，并在 hashcat 完成搜索后逐个读取原 ZIP 中的加密成员验证候选密码。该模式会继续搜索整个所选范围，避免把校验和碰撞误报为密码。

缓存位置默认是程序目录下的 `tmp`，可在界面中选择其他目录或恢复默认。每项任务会在所选目录下建立独立子目录；任务结束时只清理该子目录，不会删除所选目录或其中其他文件。若缓存路径含中文且 Windows 未提供 8.3 短路径，旧版外部工具无法访问时会提示改选仅含英文字符的目录。

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

- RAR3 类型 0：`12500`；RAR3 类型 1 方法 30：`23700`，方法 31～35：`23800`；RAR5：`13000`
- ZIP：WinZip AES `13600`；单个 PKZIP Deflate / Store `17200` / `17210`；多文件全 Deflate `17220`；含 Store 的多文件 `17225`；校验和模式 `17230`
- 7z Copy、LZMA、LZMA2、Deflate：`11600`

随附 hashcat 7.1.2 的 `m17220_a3-pure.cl` 引用了缺失的 `inc_checksum_crc32.cl` 时，程序会将该任务改用兼容模式 `17225` 并在界面提示。校验和模式 `17230` 会在完整搜索后逐个验证候选密码；只有能完整读取原 ZIP 所有加密成员并通过 CRC 校验的候选才会显示为密码。


