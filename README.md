# HttpServer V1.4.0.0

面向家庭和小团队的 Windows 局域网文件共享工具。浏览器访问，无需安装客户端。

## 本版本功能

- 多共享目录浏览、文件名搜索（支持 * 和 ?）、文本和 PDF 预览。
- 单文件下载、目录 ZIP 下载、压缩准备状态和错误提示。
- PBKDF2-SHA256 密码存储、服务端退出和管理员强制下线。
- 按共享目录配置浏览/下载/上传/修改/删除权限，所有文件操作由服务端校验 ACL。
- 独立且有并发上限的浏览、搜索、预览、压缩线程池；文本预览截断、压缩大小/数量/时间限制。
- 健康检查、管理仪表盘、审计、日志轮转和诊断 ZIP 导出。
- 路径越界、Windows 设备名、备用数据流、符号链接/Junction 边界检查。
- 单/多文件与文件夹上传，进度展示、冲突处理、20 GB 单文件上限和临时文件提交。
- 新建目录、重命名、批量移动/复制/删除、30 天回收站与恢复。
- 服务端分页和按名称/大小/修改时间/类型排序。

Office 预览和临时分享链接尚未提供；不要将“隐藏”当作目录访问权限。

## 运行

建议 Windows 10/11 x64、Python 3.10 或更高版本。

~~~powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
~~~

本机访问 http://localhost:8000；同一局域网使用服务主机的 IP 地址和端口。
初始账号为 admin / admin123、guest / guest123。新账号首次登录不强制改密，建议登录后尽快在「修改密码」中设置至少 12 字符的新密码。
管理员可删除 guest；重启不会重新创建已删除或改名的默认账号。

环境变量：

- PORT：监听端口，默认 8000。
- HTTPSERVER_DATA_DIR：数据库、日志、临时文件目录，默认 EXE/源码所在目录的 data。
- HTTPSERVER_NO_DIALOG=1：EXE 启动时不弹出提示（便于自动测试/后台运行）。

## 升级与回滚

停止旧进程，备份 data，然后替换 EXE。共享原文件不会被移动。
第一次启动会自动迁移旧数据库，保留用户/共享目录，将明文密码改为 PBKDF2 哈希，并要求用户改密。
迁移前备份保存在 data/pre-v1.3-backup.db；该备份含旧凭据，只可在本机安全保存，不能上传 GitHub 或共享。
V1.3 的接口与登录格式有变化，升级后需要重新登录。旧版程序不能直接读取哈希后的密码；
若回滚，必须停止服务并恢复迁移前完整 data 备份。回滚会丢失升级后的账号/配置改动。
数据库采用 WAL，备份时应停止进程或使用 SQLite backup API，不能只复制正在写入的 .db 文件。

## 默认边界

- 会话：空闲 8 小时、绝对 7 天；最多 4096 个，进程重启全部失效。
- 登录失败：同一 IP+用户名在 5 分钟内失败 5 次后锁定 10 分钟。
- 下载/预览票据：60 秒、限目标路径和用途、一次使用，退出/强制下线后失效。
- 压缩：最多 2 个并行任务、8 个活动临时 ZIP，每任务最大 2 GiB / 10 万文件 / 120 秒。
- 浏览/搜索/预览分别最多 4/2/2 个并发；繁忙立即返回 503 和 Retry-After，不无限排队。
- 文本预览最多读取前 2 MiB；搜索/列表单目录最多 10 万条，搜索缓存总量最多 10 万条。
- API JSON 请求上限 64 KiB，读取超时 10 秒；流式上传接口单文件上限 20 GB。
- 审计保留 7 天且定期限制在 5 万行；文本日志按 5 MiB 轮转，最多 20 个历史文件。
- 未被活动请求/票据占用的过期临时文件定期回收；完成、失败、中断下载均尝试即时删除。
- 隐藏项仅影响列表/搜索展示；知道路径的授权用户仍可访问，目录 ACL 决定真正权限。

## 测试

~~~powershell
python -m pip install -r requirements-dev.txt
python -m pytest tests/test_v13.py tests/test_v14.py -q --junitxml=build/v14-api-tests.xml
python tests/live_verify.py --seconds 600
python tests/live_verify.py --seconds 60 --exe dist/v1.3/HttpServer.exe --skip-browser
~~~

浏览器测试使用安装在本机的 Microsoft Edge。所有测试使用隔离临时数据库，不修改正式 data。
72 小时真实长稳命令：

~~~powershell
python tests/live_verify.py --seconds 259200 --skip-browser
~~~

运行中须保持主机开机、不休眠。逻辑时间模拟和短时负载不能替代这项验收。
测试内容和当前结果见 docs/V1.4测试报告.md；测试集同时包含 V1.3 安全与稳定性回归。

## 构建 EXE

双击 build_exe.bat，或在虚拟环境中运行：

~~~powershell
python -m PyInstaller --noconfirm --clean --onefile --windowed --name HttpServer --icon favorite-app.ico --version-file file_version_info.txt --add-data "static;static" app.py
~~~

产物为 dist/HttpServer.exe。只分发 EXE，不包含本机 data、日志和数据库备份。
