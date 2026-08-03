# HttpServer

一个轻量、可打包为 Windows EXE 的局域网文件共享服务。

## 功能

- 文件夹浏览、面包屑路径、文件名精确/模糊搜索
- 文件/文件夹下载，文件夹自动打包 ZIP
- TXT、LOG、MD、JSON、CSV、XML 等文本在线预览，PDF/图片/视频等由浏览器直接打开
- 管理员与普通用户双端：用户账号、浏览权限、下载权限、共享根目录、上传
- 所有路径均限制在共享根目录内，防止路径穿越

## 运行

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

浏览器打开 http://localhost:8000。默认账号：admin / admin123；普通用户：guest / guest123。

## 打包 EXE

双击 `build_exe.bat`，生成 `dist\HttpServer.exe`。将 EXE 放在希望存放共享目录的位置，首次运行会自动创建 `共享文件` 与 `data`。可通过 `PORT=8080` 修改端口。
