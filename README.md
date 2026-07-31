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
功能介绍：
python app.py或者直接运行exe包。
<img width="1113" height="626" alt="ce85de9ebd154ae78f0cbec7961528b4" src="https://github.com/user-attachments/assets/e2dc9451-b37f-45a5-9010-e319172a6a5d" />
http http://localhost:8000访问,用admin进入登录。
<img width="1105" height="800" alt="FF70E7C1-E774-4700-A6E9-1A5A457FFDBF" src="https://github.com/user-attachments/assets/a9e1f2fa-d80a-4b44-ada7-874b382b2ce1" />
a)管理端可以指定共享的文件夹，可同时指定多个共享文件夹，也可以创建用户，修改用户密码和相关权限。
<img width="1278" height="944" alt="image" src="https://github.com/user-attachments/assets/215fb639-9e8a-4b7e-b50b-32a721c34bca" />
b)管理端可对文件夹，文件进行隐藏操作，隐藏后普通用户则无法看到。
<img width="1278" height="944" alt="0A57BD6A-CFFC-4f13-AF5A-B8C349638210" src="https://github.com/user-attachments/assets/1159a1a6-f0a4-4f2f-b4b8-0e03cb172fd6" />

c)用户端可以对共享服务器的文件或文件夹进行下载。
<img width="1178" height="948" alt="ee221d1d05461791c63317fcedde2693" src="https://github.com/user-attachments/assets/a41e433a-c8ae-436b-b612-101f7e6d98d6" />



