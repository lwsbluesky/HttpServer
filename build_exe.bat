@echo off
python -m pip install -r requirements.txt
pyinstaller --noconfirm --clean --onefile --windowed --name HttpServer --icon favorite-app.ico --version-file file_version_info.txt --add-data "static;static" app.py
echo EXE 已生成到 dist\HttpServer.exe
pause
