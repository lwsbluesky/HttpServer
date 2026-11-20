@echo off
python -m pip install -r requirements.txt
if errorlevel 1 exit /b 1
python -m PyInstaller --noconfirm --clean --onefile --windowed --name HttpServer --icon favorite-app.ico --version-file file_version_info.txt --add-data "static;static" app.py
if errorlevel 1 exit /b 1
echo EXE created: dist\HttpServer.exe
pause
