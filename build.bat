@echo off
rem Сборка SecureDNS в portable exe (требуется: pip install pyinstaller)
pyinstaller --noconfirm --clean --onefile --windowed --uac-admin --name SecureDNS --icon icon.ico main.py
echo Готово: dist\SecureDNS.exe
pause
