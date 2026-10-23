@echo off
python -m pip install -q -e .[test] pyinstaller || exit /b 1
python -m pytest tests -q || exit /b 1
python -m PyInstaller revkit.spec --noconfirm --distpath dist --workpath build || exit /b 1
echo Built dist\revkit.exe
