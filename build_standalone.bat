@echo off
REM ==============================================================================
REM سكربت تحزيم محرك فحص تطبيقات أندرويد (AdbLite APK Inspector) كملف تنفيذي مستقل
REM ينشئ ملف apk_inspector.exe في مجلد tools\analyzer\bin
REM ==============================================================================

chcp 65001 > nul
echo -------------------------------------------------------------
echo جاري إعداد وتجميع محرك الفحص كملف تنفيذي مستقل (Standalone Exe)...
echo -------------------------------------------------------------

set SCRIPT_DIR=%~dp0
set OUTPUT_BIN=%SCRIPT_DIR%bin

if not exist "%OUTPUT_BIN%" mkdir "%OUTPUT_BIN%"

echo التحقق من وجود PyInstaller...
pyinstaller --version > nul 2>&1
if %errorlevel% neq 0 (
    echo [تنبيه] PyInstaller غير مثبت. يمكنك تثبيته بالأمر: pip install pyinstaller
    pause
    exit /b 1
)

echo جاري بناء الملف التنفيذي...
pyinstaller --noconfirm --onefile --console ^
    --name "apk_inspector" ^
    --distpath "%OUTPUT_BIN%" ^
    --workpath "%SCRIPT_DIR%build_tmp" ^
    --specpath "%SCRIPT_DIR%build_tmp" ^
    --add-data "%SCRIPT_DIR%data;data" ^
    "%SCRIPT_DIR%apk_inspector.py"

if %errorlevel% equ 0 (
    echo -------------------------------------------------------------
    echo تم البناء بنجاح! الملف التنفيذي موجود في:
    echo %OUTPUT_BIN%\apk_inspector.exe
    echo -------------------------------------------------------------
    rmdir /s /q "%SCRIPT_DIR%build_tmp"
) else (
    echo [خطأ] حدث خطأ أثناء عملية البناء والتجميع.
)

pause
