@echo off
setlocal

set CC=gcc
set CFLAGS=-I modules -I src
set LDFLAGS=-lws2_32
set OUT=mainDLL.exe

:: Compile syscalls.asm only if not already compiled
if exist asm\syscalls.obj (
    echo [*] syscalls.obj already exists. Skipping NASM compilation.
) else (
    echo [*] Compiling syscalls.asm...
    nasm -f win64 asm\syscalls.asm -o asm\syscalls.obj
    if errorlevel 1 (
        echo [!] Error while compiling syscalls.asm
        goto end
    )
)

:: Compile DLL
echo [*] Compiling mainDLL.exe...
%CC% .\src\mainDLL.c .\asm\syscalls.obj .\modules\syscalls\syscalls.c %CFLAGS% -o %OUT% %LDFLAGS% -shared

if errorlevel 1 (
    echo [!] Error while compiling mainDLL.exe
    goto end
)

echo.
echo Build complete. Output: %OUT%

:end
endlocal
pause
