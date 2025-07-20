@echo off
setlocal

set CC=gcc
set CFLAGS=-I modules -I src
set OUT=libEGL.dll

:: Paths
set DEF_FILE=definitions\libEGL.def
set LIB_FILE=definitions\libEGL.a

:: Step 1: Generate import library from .def
echo [*] Generating import library from .def...
dlltool -d %DEF_FILE% -l %LIB_FILE% -D libEGL.dll
if errorlevel 1 (
    echo [!] Error while generating import library from .def
    goto end
)

:: Step 2: Compile syscalls.asm if not already compiled
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

:: Step 3: Compile the final DLL
echo [*] Compiling libEGL.dll...
%CC% .\src\mainDLL.c .\asm\syscalls.obj .\modules\syscalls\syscalls.c %CFLAGS% -o %OUT% -Ldefinitions -lEGL -lws2_32 -shared

if errorlevel 1 (
    echo [!] Error while compiling libEGL.dll
    goto end
)

echo.
echo Build complete. Output: %OUT%

:end
endlocal
pause
