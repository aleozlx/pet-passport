@echo off
rem Rebuilds the delay-load fixtures from delayload.c with the MSVC toolchain.
rem Run from a plain cmd prompt; it locates vcvarsall.bat through vswhere.
rem The outputs are committed so that "go test" needs no C toolchain. They were
rem built with MSVC 14.44.35207 (Visual Studio 2022 Build Tools); /BREPRO makes
rem a rebuild with that toolchain byte-identical.
setlocal
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -property installationPath`) do set "VS=%%i"
if not defined VS (echo vswhere found no Visual Studio installation & exit /b 1)
pushd "%~dp0"
call :build x64 delayload-x64.exe || goto :fail
call :build x86 delayload-x86.exe || goto :fail
popd
exit /b 0

:build
setlocal
call "%VS%\VC\Auxiliary\Build\vcvarsall.bat" %1 >nul || exit /b 1
cl /nologo /O1 /GS- /W4 /wd4201 delayload.c /Fe:%2 /link /NODEFAULTLIB /ENTRY:start /SUBSYSTEM:WINDOWS /DELAYLOAD:user32.dll kernel32.lib user32.lib /BREPRO /DEBUG:NONE || exit /b 1
del /q delayload.obj 2>nul
endlocal & exit /b 0

:fail
popd
exit /b 1
