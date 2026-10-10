@echo off
setlocal

rem ============================================================
rem  自动定位 Visual Studio / MSVC / Windows SDK 的库路径并设置
rem  LIB 与 PATH，然后用 cargo 编译。无需手动指定 D 盘路径。
rem ============================================================

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

rem ---- 1. 查找 VS 安装路径，兼容任意盘符，例如 D 盘 ----
set "VSINSTALL="
if exist "%VSWHERE%" (
  for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -property installationPath`) do set "VSINSTALL=%%i"
)
if not defined VSINSTALL (
  echo [错误] 未找到 Visual Studio 安装，vswhere 未发现。
  echo         请确认已安装 VS2022 及使用 C++ 的桌面开发或 MSVC 生成工具。
  goto :end
)
echo [INFO] VS 安装路径: %VSINSTALL%

rem ---- 2. 取最新 MSVC 工具集版本 ----
set "MSVC_BASE=%VSINSTALL%\VC\Tools\MSVC"
set "MSVCVER="
for /f "usebackq delims=" %%i in (`dir /b /ad /o-n "%MSVC_BASE%" 2^>nul`) do (
  if not defined MSVCVER set "MSVCVER=%%i"
)
if not defined MSVCVER (
  echo [错误] 在 MSVC 目录下未找到工具集版本。
  goto :end
)
echo [INFO] MSVC 版本: %MSVCVER%

rem ---- 3. 取最新 Windows SDK 版本 ----
rem 说明：ProgramFiles x86 变量路径带括号，直接写进 for 命令串会让 cmd 误判为代码块
rem 括号而解析失败，因此先用 shortpath 子例程转成无括号的 8.3 短路径，再做 dir 扫描。
set "SDK_BASE=%ProgramFiles(x86)%\Windows Kits\10\Lib"
call :shortpath "%SDK_BASE%" SDK_BASE_SHORT
set "SDKVER="
for /f "delims=" %%i in ('dir /b /ad /o-n "%SDK_BASE_SHORT%" 2^>nul') do (
  if not defined SDKVER set "SDKVER=%%i"
)
if not defined SDKVER (
  echo [错误] 未找到 Windows SDK 版本目录，路径为: %SDK_BASE_SHORT%
  goto :end
)
echo [INFO] Windows SDK 版本: %SDKVER%

rem ---- 4. 组装 LIB 与 PATH，供链接器 link.exe 使用 ----
set "MSVCLIB=%MSVC_BASE%\%MSVCVER%\lib\x64"
set "MSVCLIB_ONECORE=%MSVC_BASE%\%MSVCVER%\lib\onecore\x64"
set "SDKUM=%SDK_BASE%\%SDKVER%\um\x64"
set "SDKUCRT=%SDK_BASE%\%SDKVER%\ucrt\x64"

set "LIB=%MSVCLIB%;%MSVCLIB_ONECORE%;%SDKUM%;%SDKUCRT%"
set "PATH=%MSVC_BASE%\%MSVCVER%\bin\Hostx64\x64;%PATH%"

echo [INFO] LIB = %LIB%
echo.

rem ---- 5. 编译 ----
echo [INFO] 开始编译，执行 cargo build --release ...
cargo build --release
if errorlevel 1 (
  echo [错误] 编译失败，未复制产物。
  goto :end
)

rem ---- 6. 复制产物到 dist 目录 ----
if not exist "dist" mkdir dist
copy /Y "target\release\file-io-mcp.exe" "dist\"
echo [INFO] 已复制 file-io-mcp.exe 到 dist\

:end
pause
goto :eof

rem ---- 子例程：取路径的 8.3 短路径，去掉空格与括号，避免 for 命令串解析失败 ----
:shortpath
set "%~2=%~s1"
goto :eof
