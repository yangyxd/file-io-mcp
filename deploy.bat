@echo off
chcp 65001 >nul
cd /d "%~dp0"

set EXE_NAME=file-io-mcp.exe
set DST_DIR=F:\Back\mcp

REM 查找发布版可执行文件：优先 target\release\，其次 file-io-mcp-exe\
set SRC=%~dp0target\release\%EXE_NAME%
if exist "%SRC%" goto :found
set SRC=%~dp0file-io-mcp-exe\%EXE_NAME%
if exist "%SRC%" goto :found

echo [deploy] 错误: 未找到 %EXE_NAME%
echo [deploy] 请先执行 build.bat 编译
pause
exit /b 1

:found
echo [deploy] 源文件: %SRC%
echo [deploy] 目标目录: %DST_DIR%

echo [deploy] 正在结束所有 %EXE_NAME% 进程...
taskkill /f /im "%EXE_NAME%" >nul 2>&1
if errorlevel 1 (
    echo [deploy] 没有正在运行的 %EXE_NAME% 进程
) else (
    echo [deploy] 已结束相关进程
)

REM 等待文件句柄释放
timeout /t 1 /nobreak >nul

if not exist "%DST_DIR%" (
    echo [deploy] 目标目录不存在，正在创建...
    mkdir "%DST_DIR%"
    if errorlevel 1 (
        echo [deploy] 错误: 无法创建目标目录 %DST_DIR%
        pause
        exit /b 1
    )
)

echo [deploy] 正在复制...
copy /y "%SRC%" "%DST_DIR%\%EXE_NAME%" >nul
if errorlevel 1 (
    echo [deploy] 错误: 复制失败
    pause
    exit /b 1
)

echo [deploy] 完成: %DST_DIR%\%EXE_NAME%
pause
