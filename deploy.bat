@echo off
chcp 65001 >nul
cd /d "%~dp0"

set EXE_NAME=file-io-mcp.exe
set BACK_DIR=F:\Back\mcp
set DIST_DIR=%~dp0dist

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

echo [deploy] 正在结束所有 %EXE_NAME% 进程...
taskkill /f /im "%EXE_NAME%" >nul 2>&1
if errorlevel 1 (
    echo [deploy] 没有正在运行的 %EXE_NAME% 进程
) else (
    echo [deploy] 已结束相关进程
)

REM 等待文件句柄释放
timeout /t 1 /nobreak >nul

set FAILED=0

REM 目标 1：项目内 dist 目录（不存在则自动创建）
if not exist "%DIST_DIR%" mkdir "%DIST_DIR%"
call :copyto "%DIST_DIR%"

REM 目标 2：备份目录（目录不存在则跳过，不复制）
if not exist "%BACK_DIR%" (
    echo [deploy] 跳过: 目录 %BACK_DIR% 不存在，不复制
) else (
    call :copyto "%BACK_DIR%"
)

if "%FAILED%"=="1" (
    echo [deploy] 存在复制失败的目标
    pause
    exit /b 1
)

echo [deploy] 全部完成
pause
exit /b 0

:copyto
echo [deploy] 正在复制到 %~1 ...
copy /y "%SRC%" "%~1\%EXE_NAME%" >nul
if errorlevel 1 (
    echo [deploy] 错误: 复制到 %~1 失败
    set FAILED=1
) else (
    echo [deploy]   完成: %~1\%EXE_NAME%
)
exit /b 0
