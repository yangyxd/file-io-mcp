@echo off
chcp 65001 >nul
cd /d "%~dp0"

set ADDR=0.0.0.0:3790

echo [file-io-mcp] 正在构建 release 版本...
call cargo build --release
if %ERRORLEVEL% neq 0 (
    echo [file-io-mcp] 构建失败，请检查错误信息
    pause
    exit /b 1
)

REM 寻找可执行文件：优先 target\release\，其次当前目录
set EXE_PATH=.\target\release\file-io-mcp.exe
if not exist "%EXE_PATH%" (
    if exist ".\file-io-mcp.exe" (
        set EXE_PATH=.\file-io-mcp.exe
    ) else (
        echo [file-io-mcp] 错误: 未找到 file-io-mcp.exe
        echo [file-io-mcp] 请先执行 build.bat 编译，或将可执行文件放在当前目录
        pause
        exit /b 1
    )
)

echo [file-io-mcp] HTTP 服务启动中，监听地址: %ADDR%
echo.
echo ==================== MCP 客户端配置 ====================
echo.
echo   {
echo     "mcpServers": {
echo       "file-io": {
echo         "url": "http://%ADDR%/mcp"
echo       }
echo     }
echo   }
echo.
echo ========================================================
echo.
"%EXE_PATH%" --http --addr %ADDR%
pause