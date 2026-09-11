@echo off
setlocal EnableExtensions

REM 切换到本脚本所在目录，确保后续路径正确
cd /d "%~dp0"

set "PORT=8787"
set "DATA_DIR=%~dp0data"

REM 优先使用自带便携 Node 运行时（runtime\node.exe）
set "NODE_EXE=%~dp0runtime\node.exe"
if exist "%NODE_EXE%" (
  set "RUN_EXE=%NODE_EXE%"
) else (
  where node >nul 2>nul
  if errorlevel 1 (
    echo ==============================================
    echo   未找到 Node.js 运行时！
    echo   请二选一：
    echo     1^) 把 node.exe 放到本目录的 runtime\ 文件夹下
    echo     2^) 到 https://nodejs.org/ 安装 Node.js 后重开本脚本
    echo ==============================================
    pause
    exit /b 1
  ) else (
    set "RUN_EXE=node"
  )
)

REM 确保数据目录存在
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"

REM 通过 VBS 启动 node 服务（窗口完全隐藏，后台静默运行）
wscript "%~dp0_run_hidden.vbs" "%RUN_EXE%" "%~dp0server.js"

REM 轮询等待端口可用（最多 15 秒）
set /a tries=0
:WAIT_LOOP
  ping -n 1 -w 500 127.0.0.1 >nul
  powershell -NoProfile -Command "try { (New-Object Net.Sockets.TcpClient).Connect('127.0.0.1', %PORT%); exit 0 } catch { exit 1 }" >nul 2>nul
  if %errorlevel% == 0 goto PORT_READY
  set /a tries+=1
  if %tries% lss 15 goto WAIT_LOOP

:PORT_READY
REM 打开浏览器
start "" "http://localhost:%PORT%/"

REM 启动器窗口自动关闭，服务在后台无窗口运行
REM 如需停止服务，请双击"停止.bat"
exit
