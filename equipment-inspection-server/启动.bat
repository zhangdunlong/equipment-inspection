@echo off
setlocal EnableExtensions

REM �л������ű�����Ŀ¼��ȷ������·����ȷ
cd /d "%~dp0"

set "PORT=8787"
set "DATA_DIR=%~dp0data"

REM ����ʹ���Դ���Я Node ����ʱ��runtime\node.exe��
set "NODE_EXE=%~dp0runtime\node.exe"
if exist "%NODE_EXE%" (
  set "RUN_EXE=%NODE_EXE%"
) else (
  where node >nul 2>nul
  if errorlevel 1 (
    echo ==============================================
    echo   δ�ҵ� Node.js ����ʱ��
    echo   ���ѡһ��
    echo     1^) �� node.exe �ŵ���Ŀ¼�� runtime\ �ļ�����
    echo     2^) �� https://nodejs.org/ ��װ Node.js ���ؿ����ű�
    echo ==============================================
    pause
    exit /b 1
  ) else (
    set "RUN_EXE=node"
  )
)

REM ȷ������Ŀ¼����
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"

REM ͨ�� VBS ���� node ���񣨴�����ȫ���أ���̨��Ĭ���У�
wscript "%~dp0_run_hidden.vbs" "%RUN_EXE%" "%~dp0server.js"

REM ��ѯ�ȴ��˿ڿ��ã���� 15 �룩
set /a tries=0
:WAIT_LOOP
  ping -n 1 -w 500 127.0.0.1 >nul
  powershell -NoProfile -Command "try { (New-Object Net.Sockets.TcpClient).Connect('127.0.0.1', %PORT%); exit 0 } catch { exit 1 }" >nul 2>nul
  if %errorlevel% == 0 goto PORT_READY
  set /a tries+=1
  if %tries% lss 15 goto WAIT_LOOP

:PORT_READY
REM �������
start "" "http://localhost:%PORT%/"

REM �����������Զ��رգ������ں�̨�޴�������
REM ����ֹͣ������˫��"ֹͣ.bat"
exit
