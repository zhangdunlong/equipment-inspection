@echo off
setlocal EnableExtensions
cd /d "%~dp0"

echo ����ֹͣ�豸���ϵͳ���񣨽���ֹռ�� 8787 �˿ڵı�������̣�...

REM ͨ���˿� 8787 ��ȷ��λ��ֻ������������̣�������ɱ���� node ����
powershell -NoProfile -Command "$p=(Get-NetTCPConnection -LocalPort 8787 -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique); if($p){Stop-Process -Id $p -Force; Write-Host ('killed PID '+$p)} else {Write-Host 'no listener on 8787'}"

REM ����У�飺���˿���δ�ͷţ��ٰ�ӳ����ǿ�ƽ��������ٴ�����
ping -n 2 127.0.0.1 >nul
powershell -NoProfile -Command "try { (New-Object Net.Sockets.TcpClient).Connect('127.0.0.1', 8787); exit 0 } catch { exit 1 }" >nul 2>nul
if %errorlevel% == 0 (
  echo �˿��Ա�ռ�ã�ǿ�ƽ��� node.exe...
  taskkill /f /im node.exe >nul 2>nul
  ping -n 2 127.0.0.1 >nul
)

echo ������ֹͣ��
ping -n 3 127.0.0.1 >nul
exit
