' _run_hidden.vbs - 以无窗口方式启动指定程序（后台静默运行）
' 用法: wscript _run_hidden.vbs "程序路径" "参数1" "参数2" ...
Set sh = CreateObject("WScript.Shell")
If WScript.Arguments.Count < 1 Then WScript.Quit 1
cmd = """" & WScript.Arguments(0) & """"
For i = 1 To WScript.Arguments.Count - 1
  cmd = cmd & " """ & WScript.Arguments(i) & """"
Next
sh.Run cmd, 0, False
