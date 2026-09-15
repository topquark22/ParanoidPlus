Set shell = CreateObject("WScript.Shell")
shell.Run "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy RemoteSigned -File """ & WScript.Arguments(0) & """", 0, False
