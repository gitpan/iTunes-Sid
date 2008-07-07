@echo off
rem get_hwdata.cmd, run as "get_hwdata.cmd" from a WINDOWS prompt
    
REG query "HKLM\HARDWARE\DESCRIPTION\System" /v SystemBiosVersion  > c:\regdata

REG query "HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0" /v ProcessorNameString  >> c:\regdata

REG query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion" /v ProductId   >> c:\regdata

REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductId   >> c:\regdata
    
DIR C:\Windows\PROTOCOL.INI  >> c:\regdata

