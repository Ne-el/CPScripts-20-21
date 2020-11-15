@echo off
setlocal enabledelayedexpansion
net session
if %errorlevel%==0 (
	echo Admin rights granted!
) else (
    echo Failure, no rights
	pause
    exit
)
cls

set pwd = cd


:menu
echo ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
echo  "__      __      ___.      __      __                                         "
echo "/  \    /  \ ____\_ |__   /  \    /  \___.__.___  __ ___________  ____   ______"
echo "\   \/\/   // __ \| __ \  \   \/\/   <   |  |\  \/ // __ \_  __ \/    \ /  ___/"
echo  "\        /\  ___/| \_\ \  \        / \___  | \   /\  ___/|  | \/   |  \\___ \ "
echo   "\__/\  /  \___  >___  /   \__/\  /  / ____|  \_/  \___  >__|  |___|  /____  >"
echo      "  \/       \/    \/         \/   \/                \/           \/     \/"
echo ~~~~~~~~~~~~~~~~~~~~~~~~~~~~Written By: Neel Mittal~~~~~~~~~~~~~~~~~~~~~~~~~~~~
echo ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
echo "1)Set user properties		                2)Create a user"
echo "3)Disable a user                               4)Change all passwords"
echo "5)Disable guest/admin		                6)Set password policy"
echo "7)Set lockout policy		                8)Enable Firewall"
echo "9)Search for media files	                10)Disable services"
echo "11)Turn on UAC			                12)remote Desktop Config"
echo "13)Enable auto update		                14)Security options"
echo "15)Audit the machine		                16)Edit groups"
echo "17)List All Users                              18)Print Admins"
echo "19)Install MB                                                     "
echo "69)Exit                                        70)Reboot"
echo ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
set /p answer=Please choose an option: 
		if "%answer%"=="1" goto :userProp
		if "%answer%"=="2" goto :createUser
		if "%answer%"=="3" goto :disUser
		if "%answer%"=="4" goto :passwd
		if "%answer%"=="5" goto :disGueAdm
		if "%answer%"=="6" goto :passwdPol
		if "%answer%"=="7" goto :lockout
		if "%answer%"=="8" goto :firewall
		if "%answer%"=="9" goto :badFiles
		if "%answer%"=="10" goto :services
		if "%answer%"=="11" goto :UAC
		if "%answer%"=="12" goto :remDesk
		if "%answer%"=="13" goto :autoUpdate
		if "%answer%"=="14" goto :secOpt
		if "%answer%"=="15" goto :audit
		if "%answer%"=="16" goto :group
        if "%answer%" == "17" goto :listUsers
        if "%answer%" == "18" goto :listAdmins
		if "%answer%" == "19" goto :MalwareBytesInstaller
		rem turn on screensaver
		rem password complexity
		if "%answer%"=="69" exit
		if "%answer%"=="70" shutdown /r
	pause

:userProp
	echo Setting password never expires
	wmic UserAccount set PasswordExpires=True
	wmic UserAccount set PasswordChangeable=True
	wmic UserAccount set PasswordRequired=True

	pause
    cls
	goto :menu

:passwd
	echo Changing all user passwords
	
	endlocal
	setlocal EnableExtensions
	for /F "tokens=2* delims==" %%G in ('
		wmic UserAccount where "status='ok'" get name >null
	') do for %%g in (%%~G) do (
		net user %%~g Cyb3rPatr!0t$
		)
	endlocal
	setlocal enabledelayedexpansion	
	pause
    cls
	goto :menu

:disUser
	cls
	net users
	set /p answer=Would you like to delete a user?[y/n]: 
	if /I "%answer%"=="y" (
		cls
		net users
		set /p DISABLE=What is the name of the user?:
			net user !DISABLE! /active:no
		echo !DISABLE! has been disabled
		pause
        cls
		goto :disUser
	)
	
	pause
	goto :menu
	
:createUser
	set /p answer=Would you like to create a user?[y/n]: 
	if /I "%answer%"=="y" (
		set /p NAME=What is the user you would like to create?:
		net user !NAME! /add
		echo !NAME! has been added
		pause 
		goto :createUser
	) 
	if /I "%answer%"=="n" (
		goto :menu
	)
cls
:disGueAdm
	rem Disables the guest account
	net user Guest | findstr Active | findstr Yes
	if %errorlevel%==0 (
		echo Guest account is already disabled.
	)
	if %errorlevel%==1 (
		net user guest Cyb3rPatr!0t$ /active:no
	)
	
	rem Disables the Admin account
	net user Administrator | findstr Active | findstr Yes
	if %errorlevel%==0 (
		echo Admin account is already disabled.
		pause
		goto :menu
	)
	if %errorlevel%==1 (
		net user administrator Cyb3rPatr!0t$ /active:no
		pause
		goto :menu
	)
	cls
:passwdPol
	rem Sets the password policy
	rem Set complexity requirments
	echo Setting pasword policies
	net accounts /minpwlen:8
	net accounts /maxpwage:60
	net accounts /minpwage:10
	net accounts /uniquepw:3
	
	pause
	goto :menu
	cls
:lockout
	rem Sets the lockout policy
	echo Setting the lockout policy
	net accounts /lockoutduration:30
	net accounts /lockoutthreshold:3
	net accounts /lockoutwindow:30

	pause
    cls
	goto :menu
	
:firewall
	rem Enables firewall
	netsh advfirewall set allprofiles state on
	netsh advfirewall reset
	
	pause
    cls
	goto :menu
	
:badFiles
    @echo off
color 0f
cls
echo Flashing Disk to .flashed Files to reference....
dir /b /s "C:\Program Files\" >> programfiles.flashed
dir /b /s "C:\Program Files (x86)\" >> programfiles.flashed
echo Program Files flashed
dir /b /s "C:\Users\" > users.flashed
dir /b /s "C:\Documents and Settings" >> users.flashed
echo User profiles flashed
dir /b /s "C:\" > c.flashed
echo C:\ Flashed
pause
echo Finding media files in C:\Users and/or C:\Documents and Settings...
findstr .mp3 users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.mp3 > media_audio
findstr .ac3 users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.ac3 >> media_audio
findstr .aac users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.aac >> media_audio
findstr .aiff users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.aiff >> media_audio
findstr .flac users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.flac >> media_audio
findstr .m4a users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.m4a >> media_audio
findstr .m4p users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.m4p >> media_audio
findstr .midi users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.midi >> media_audio
findstr .mp2 users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.mp2 >> media_audio
findstr .m3u users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.m3u >> media_audio
findstr .ogg users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.ogg >> media_audio
findstr .vqf users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.vqf >> media_audio
findstr .wav users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.wav >> media_audio
findstr .wma users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.wma >> media_video
findstr .mp4 users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.mp4 >> media_video
findstr .avi users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.avi >> media_video
findstr .mpeg4 users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ .mpeg4 >> media_video
::BREAKLINE
findstr .gif users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.gif >> media_pics
findstr .png users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.png >> media_pics
findstr .bmp users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.bmp >> media_pics
findstr .jpg users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ .jpg >> media_pics
findstr .jpeg users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ .jpeg >> media_pics
C:\WINDOWS\system32\notepad.exe media_video
C:\WINDOWS\system32\notepad.exe media_audio
C:\WINDOWS\system32\notepad.exe media_pics
echo Finding Hacktools now...
findstr "Cain" programfiles.flashed
if %errorlevel%==0 (
echo Cain detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "nmap" programfiles.flashed
if %errorlevel%==0 (
echo Nmap detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "keylogger" programfiles.flashed
if %errorlevel%==0 (
echo Potential keylogger detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "Armitage" programfiles.flashed
if %errorlevel%==0 (
echo Potential Armitage detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "Metasploit" programfiles.flashed
if %errorlevel%==0 (
echo Potential Metasploit framework detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "Shellter" programfiles.flashed
if %errorlevel%==0 (
echo Potential Shellter detected. Please take note, then press any key.
pause >NUL
)
cls
pause
	goto :menu

:services
	echo Disabling Services
	sc stop TapiSrv
	sc config TapiSrv start= disabled
	sc stop TlntSvr
	sc config TlntSvr start= disabled
	sc stop ftpsvc
	sc config ftpsvc start= disabled
	sc stop SNMP
	sc config SNMP start= disabled
	sc stop SessionEnv
	sc config SessionEnv start= disabled
	sc stop TermService
	sc config TermService start= disabled
	sc stop UmRdpService
	sc config UmRdpService start= disabled
	sc stop SharedAccess
	sc config SharedAccess start= disabled
	sc stop remoteRegistry 
	sc config remoteRegistry start= disabled
	sc stop SSDPSRV
	sc config SSDPSRV start= disabled
	sc stop W3SVC
	sc config W3SVC start= disabled
	sc stop SNMPTRAP
	sc config SNMPTRAP start= disabled
	sc stop remoteAccess
	sc config remoteAccess start= disabled
	sc stop RpcSs
	sc config RpcSs start= disabled
	sc stop HomeGroupProvider
	sc config HomeGroupProvider start= disabled
	sc stop HomeGroupListener
	sc config HomeGroupListener start= disabled
	
	pause
	goto :menu
:UAC

	rem Enable UAC
	echo Turning on UAC has to be done manually.
	
	pause
	goto :menu

:remDesk
	rem Ask for remote desktop
	set /p answer=Do you want remote desktop enabled?[y/n]
	if /I "%answer%"=="y" (
		reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
		echo RemoteDesktop has been enabled, reboot for this to take full effect.
	)
	if /I "%answer%"=="n" (
		reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
		echo RemoteDesktop has been disabled, reboot for this to take full effect.
	)
	
	pause
	goto :menu
	
:autoUpdate
	rem Turn on automatic updates
	echo Turning on automatic updates
	reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f

	pause
	goto :menu
	
:secOpt
	echo Changing security options now.

	rem Restrict CD ROM drive
	reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f

	rem Automatic Admin logon
	reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
	
	rem Logon message text
	set /p body=Please enter logon text: 
		reg ADD "HKLM\SYSTEM\microsoft\Windwos\CurrentVersion\Policies\System\legalnoticetext" /v LegalNoticeText /t REG_SZ /d "%body%"
	
	rem Logon message title bar
	set /p subject=Please enter the title of the message: 
		reg ADD "HKLM\SYSTEM\microsoft\Windwos\CurrentVersion\Policies\System\legalnoticecaption" /v LegalNoticeCaption /t REG_SZ /d "%subject%"
	
	rem Wipe page file from shutdown
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
	
	rem Disallow remote access to floppie disks
	reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f
	
	rem Prevent print driver installs 
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f
	
	rem Limit local account use of blank passwords to console
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
	
	rem Auditing access of Global System Objects
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v auditbaseobjects /t REG_DWORD /d 1 /f
	
	rem Auditing Backup and Restore
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v fullprivilegeauditing /t REG_DWORD /d 1 /f
	
	rem Do not display last user on logon
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
	
	rem UAC setting (Prompt on Secure Desktop)
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
	
	rem Enable Installer Detection
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
	
	rem Undock without logon
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v undockwithoutlogon /t REG_DWORD /d 0 /f
	
	rem Maximum Machine Password Age
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v MaximumPasswordAge /t REG_DWORD /d 15 /f
	
	rem Disable machine account password changes
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f
	
	rem Require Strong Session Key
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f
	
	rem Require Sign/Seal
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f
	
	rem Sign Channel
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f
	
	rem Seal Channel
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f
	
	rem Don't disable CTRL+ALT+DEL even though it serves no purpose
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f 
	
	rem Restrict Anonymous Enumeration #1
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f 
	
	rem Restrict Anonymous Enumeration #2
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f 
	
	rem Idle Time Limit - 45 mins
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v autodisconnect /t REG_DWORD /d 45 /f 
	
	rem Require Security Signature - Disabled pursuant to checklist
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v enablesecuritysignature /t REG_DWORD /d 0 /f 
	
	rem Enable Security Signature - Disabled pursuant to checklist
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v requiresecuritysignature /t REG_DWORD /d 0 /f 
	
	rem Disable Domain Credential Storage
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f 
	
	rem Don't Give Anons Everyone Permissions
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f 
	
	rem SMB Passwords unencrypted to third party
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
	
	rem Null Session Pipes Cleared
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
	
	rem remotely accessible registry paths cleared
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /v Machine /t REG_MULTI_SZ /d "" /f
	
	rem remotely accessible registry paths and sub-paths cleared
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths /v Machine /t REG_MULTI_SZ /d "" /f
	
	rem Restict anonymous access to named pipes and shares
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionShares /t REG_MULTI_SZ /d "" /f
	
	rem Allow to use Machine ID for NTLM
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v UseMachineId /t REG_DWORD /d 0 /f

	rem Enables DEP
	bcdedit.exe /set {current} nx AlwaysOn
	pause
	goto :menu
	
:audit
	echo Auditing the maching now
	auditpol /set /category:* /success:enable
	auditpol /set /category:* /failure:enable
	
	pause
	goto :menu

:group
	cls
	net localgroup
	set /p grp=What group would you like to check?:
	net localgroup !grp!
	set /p answer=Is there a user you would like to add or remove?[add/remove/back]:
	if "%answer%"=="add" (
		set /p userAdd=Please enter the user you would like to add: 
		net localgroup !grp! !userAdd! /add
		echo !userAdd! has been added to !grp!
	)
	if "%answer%"=="remove" (
		set /p userRem=Please enter the user you would like to remove:
		net localgroup !grp! !userRem! /delete
		echo !userRem! has been removed from !grp!
	)
	if "%answer%"=="back" (
		goto :group
	)

	set /p answer=Would you like to go check again?[y/n]
	if /I "%answer%"=="y" (
		goto :group
	)
	if /I "%answer%"=="n" (
		goto :menu
	)
:listUsers
dir /b C:\Users >> %USERPROFILE%\AppData\Local\Temp\listofusers.txt
notepad.exe %USERPROFILE%\AppData\Local\Temp\listofusers.txt
cls
goto :menu

:listAdmins
net localgroup administrators >> %USERPROFILE%\AppData\Local\Temp\listofadmins.txt
notepad.exe %USERPROFILE%\AppData\Local\Temp\listofadmins.txt
cls
goto :menu

:MalwareBytesInstaller

%pwd%\resources\mbar-1.10.3.1001.exe