#/bin/bash

## Declare variables
UserName=$(whoami)
LogTime=$(date '+%Y-%d %H:%M;%S')
pwd=$(pwd)

# Check for Admin Perms
if [[ "$EUID" -ne 0 ]]
	then
	echo "Please run again as root using 'sudo ./linuxHardening.sh'"
	exit 1
fi

# Pause Statement
pause() {
	read -p "Press [Enter] to continue..." fakeEnter
}

# Exits Script
exit20() {
	exit 1
	clear
}


menu() {
	clear
	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	echo  "__      __      ___.      __      __                                         "
	echo "/  \    /  \ ____\_ |__   /  \    /  \___.__.___  __ ___________  ____   ______"
	echo "\   \/\/   // __ \| __ \  \   \/\/   <   |  |\  \/ // __ \_  __ \/    \ /  ___/"
	echo  "\        /\  ___/| \_\ \  \        / \___  | \   /\  ___/|  | \/   |  \\___ \ "
	echo   "\__/\  /  \___  >___  /   \__/\  /  / ____|  \_/  \___  >__|  |___|  /____  >"
	echo      "  \/       \/    \/         \/   \/                \/           \/     \/"
	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~Written By: Neel Mittal~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	echo "1) Backup the System			                 2) Update the System"
	echo "3) Enable Automatic Updates                                4) Manual Network Inspection"
	echo "5) Secure Root						 6) Search for Prohibited Files"
	echo "7) Create new users					 8) Change all Passwords"
	echo "9) Delete unauthorized users				 10) List Cronjobs"
	echo "11) Password Policy					 12) Set Lockout Policy"
	echo "13) Remove prohibited programs				 14) Configure SSH"
	echo "15) Edit sysctl.conf"
}

while true 
do
menu
done
