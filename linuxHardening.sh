#/bin/bash

#Get rid of aliases
unalias -a 
echo "unalias -a" >> ~/.bashrc
echo "unalias -a" >> /root/.bashrc
PWD=$(pwd)
if [ ! -d $PWD/referenceFiles ]; then
	echo "cd to location of script"
	exit
fi

# Check for Root Perms
if [[ $EUID -ne 0 ]]
	then
	echo "Please run again as root using 'sudo ./linuxmain.sh'"
	exit 1
fi
#Function List
    #manualEdit
    #updateSystem
    #networkProtection
    #rootpasswd
    #rootkitInstall
    #firewallNOW
    #noRDP
    #repoCheck
    #cronProtection
    #zeroUidProtection
    #systemctlProtection
    #FileFinderDeleter
    #fileSecurityProtection
    #hackerToolDeleter
    #passwordAuditSecurity
allFunctions()
{
    clear

    manualEdit
    updateSystem >> $PWD/Logs/Updates.log
    networkProtection
    rootpasswd
    rootkitInstall
    firewallNOW
    noRDP
    repoCheck
    cronProtection
    zeroUidProtection
    systemctlProtection  >> $PWD/Logs/SysCtl.log
    FileFinderDeleter  >> $PWD/Logs/FileFinderDeleter.log
    fileSecurityProtection
    hackerToolDeleter >> $PWD/Logs/haktool.log
    passwordAuditSecurity  >> $PWD/Logs/passAudit.log
}


cont()
{
    printf "\033[1;31mI have finished this task. Continue to next Task? (Y/N)\033[0m\n"
	read contyn
	if [ "$contyn" = "N" ] || [ "$contyn" = "n" ]; then
		printf "\033[1;31mAborted\033[0m\n"
		exit
	fi
	clear
}


manualEdit()
{
    cat /etc/group | grep sudo >> $PWD/Logs/Admins.log
    pause
    cat /etc/apt/sources.list >> $PWD/Logs/sources.log
    pause
    cont
}


networkProtection()
{
    printf "\033[1;31mSome manual network inspection...\033[0m\n"
	#--------- Manual Network Inspection ----------------
	lsof -i -n -P >> $PWD/Logs/Ports.log
	netstat -tulpn >> $PWD/Logs/Ports.log
	cont
}


updateSystem()
{
    # Updates
    apt-get update -y
	apt-get dist-upgrade -y
	apt-get install -f -y
	apt-get autoremove -y
	apt-get autoclean -y
	apt-get check
    ##Set daily updates
		sed -i -e 's/APT::Periodic::Update-Package-Lists.*\+/APT::Periodic::Update-Package-Lists "1";/' /etc/apt/apt.conf.d/10periodic
		sed -i -e 's/APT::Periodic::Download-Upgradeable-Packages.*\+/APT::Periodic::Download-Upgradeable-Packages "0";/' /etc/apt/apt.conf.d/10periodic
    ##Sets default broswer
		sed -i 's/x-scheme-handler\/http=.*/x-scheme-handler\/http=firefox.desktop/g' /home/$UserName/.local/share/applications/mimeapps.list
    ##Set "install security updates"
		cat /etc/apt/sources.list | grep "deb http://security.ubuntu.com/ubuntu/ trusty-security universe main multiverse restricted"
		if [ $? -eq 1 ]
		then
			echo "deb http://security.ubuntu.com/ubuntu/ trusty-security universe main multiverse restricted" >> /etc/apt/sources.list
		fi

		echo "###Automatic updates###"
		cat /etc/apt/apt.conf.d/10periodic
		echo ""
		echo "###Important Security Updates###"
		cat /etc/apt/sources.list

	cont
}


rootpasswd() 
{
    #All passwords: CyberPatri0t1!
    echo "Editing Root Password.."
    echo -e "CyberPatri0t1!" | passwd root
    echo "Changed Root Password to CyberPatri0t1!\nChange Other Passwords too Please"
    # Lock Out Root User
    sudo passwd -l root
    cont
}


rootkitInstall() 
{
    # Install rootkits, anti-malware, etc..
    sudo apt-get install chkrootkit -y
    sudo apt-get install ufw  -y
    sudo apt-get install clamav  -y
    sudo apt-get install rkhunter  -y
    sudo apt-get install selinux -y 
    sudo apt-get install tree -y
    sudo apt-get install auditd -y 
    sudo apt-get install bum -y 
    sudo apt-get install htop -y
    sudo apt-get install symlinks -y
    sudo apt-get install clamav-freshclam -y
	sudo apt-get install clamav-daemon -y
    clear
    # Use those rootkits, anti-malware, etc...
    echo -e "Starting CHKROOTKIT scan"
    sudo chkrootkit -q >> $PWD/Logs/Rootkits.log
    cont
    echo -e "Starting FRESHCLAM scan"
    sudo freshclam >> $PWD/Logs/Rootkits.log
    cont
    echo -e "Starting Clamscan scan"
    sudo clamscan -r --bell -i /home/ >> $PWD/Logs/Rootkits.log
    cont
    echo -e "Starting RKHUNTER scan"
    sudo rkhunter --update >> $PWD/Logs/Rootkits.log
    rkhunter --propupd >> $PWD/Logs/Rootkits.log
    rkhunter -c --enable all --disable none >> $PWD/Logs/Rootkits.log
    cont
    echo -e "Starting CLAMAV scan"
    systemctl stop clamav-freshclam >> $PWD/Logs/Rootkits.log
	freshclam --stdout >> $PWD/Logs/Rootkits.log
	systemctl start clamav-freshclam >> $PWD/Logs/Rootkits.log
	clamscan -r -i --stdout --exclude-dir="^/sys" / >> $PWD/Logs/Rootkits.log
	cont
    # Run Lynis AV for audit config
    echo -e "Running Lynis Scan" >> $PWD/Logs/Rootkits.log
    wget https://downloads.cisofy.com/lynis/lynis-2.6.9.tar.gz -O lynis.tar.gz >> $PWD/Logs/Rootkits.log
    sudo tar -xzf ./lynis.tar.gz --directory /usr/share/ >> $PWD/Logs/Rootkits.log
    cd /usr/share/lynis >> $PWD/Logs/Rootkits.log
    /usr/share/lynis/lynis update info >> $PWD/Logs/Rootkits.log
    /usr/share/lynis/lynis audit system >> $PWD/Logs/Rootkits.log

    cont
}


firewallNOW()
{
    sudo ufw enable
    sudo ufw default allow outgoing
    sudo ufw default deny incoming
    ufw logging on
    ufw app pause
    list
    echo "Logs will be available at '/var/logs/ufw'"
    ufw allow 22
    ufw allow 80
    ufw allow 443
    ufw deny 23
    ufw deny 2049
    ufw deny 515
    ufw deny 111
    ufw deny 7100
    ufw status >> $PWD/Logs/Firewall.log
    pause
    clear
    cont
}


noRDP()
{
    gconftool-2 -s -t bool /desktop/gnome/remote_access/enabled false
    cont
}


repoCheck()
{
	read -p "Please check the repo for any issues [Press any key to continue...]" -n1 -s
	nano /etc/apt/sources.list
	gpg /etc/apt/trusted.gpg > /tmp/trustedGPG
	printf "\033[1;31mPlease check /tmp/trustedGPG for trusted GPG keys\033[0m\n"
	cont
}


cronProtection()
{
    printf "\033[1;31mChanging cron to only allow root access...\033[0m\n"
	#--------- Allow Only Root Cron ----------------
	#reset crontab
	crontab -r
	cd /etc/
	/bin/rm -f cron.deny at.deny
	echo root >cron.allow
	echo root >at.allow
	/bin/chown root:root cron.allow at.allow
	/bin/chmod 644 cron.allow at.allow
	cont
}


zeroUidProtection()
{
	printf "\033[1;31mChecking for 0 UID users...\033[0m\n"
	#--------- Check and Change UID's of 0 not Owned by Root ----------------
	touch /zerouidusers
	touch /uidusers

	cut -d: -f1,3 /etc/passwd | egrep ':0$' | cut -d: -f1 | grep -v root > /zerouidusers

	if [ -s /zerouidusers ]
	then
		echo "There are Zero UID Users! I'm fixing it now!"

		while IFS='' read -r line || [[ -n "$line" ]]; do
			thing=1
			while true; do
				rand=$(( ( RANDOM % 999 ) + 1000))
				cut -d: -f1,3 /etc/passwd | egrep ":$rand$" | cut -d: -f1 > /uidusers
				if [ -s /uidusers ]
				then
					echo "Couldn't find unused UID. Trying Again... "
				else
					break
				fi
			done
			usermod -u $rand -g $rand -o $line
			touch /tmp/oldstring
			old=$(grep "$line" /etc/passwd)
			echo $old > /tmp/oldstring
			sed -i "s~0:0~$rand:$rand~" /tmp/oldstring
			new=$(cat /tmp/oldstring)
			sed -i "s~$old~$new~" /etc/passwd
			echo "ZeroUID User: $line"
			echo "Assigned UID: $rand"
		done < "/zerouidusers"
		update-passwd
		cut -d: -f1,3 /etc/passwd | egrep ':0$' | cut -d: -f1 | grep -v root > /zerouidusers

		if [ -s /zerouidusers ]
		then
			echo "WARNING: UID CHANGE UNSUCCESSFUL!"
		else
			echo "Successfully Changed Zero UIDs!"
		fi
	else
		echo "No Zero UID Users"
	fi
	cont
}


systemctlProtection()
{
    sysctl -w net.ipv4.ip_forward=0
    sysctl -w net.ipv4.conf.all.send_redirects=0 
    sysctl -w net.ipv4.conf.default.send_redirects=0
    sysctl -w net.ipv4.conf.all.accept_source_route=0 
    sysctl -w net.ipv4.conf.default.accept_source_route=0
    sysctl -w net.ipv4.conf.all.accept_redirects=0 
    sysctl -w net.ipv4.conf.default.accept_redirects=0 
    sysctl -w net.ipv4.conf.all.secure_redirects=0 
    sysctl -w net.ipv4.conf.default.secure_redirects=0
    sysctl -w net.ipv4.conf.all.log_martians=1 
    sysctl -w net.ipv4.conf.default.log_martians=1
    sysctl -w net.ipv4.route.flush=1
    sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
    sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
    sysctl -w net.ipv4.conf.all.rp_filter=1 
    sysctl -w net.ipv4.conf.default.rp_filter=1 
    sysctl -w net.ipv4.tcp_syncookies=1
    sysctl -w net.ipv6.conf.all.accept_ra=0 
    sysctl -w net.ipv6.conf.default.accept_ra=0
    sysctl -w net.ipv6.conf.all.accept_redirects=0 
    sysctl -w net.ipv6.conf.default.accept_redirects=0
    sysctl -p
    cont
}


FileFinderDeleter()
{
	printf "\033[1;31mDeleting dangerous files...\033[0m\n"
	#--------- Delete Dangerous Files ----------------
	find / -name '*.mp3' -type f -delete
	find / -name '*.mov' -type f -delete
	find / -name '*.mp4' -type f -delete
	find / -name '*.avi' -type f -delete
	find / -name '*.mpg' -type f -delete
	find / -name '*.mpeg' -type f -delete
	find / -name '*.flac' -type f -delete
	find / -name '*.m4a' -type f -delete
	find / -name '*.flv' -type f -delete
	find / -name '*.ogg' -type f -delete
	find /home -name '*.gif' -type f -delete
	find /home -name '*.png' -type f -delete
	find /home -name '*.jpg' -type f -delete
	find /home -name '*.jpeg' -type f -delete
	cd / && ls -laR 2> /dev/null | grep rwxrwxrwx | grep -v "lrwx" &> /tmp/777s
	cont

	printf "\033[1;31m777 (Full Permission) Files : \033[0m\n"
	printf "\033[1;31mConsider changing the permissions of these files\033[0m\n"
	cat /tmp/777s
    ##Items without groups
	echo "###FILES WITHOUT GROUPS###" >> pFiles.log
	find / -nogroup >> pFiles.log
	echo "###GAMES###" >> pFiles.log
	dpkg -l | grep -i game
	cont
}


fileSecurityProtection()
{
	printf "\033[1;31mSome automatic file inspection...\033[0m\n"
	#--------- Manual File Inspection ----------------
	cut -d: -f1,3 /etc/passwd | egrep ':[0-9]{4}$' | cut -d: -f1 > /tmp/listofusers
	echo root >> /tmp/listofusers
	
	#Replace sources.list with safe reference file (For Ubuntu 14 Only)
	# cat $PWDthi/referenceFiles/sources.list > /etc/apt/sources.list
	# apt-get update

#	#Replace lightdm.conf with safe reference file
#	cat $PWDthi/referenceFiles/lightdm.conf > /etc/lightdm/lightdm.conf

	#Replace sshd_config with safe reference file
	cat $PWDthi/referenceFiles/sshd_config > /etc/ssh/sshd_config
	/usr/sbin/sshd -t
	systemctl restart sshd.service

	#/etc/rc.local should be empty except for 'exit 0'
	echo 'exit 0' > /etc/rc.local

	printf "\033[1;31mFinished automatic file inspection. Continue to manual file inspection? (Y/N)\033[0m\n"
	read contyn
	if [ "$contyn" = "N" ] || [ "$contyn" = "n" ]; then
		exit
	fi
	clear

	printf "\033[1;31mSome manual file inspection...\033[0m\n"

	#Manual File Inspection
	nano /etc/resolv.conf #make sure if safe, use 8.8.8.8 for name server
	nano /etc/hosts #make sure is not redirecting
	visudo #make sure sudoers file is clean. There should be no "NOPASSWD"
	nano /tmp/listofusers #No unauthorized users

	cont
}


hackerToolDeleter()
{
    ##CHANGE TO GREP -i
    ##Looks for apache web server
	dpkg -l | grep apache
	if [ $? -eq 0 ];
	then
        	read -p "Do you want apache installed on the system[y/n]: "
        	if [ $a = n ];
        	then
      	        	apt-get autoremove -y --purge apache2
			else
            		if [ -e /etc/apache2/apache2.conf ]
				then
					chown -R root:root /etc/apache2
					chown -R root:root /etc/apache
					echo \<Directory \> >> /etc/apache2/apache2.conf
					echo -e ' \t AllowOverride None' >> /etc/apache2/apache2.conf
					echo -e ' \t Order Deny,Allow' >> /etc/apache2/apache2.conf
					echo -e ' \t Deny from all' >> /etc/apache2/apache2.conf
					echo UserDir disabled root >> /etc/apache2/apache2.conf
				else
					##Installs and configures apache
					apt-get install apache2 -y
						chown -R root:root /etc/apache2
						chown -R root:root /etc/apache
						echo \<Directory \> >> /etc/apache2/apache2.conf
						echo -e ' \t AllowOverride None' >> /etc/apache2/apache2.conf
						echo -e ' \t Order Deny,Allow' >> /etc/apache2/apache2.conf
						echo -e ' \t Deny from all' >> /etc/apache2/apache2.conf
						echo UserDir disabled root >> /etc/apache2/apache2.conf

					##Installs and configures sql
					apt-get install mysql-server -y

					##Installs and configures php5
					apt-get install php5 -y
					chmod 640 /etc/php5/apache2/php.ini
				fi
        	fi
	else
        echo "Apache is not installed"
		sleep 1
	fi
        ##Looks for john the ripper
	dpkg -l | grep john
	if [ $? -eq 0 ];
	then
        	echo "JOHN HAS BEEEN FOUND! DIE DIE DIE"
        	apt-get autoremove -y --purge john
        	echo "John has been ripped"
			sleep 1
	else
        	echo "John The Ripper has not been found on the system"
			sleep 1
	fi
    ##Look for HYDRA
	dpkg -l | grep hydra >>output.log
	if [ $? -eq 0 ];
	then
		echo "HEIL HYDRA"
		apt-get autoremove -y --purge hydra
	else
		echo "Hydra has not been found."
	fi
    ##Looks for nginx web server
	dpkg -l | grep nginx
	if [ $? -eq 0 ];
	then
        	echo "NGINX HAS BEEN FOUND! OHHHH NOOOOOO!"
        	apt-get autoremove -y --purge nginx
	else
        	echo "NGINX has not been found"
			sleep 1
	fi
    ##Looks for samba
	if [ -d /etc/samba ];
	then
		read -p "Samba has been found on this system, do you want to remove it?[y/n]: " a
		if [ $a = y ];
		then
    echo "$LogTime uss: [$UserName]# Uninstalling samba..."
			sudo apt-get autoremove --purge -y samba
			sudo apt-get autoremove --purge -y samba
    echo "$LogTime uss: [$UserName]# Samba has been removed."
		else
			sed -i '82 i\restrict anonymous = 2' /etc/samba/smb.conf
			##List shares
		fi
	else
		echo "Samba has not been found."
		sleep 1
	fi
    ##LOOK FOR DNS
	if [ -d /etc/bind ];
	then
		read -p "DNS server is running would you like to shut it down?[y/n]: " a
		if [ $a = y ];
		then
			apt-get autoremove -y --purge bind9 
		fi
	else
		echo "DNS not found."
		sleep 1
	fi
    ##Looks for FTP
	dpkg -l | grep -i 'vsftpd|ftp'
	if [ $? -eq 0 ]
	then	
		read -p "FTP Server has been installed, would you like to remove it?[y/n]: " a
		if [ $a = y ]
		then
			PID = `pgrep vsftpd`
			sed -i 's/^/#/' /etc/vsftpd.conf
			kill $PID
			apt-get autoremove -y --purge vsftpd ftp
		else
			sed -i 's/anonymous_enable=.*/anonymous_enable=NO/' /etc/vsftpd.conf
			sed -i 's/local_enable=.*/local_enable=YES/' /etc/vsftpd.conf
			sed -i 's/#write_enable=.*/write_enable=YES/' /etc/vsftpd.conf
			sed -i 's/#chroot_local_user=.*/chroot_local_user=YES/' /etc/vsftpd.conf
		fi
	else
		echo "FTP has not been found."
		sleep 1
	fi
    ##Looks for TFTPD
	dpkg -l | grep tftpd
	if [ $? -eq 0 ]
	then
		read -p "TFTPD has been installed, would you like to remove it?[y/n]: " a
		if [ $a = y ]
		then
			apt-get autoremove -y --purge tftpd
		fi
	else
		echo "TFTPD not found."
		sleep 1
	fi
    ##Looking for VNC
	dpkg -l | grep -E 'x11vnc|tightvncserver'
	if [ $? -eq 0 ]
	then
		read -p "VNC has been installed, would you like to remove it?[y/n]: " a
		if [ $a = y ]
		then
			apt-get autoremove -y --purge x11vnc tightvncserver 
		##else
			##Configure VNC
		fi
	else
		echo "VNC not found."
		sleep 1
	fi

    ##Looking for NFS
	dpkg -l | grep nfs-kernel-server
	if [ $? -eq 0 ]
	then	
		read -p "NFS has been found, would you like to remove it?[y/n]: " a
		if [ $a = 0 ]
		then
			apt-get autoremove -y --purge nfs-kernel-server
		##else
			##Configure NFS
		fi
	else
		echo "NFS has not been found."
		sleep 1
	fi
    ##Looks for snmp
	dpkg -l | grep snmp
	if [ $? -eq 0 ]
	then	
		echo "SNMP HAS BEEN LOCATED!"
		apt-get autoremove -y --purge snmp
	else
		echo "SNMP has not been found."
		sleep 1
	fi
    ##Looks for sendmail and postfix
	dpkg -l | grep -E 'postfix|sendmail'
	if [ $? -eq 0 ]
	then
		echo "Mail servers have been found."
		apt-get autoremove -y --purge postfix sendmail
	else
		echo "Mail servers have not been located."
		sleep 1
	fi
    ##Looks xinetd
	dpkg -l | grep xinetd
	if [ $? -eq 0 ]
	then
		echo "XINIT HAS BEEN FOUND!"
		apt-get autoremove -y --purge xinetd
	else
		echo "XINETD has not been found."
		sleep 1
	fi
    dpkg --get-selections | grep john

    dpkg --get-selections | grep crack
    # NOTE: CRACKLIB IS GOOD

    dpkg --get-selections | grep -i hydra

    dpkg --get-selections | grep weplab

    dpkg --get-selections | grep pyrit
    sudo apt-get purge qbittorrent 
    sudo apt-get purge utorrent 
    sudo apt-get purge ctorrent 
    sudo apt-get purge ktorrent 
    sudo apt-get purge rtorrent 
    sudo apt-get purge deluge 
    sudo apt-get purge transmission-gtk
    sudo apt-get purge transmission-common 
    sudo apt-get purge tixati 
    sudo apt-get purge frostwise 
    sudo apt-get purge vuze 
    sudo apt-get purge irssi
    sudo apt-get purge talk 
    sudo apt-get purge telnet
	#Remove pentesting
    sudo apt-get purge wireshark 
    sudo apt-get purge nmap 
    sudo apt-get purge john 
    sudo apt-get purge netcat 
    sudo apt-get purge netcat-openbsd 
    sudo apt-get purge netcat-traditional 
    sudo apt-get purge netcat-ubuntu 
    sudo apt-get purge netcat-minimal
	#cleanup	 
    sudo apt-get autoremove
    # MySQL
    echo -n "MySQL [Y/n] "
    read option
    if [[ $option =~ ^[Yy]$ ]]
    then
      sudo apt-get -y install mysql-server
    # Disable remote access
    sudo sed -i '/bind-address/ c\bind-address = 127.0.0.1' /etc/mysql/my.cnf
    sudo service mysql restart
    else
    sudo apt-get -y purge mysql*
    fi

    # OpenSSH Server
    echo -n "OpenSSH Server [Y/n] "
    read option
    if [[ $option =~ ^[Yy]$ ]]
    then
      sudo apt-get -y install openssh-server
      # Disable root login
      sudo sed -i '/^PermitRootLogin/ c\PermitRootLogin no' /etc/ssh/sshd_config
      sudo service ssh restart
    else
      sudo apt-get -y purge openssh-server*
    fi

    # VSFTPD
    echo -n "VSFTP [Y/n] "
    read option
    if [[ $option =~ ^[Yy]$ ]]
    then
      sudo apt-get -y install vsftpd
      # Disable anonymous uploads
      sudo sed -i '/^anon_upload_enable/ c\anon_upload_enable no' /etc/vsftpd.conf
      sudo sed -i '/^anonymous_enable/ c\anonymous_enable=NO' /etc/vsftpd.conf
      # FTP user directories use chroot
      sudo sed -i '/^chroot_local_user/ c\chroot_local_user=YES' /etc/vsftpd.conf
      sudo service vsftpd restart
    else
     sudo apt-get -y purge vsftpd*
    fi

        
	cont
}


passwordAuditSecurity()
{
    sudo sed -i '/^PASS_MAX_DAYS/ c\PASS_MAX_DAYS   90' /etc/login.defs
    sudo sed -i '/^PASS_MIN_DAYS/ c\PASS_MIN_DAYS   10'  /etc/login.defs
    sudo sed -i '/^PASS_WARN_AGE/ c\PASS_WARN_AGE   7' /etc/login.defs
    # Password Authentication
    sudo sed -i '1 s/^/auth optional pam_tally.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account silent\n/' /etc/pam.d/common-auth

    # Force Strong Passwords
    sudo apt-get -y install libpam-cracklib
    sudo sed -i '1 s/^/password requisite pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1\n/' /etc/pam.d/common-password
}


allFunctions