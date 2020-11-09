# CyberPatriot-Scripts
These scripts are meant only for the BASIS San Antonio Shavano Campus teams
# Windows 10
Use all of the options for the script
# Windows Server 2016
Use the same script but do everything except the 'Disable Remote Desktop' option
# Linux
The 'linuxHardening.sh' script will run automatically. Please don't leave the script running unattended, because you need to make sure that the script isn't doing what you don't want it to.




# How To Install: 

## Linux

First, you will need to install Git, which will allow you to clone (download) the scripts to your device.

```bash
sudo apt-get install git -y
```
After it installs, we will need to actually clone the scripts to the system.

```bash
git clone https://github.com/Ne-el/CPScripts-20-21.git
```
Now, we need to go into the install directory, which will be where you started the 'git clone' command.

After this, we will find the script (linuxHardening.sh) which will allow us to execute scripts and get the win.

After finding the script, we need to make it executable.

```bash
sudo chmod +x ./linuxHardening.sh
```

Finally, execute the script
```bash
sudo ./linuxHardening.sh
```

## Windows
This might be the easiest way to get your points in the fastest way possible.

Just go to github.com/Ne-el/CPScripts-20-21 and click 
