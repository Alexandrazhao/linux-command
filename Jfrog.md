# JFrog Interview Prep
## Linux study
### `usermod` 
### `sudo`
`su -u` get into the root mode  
`which sudo` check if sudo package is installed  
`cat /etc/sudoers` Permission denied  
`su -`then `cat` works  
`sudo -l` what permission you are allowed to do  
`sudo apt update` update
`sudo !!` command you run most recently, rerun the command but prefix the sudo.  
`sudo nano /etc/sudoers` open the protected file (don't open it in an editor)  
`root ALL=(ALL:ALL) ALL` the first in `()` `ALL` refers user, the second `ALL` refers the group.  
`tux  ALL=(ALL:ALL) ALL` give tux all permission as root   
`sudo adduser tux` add user tux
`sudo su - tux` login tux as sudo  
`sudo -l ` to check what tux can do, then you will see tux can do everything as root does.   
`tux  ALL=(ALL:ALL) NOPASSWD: /usr/bin/apt, /usr/bin/rm` only allow tux using `apt` and `rm` commands, also allow no password 

### `htop` monitor the system resources 
`SIGTERM` politely ask the process can you please close down? If a process is not working properly, and you wanna kill it, you'd better use `SIGTERM` to cleanlt exit.   
`SIGKILL` If the process is not listening to you, use `SIGKILL`, might free the resources properly.   
`Ctrl + P` sort the process through CPU usage.  
`Ctrl + M` sort the process through Memory usage.  
`U` press `U` for user.    
`F3` for searching.   
### `ps`   
`PID` process ID, unique  
`TTY` the terminal the process is running inside of.  
`TIME` refers to CPU time, how much time the process utilize the CPU.  
`CMD` the actual command that is running in our process.  
`ps -aux` or `ps aux` (this one is working on mac)
`ps --quick-pid 10677` (not working on mac)  
`ps x` show all processes are running -> `?` means processes are running by the syetem; `tty..` means processes are running by the terminal.  
`STAT`: `s` means it is a process leader, `S` means the process is waiting for some user input and can't be disturbed. `R` means the process is actively running. `T` means process is stoped.   
`ps -He` process hierchy   
`ps -axjf` shows process relationship, `PPID`: Parent process ID; `UID`: `UID = 0` is the root, `UID = 1000`: non system user created.   
`ps aux`:can see %CPU and %MEM, so that we can tell which process cause the sysme slow down. Also the `START` time can help you check when that process started to run. For example, if a process is supposed to run all the time, you can check if it get rebooted at some point.   

### Data Streams (stdin-0, stdout-1 & stderr-2)  
`echo $?` gives the return code of previous command. Return `0` means success, return `1` means error.   
`find /etc -type f`: may have part of files I don't have access to. So we have to split `stderr` and `stdout` differently.   
`find /etc -type f 2> /dev/null`: omit the `stderr`. (`stderr` is represented by number 2. Also, `/dev/null` is more like a blackhole.)  
`find /etc -type f > ~/results.txt`: sends result to results.txt in my home directory.  
`cat ~/results.txt`: cat the contents of the text file.  
`find /etc -type f 1> ~/results.txt 2> ~/errors.txt`: target specifically `stdout` and send that to results.txt, then grub data stream `2`, the `stderr` and send that to errors.txt.  
`>` means the data stream will overwrite the file, while `>>` means the input will be written at the end of the file.    
`echo "Hello world" > hello.txt`  -----> `cat hello.txt` -----> Hello world  
`echo "Hello world" >> hello.txt` -----> `cat hello.txt` -----> Hello world  Hello world   
### nano
`nano alex.txt` open the file in nano.  
`cp /etc/ssh/sshd_config .` copy the file and save it locally.  
`nano +15 xxx`: edit the line 15.  
`nano -v xxx`: view only.   
`ctrl + T`: check the spelling.   
### User Account & Password Expiration (on Linux)
`chage`: `sudo chage -E 2022-12-28 neo` change the expiration date for neo.   
`sudo chage -l neo`: get the information of neo. It is useful for some temperal worker or contractors so you can set their leaving date as expiration date. 
`sudo chage -M 30 neo`: set the expiration date for user's password.  
`sudo chage -M -1 neo`: Removing the password expiration date.   
`sudo chage -m 7 neo`: allow the user to change the password again. `-m` means set the minimum num of days the users allowed to set the password again. Avoid users to overwrite the password policy.
`sudo passwd -l neo`: lock a user account immediately so the user is not able to sign in.   
`sudo passwd -u neo`: unlock the account.    
### Background (bg) and Foreground (fg)
`ctrl+Z` to suspend the process in the background, and use `fg` to go back to htop.  
`sudo vim /etc/ssh/sshd_config` then use `ctrl+Z` to hide this in the background.   
`htop &`: htop is sent to the background.   
`jobs`: to see the work in the background.  
`fg`: bring the most recently backgrounded job to the foreground.  
`fg job_id`: bring the specific the job to the foreground.   
### Bash Aliases (create your own linux command)  
`alias mycmd="ls -lh"`:creating an alias called mycmd. You can name your alias whatever you want.   
`alias`: to list all alias exist in your system. 
`unalias mycmd`: delete the alias.  
`df -h`: the `df` commnad, disk free command, tells you how much storage you have available. `-h` gives you human readible output.  
`alias df="df -h -x squashfs -x tmpfs -x devtemfs"`:   
`mount`: allows you to mouunt additional file systems to your linux system.   
`alias lsmount="mount | column -t"`: seperate the mount output to columns.   
`alias extip="curl icanhazip.com"`: curl my external ip address.   
`alias install="sudo apt install"`: install a package.   
`alias upgrade = "sudp apt update && sudo apt dist-upgrade"` update the package sources and repository indexes. `&&` means if the first command is successful, I am willing to run the second command.  
`alias mem5="ps auxf | sort -nr -k 4 | head -5"`: give you the top five processes which use most memory.    
`alias cpu5="ps auxf | sort -nr -k 3 | head -5"`:give you the top five processes which use most cpu.     
`nano ~/.bashrc`: make your alias permanent.  
### Public Key Authentication 
`which ssh`: check if `ssh` client installed.   
Install `putty` on windows.   
`ls -l ~/.ssh`: List the current ssh already exist in your system.   
`ssh-keygen -b 4096`: `4096` is the key size. Generate a key pair for ssh.   
`ssh root@172.105.10.184`: Confirming is you actually connecting to the server.   
`ssh-copy-id root@172.105.10.184`: to copy the ssh key.  
### Scheduling Tasks with Cron (automatically complete a task for us)
`crontab -l`: show the user's cron job.  
`crontab -e`: editor. m h dom mon dow command
`5 9 15 8 5 echo "hello world"`: run every month of Aug 15th at 9:05 if it is Friday.   
`* 11 * * * echo "hello world"`: run 11am everyday.   
`@hourly echo "hello world"`: set hourly.  
`@reboot echo "hello world"`: every time reboot.   
`crontab -u root -e`: edit the crontab of user root.   
`* * * * * apt install -y tmux`: install tmux  
#### `cat /var/log/syslog | grep CRON ` or `cat /var/log/system.log` on mac.   
`* * * * * date >> /root/date.txt`: save the date in txt file. (should inlude full path) -> crontab.generator.org  
### `awk` command: to create filter  
`awk '{print}' alex.txt`: print the alex.txt file.   
`awk '{print $1}' alex.txt`: show first field only.   
`awk '{print $1, $3}' alex.txt`: show field 1 and 3.   
`ls -l | awk '{print $4}'`: print field 4.  
`echo "Hello world | awk '{print $1}'`: let awk truncate the first word. Take the output of echo command and pipe it into the awk command.  
`awk '{print $NF}' alex.txt`: NF->number of fields, actually the last field will be print.   
`awk -F':' '{print $1, $7}' /etc/passwd`: set the field seperator as `:`  
### The `sed` Command: string editor
`sed 's/Pineapple/Feta' topings.txt`: change all Pineapple string to Feta in toppings.txt file.   
`sed -i 's/Pineapple/Feta/' toppings.txt`: `-i` means make the changes in place.   
`find /etc -type f > paths.txt`: redirect the output into a file.  
`sed 's./etc..'`: delete the /etc in the path.   
`echo "hello" | sed 's/hello/goodbye/'`: stop printing hello with goodbye.   
### Managing Groups
`groups`: show groups.  
`groups groupname`: show a specific group.  
`cat /etc/group`: show groups, similar to /etc/password. `a:b:c:d`, `a` is the name of group, `b` refers to the group password, `c` is the group id, `d` means which users are a member of the group.  
`sudo groupadd gamers`: add a group gamers.   
`sudo groupdel gamers`: delete a group.  
`cat /etc/group | grep 20`: get group id 20.   
`sudo usermod -aG group_name user_name`: add user_name to group_name.  
`sudo gpasswd -a user_name group_name`: add a member to the group.   
`sudo nano /etc/ssh/sshd_config`: add `AllowUsers alex leo namcy` define which users in patically are allow to your server via ssh.  `AllowGroups ssh-users` we can add users to the `ssh-users` group so it is easier.   
`sudo gpasswd -d alex testgroup`: remove user alex from a group testgroup.   
###   The `/etc/fstab` file (storage)
### Managing Users
`ls -l /home`: list the contents of your home directory.  
`cat /etc/passwd`: look up the user. 
`cat /etc/passwd | wc -l`: `wc` means word count.  
`cat /etc/passwd | grep yuxuanzhao`: grep the specific line. 
`sudo useradd alexneedfood`: create a user alexneedfood.  
`sudo userdel alexneedfood`: delete the user account.  
### System `systemctl` command (need to study later)
`sudo apt install apache2` or on mac `brew install apache2`: install  
`systemd`: what is running on your server, easily manage running services. (units)   
`systemctl` = `launchctl` on mac.  
### Symbolic Links
### The `find` command
`find /home/yuxuanzhao -name *.txt | grep -v .cache`: search anything.txt    
`find . -name Documents`: find in current directory, look for documents.  
`find . -type f -name Documents -exec rm {} +`:   
### File & Directory Permissions
`ls -l`: allow us to see th permission string. drwxr-xr-x `d`:directory, `-`: that object is a file.  
`drwxrwxr-x 2 jay jay 4.0K 2021-03-12 17:28 vbox`: a folder called vbox. `d`: the first section, file(f)? directory(d)? Link? `rwx`: Permission for the user. `r`: read. `w`: write. `x`: file: execute the file as a program; directory: can go inside the directory. `rwx`: the third section, Permission for the group. `r-x`: the fourth section: Permission for "other"
User: jay, Group:jay.    
`chmod +x alex.txt`: change the permission.   
`chmod u-x alex.txt`: set except the user.  
`chmod u+x alex.txt`: set to the specific user.    
`r = 4`, `w = 2`, `x = 1`  
`chmod 770 alex.txt`: `chmod ??? alex.txt`: 1:user, 2: group, 3: other. `4+2+1 = 7 -> r+w+x`   
`chmod 600 Downloads/*`: `-R` means recursive.   
`sudo chown -R batman Downloads/`: change the ownership of a object.   
`sudo chown -R batman:batman Downloads/`: change th ownership of my user and my group.  
### Navigating the Linux Filesystem
`ls -l`: gives info of all files in your current directory.  
`~`: refer your home directory.   
`pwd`: print current directory.  
`mkdir myfolder`: make a new directory. 
`mkdir -p thirdfolder/subdir1/subdir2`: `p` means parent if thirdfolder doesn't exist. 
`cd ~`: go to home directory.   
`rm alex.txt`: remove alex.txt file.  
`rm -r folder`: remove the directory. `r` means recursive.   
`mv myfolder/ renamed`: rename  
`mv renamed secondfolder/` move renamed dir to secondfolder dir.   
### The Arch User Repository (AUR) 
`wget`: is a robust command line application for downloading URL-specific resources.
`wget https://aur.archlinux.org/cgit/aur.git/snapshot/google-chrome.tar.gz`: download the google chrome compressed file.  
`tar -xvf google-chrome.tar.gz`: `-x` means extract, `-v` means enable verbose mode, showing the progress of the command. `f` means specify file input, rather than STDIN. `-z` means use gzip, omit this if you have a .tar.  
## Always check the script (check PKGBUILD file)

## How to verify downloaded Files
1. Checksum is used to verify the integrity of the file you just downloaded (MD5 and SHA1)
2. Sometimes PGP/GPG signatures are provided for file verification purposes as well. 
`md5sum` or `sha1sum` on Linux or `md5` or `shasum` to use MD5 hashing algorithm.   
For example, we download the `mini.iso` file, then run `md5 mini.iso` in our terminal to generate the MD5, then we have `MD5 (mini.iso) = 8388f7232b400bdc80279668847f90da` and compare to `8388f7232b400bdc80279668847f90da` from the official website.   
We can run `shasum -a 1 mini.iso` to specify using SHA1 in command line.  
### The apt command (brew in mac)
`sudo apt update`: 
### Setting the hostname of your linux workstation or server.  
`hostname`: print your hostname.  
`sudo hostnamectl set-hostname my-laptop.mydomain.com`: set my hostname. (on linux)  
`sudo scutil --set HostName <new host name>`: set my hostname. (on mac)    
`cat /etc/hosts`: look at the host file.   
`ping Yuxuans-MacBook-Pro.local`: ping my localhost.   
### Installing updates  
`apt update` Update package index  
`apt dist-upgrade`:   
### The `grep` command (search text within files)
`cat /etc/ssh/ssh_config | wc -l`: see how many lines.  
`cat /etc/ssh/ssh_config | grep Port`: search for Port.   
`cat /etc/ssh/ssh_config | grep -v Port`: print everyline that doesn't contain port. (exclusion) 
`grep Port /etc/ssh/sshd_config`: get the port.   
`grep Alex alex.txt`: search Alex in alex.txt.  
`grep -n Alex alex.txt`: give the line number.  
`grep -c Alex alex.txt`: give the number of time Alex appears.   
`grep` is case sensitive. `grep -i alex alex.txt` can ignore the case sensotivity.  
`grep gedit *`: look gesit through every file.   
`grep -r gedit git/personal/ansible/roles/` recursive search.  
## `grep -ri Error /var/log`: see all the errors in log file.   
`grep -r term /path/to/folder`: search a term.   
### The echo command: shwoing text in the terminal, and showing contents and variables. 
`echo "Hello World"`: print.  
`msg = "Hello World"`, `echo msg`.  
`echo $HOME`: print the home path.   
`echo -e "\aHello World"`: enable audio output of Hello world.   
`echo -e "This is a\bLinux server."`: implement backspace in the output.  
`echo -e "This is a Linux\c server. "`: bash outout is right next to the text.   
`echo -e "This is a Linux\n server."`: create a new line. 
`echo "Logfile started: $(date + '%D %T')"`:add to a log file.   
### Bash History:
`history`: a list of commands that have been ran. (something is run, some file is missing)  
`!1012`:then it will rerun that command.   
`nano .bashrc`  
`history 4`: see only last four commands.  
`history | grep apt`: show all history contians apt.   
`ctrl+R`: search history.   
### Memory Usage  
`free`: how much memeory is free. Or use `vm_stat` on mac.   
### ping command: determine wheather or not a server is online
`ping 172.105.22.239`: to check if server is online.  
`ping localhost`: ping the localhost. sending icmp request.    
`ping -c 5 8.8.8.8`: to determine if we have internet connection. Real world: if user cannot reach the browsers, as an administrator, I can try to ping google's dns, if I am able to do that, then i know my internet connection is fine. But if users are having a problem, then the problem is DNS or one of the network services are not working. Then check local dns server, such as DHCP server.  
`ping 10.10.10.222`:find out a server is finally become available. You can see packet loss when you reboot the server.    
### The wget Command (to download something from internet) 
`wget https://wordpress.org/latest.zip`: download Wordpress.  
`wget -O wp.zip https://wordpress.org/latest.zip`: change the name of downloaded file.   
`wget -P /home/yuxuanzhao/Downloads https://wordpress.org/latest.zip`: download to the specific path.  
`wget -c https://wordpress.org/latest`: If download something quite large and you lose the network connection during the process. `-c` resume the download when it got cut.   
`nano fetch-list.txt`: add the download url in fetch-list.txt. Then use `wget -i fetch-list.txt`. 
### The `df` and `du` Commands
`df`: disk free. Telling you how much disk space you have free.   
`df -h`: human readible numbers.  
`df -h -T`: show the type (linux).  
`df -hT -x`: `-x tmpfs` means to exclude something.   
`watch df -h`: `watch` command means keep watching the command and see if there is any updates.    
`du -h /home/yuxuanzhao`: show how much space that is used in that directory.   
`du -h --max-depth 1 /home/jay`: more clear.   
`du -h --max-depth 2 /home/yuxuanzhao`: going to 2 directories deep. Or `du -h -d 2` on Mac.   
`du -hs /home/yuxuanzhao`:  
`sudo du -hsc /home/yuxuanzhao/*`: show all sub directory.  
`ncdu`: give a breakdown of folders underneath the home directory. (no mac)  
### The `head` and `tail` Commands (show the first or last lines of a file)
`head /var/log/syslog | wc -l`: print the first 10 lines.   
`tail /var/log/syslog`: print the last 10 lines of the file.   
`cp /var/log/syslog .`: copy the syslog to local.  
### Understanding Logging  
`cd /var/log` and use `ls -l` to list the storage.   
`cat wifi.log`:  
`cat wtmp`: binary log, some other command you need to use.   
`last`: give detail about log in and log out events.  
`cat btmp` -> `sudo lastb -adF`: `-a` show the host name in the last column. `-d`: attempt to match dns name with ip address. `-F` give us full time show in the command. 
`sudo tail -f /var/log/auth.log`: show last ten logs in auth.log file.  
`cat syslog`: system events, (hardware issues, USB, flash drive.)  
`cat dmesg.log`: similar to syslog.  
`sudo dmesg`: displays kernel-related messages retrieved from the kernel ring buffer.  
`journalctl`: similar to systemd. inspect actualy units or services in the system.  
`journalctl -u ssh`: see log entries specific via ssh.  
`systemctl start apache2`:
`journalctl -fu ssh`: follow a unit, follow ssh. 
 















 





















