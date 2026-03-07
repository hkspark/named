# cdt-blue-team

WILL HAVE TO MODIFY SCRIPTS TO ALLOW SCORING/GREY TEAM USERS
Can edit /etc/vsftpd.userlist to add allowed users
If we need to add users: chmod 755 /usr/sbin/useradd (after running disableUserCreation.sh)
Make sure to run all cron jobs and then run disableCron.sh to block red team from gaining persistence with Cron
Add to Cron: changeUserPass.sh; killSSH.sh; folderMonitor.sh; closeUnecessaryPorts.sh; killProcesses.sh; disableUserCreation.sh
