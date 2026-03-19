# cdt-blue-team

WILL HAVE TO MODIFY SCRIPTS TO ALLOW SCORING/GREY TEAM USERS
Have tested all but blockCron.sh; need to fix sandbox_ssh.sh.
Started adding python versions of all scripts in case bash gets broken (don't know if it'll work bc it calls commands). haven't tested those yet.
Can edit /etc/vsftpd.userlist to add allowed users
If we need to add users: chmod 755 /usr/sbin/useradd (after running disableUserCreation.sh)
Make sure to run all cron jobs and then run disableCron.sh to block red team from gaining persistence with Cron
Add to Cron: changeUserPass.sh; killSSH.sh; folderMonitor.sh; closeUnecessaryPorts.sh; killProcesses.sh; disableUserCreation.sh; logAttackerActivity.sh; reverseShellDetection.sh;
