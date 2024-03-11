Codo

`---------------------Starting Port Scan-----------------------`

`PORT   STATE SERVICE`
`22/tcp open  ssh`
`80/tcp open  http`

`| http-enum:` 
`|   /admin/: Possible admin folder`
`|   /admin/index.php: Possible admin folder`
`|   /admin/login.php: Possible admin folder`
`|   /cache/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'`
`|   /sites/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'`
`|_  /sys/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'`
`|_http-dombased-xss: Couldn't find any DOM based XSS.`
`| http-cookie-flags:` 
`|   /:` 
`|     PHPSESSID:` 
`|       httponly flag not set`
`|   /admin/:` 
`|     PHPSESSID:` 
`|       httponly flag not set`
`|   /admin/index.php:` 
`|     PHPSESSID:` 
`|_      httponly flag not set`

We have weak credentials on 192.168.190.23/admin/ - admin:admin

Found this site for the Codoforum RCE: https://vikaran101.medium.com/codoforum-v5-1-authenticated-rce-my-first-cve-f49e19b8bc

Get Pentest Monkey's PHP reverse shell - https://github.com/pentestmonkey/php-reverse-shell - and update the IP and port in it.

Upload this as the forum's logo.
![[Pasted image 20240209232651.png]]

![[Pasted image 20240209232523.png]]

Go back to the forum and right click -> open image in new window on one of the icons

http://192.168.190.23/sites/default/assets/img/profiles/icons/6488ee7e82484.png

If we traverse up to http://192.168.190.23/sites/default/assets/img/ we can see our php-reverse-shell.php probably got placed in one of these folders.

![[Pasted image 20240209232651.png]]

The first one we try gives us our reverse shell.

Download linpeas from here - https://github.com/carlospolop/PEASS-ng - you might have a different version. I did previously and this one was much larger so I'm guessing it does a lot more. It found what was needed.

Scrolling through what linpeas gives us we see this

![[Pasted image 20240209233057.png]]

Try to use this for the offsec user we saw - no success. Try to use it for root and it works.

`su root`
`Password: FatPanda123`

`cat /root/proof.txt`
`01565b9ac4b759eec0ce85b9f6acef11`
