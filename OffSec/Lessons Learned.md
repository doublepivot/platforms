Clue
Look in bash history of users. This is located in /home/<user>/.bash_history
Keep in mind all the credentials you've collected and try to switch after you do a major action (get foothold in this case) with one.
If when you try to do directory transversal it doesn't give an error, just collapses the URL, use curl --path-as-is.s

Cockpit
Check your SECLISTS wordlist. There was a MySQL SQLi wordlist in there that helped.
If you're not having luck with wfuzzing, turn on follow redirects.
With tar (possibly other programs too), if you can sudo it but the parameters are restricted to asterisk, you can make files that names that will execute when tar'ing and they can possibly execute scripts.
Example: the user has SUDO access to exactly /usr/bin/tar -czvf /tmp/backup.tar.gz *
You can create files named --checkpoint=1 and --checkpoint-exec=sh payload.sh
Then when you run sudo /usr/bin/tar -czvf /tmp/backup.tar.gz * in that directory, it will run payload.sh.

Codo
Make sure the tools you have are reliable. I have 3 different versions of linPEAS now. 

Educated
Carefully read through exploits and enumerate thoroughly. It might first look like you don't have access or they won't work. They might need modified just a little bit or you might be able to skip a step.
If you have to debug a program to find credentials, try decompiling it and just search for things like "username", "user", any actual usernames you may have, "password", "pass", "hash", "md5".

Extplorer
Look for other users in /home to see if you might have to switch to them to do the next step.
If you have a filemanager, search for any user IDs you might have to see if the password is available in one of the files.

Image
If you find a discussion or log of a CVE, look through the changes. There might be a newer CVE # opened for it with different PoCs.

Law
Pspy is a good tool to see what is being ran. UID=0 is the root user.

Marshalled
I'm not adding the steps for this one because there's no way something this hard will be on the exam. The only lesson learned that might be on it is scanning for vhosts:
`ffuf -w $payloads/seclist/Discovery/DNS/subdomains-top1million-110000.txt -u http://marshalled.pg -H 'Host: FUZZ.marshalled.pg' -fs 868`

PC
The opt folder normally contains optional files for applications. If root is running something from this when you do lse or ps aux, check into it.

Plum
Valuable information can sometimes be found in messages if the user has mail.

Press
Sometimes to find out a version of a web application, there is a CHANGELOG.md you can view. Usually you can find where this is if you look at the program on GitHub.

pyLoader
If the first exploit doesn't work, search for other PoCs.

Election
To do hashed or binary conversions, sometimes you need to do it twice to get the plain text. You can run goboster on one directory at a time, add extensions, and filter out response codes. 

Stapler
An interesting option with Hydra is -e nsr. This tries for null passwords, s for standard passwords (like pass), and r tries the username reversed.

DirtyBlues6
If you run out of ideas for privesc, start working through the CVEs.

Blogger
Run wpscan on WordPress instances with --plugins-detection aggressive to check the plugins in depth for vulnerabilities.

DC-9
If a port is in filtered mode, you might have to port knocking to get it open.
