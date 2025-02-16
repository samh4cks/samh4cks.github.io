---
title: HackTheBox Preignition Writeup
authors: Samarth
categories: [HackTheBox , Starting Point - Tier 0]
tags: [Linux, Custom Applications, Apache, Reconnaissance, Web Site Structure Discovery, Default Credentials]
math: true
mermaid: true
---

![Preignition-HTB](/assets/images/starting-point/Preignition-HTB/banner.png)

## TL;DR

This writeup covers the [__Preignition__](https://app.hackthebox.com/starting-point){:target="_blank"} machine, a beginner-friendly Linux box on Hack The Box. The initial Nmap scan revealed an open HTTP port (80) running Nginx. Directory fuzzing with `dirb` uncovered an `admin.php` page, leading to a login panel. I attempted common default credentials, and the combination `admin:admin` successfully granted access to the admin console. From here, further exploitation was possible to gain system access.

## Scanning Network

I began by performing an Nmap scan, which revealed an open port, `80`, corresponding to `http`. Here are the results from the Nmap scan:

```bash
nmap -sC -sV -A -T4 -Pn 10.129.12.119 -oN scan/normal.scan
Starting Nmap 7.94 ( https://nmap.org ) at 2025-02-15 22:08 IST
Nmap scan report for 10.129.12.119
Host is up (0.22s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT      STATE    SERVICE        VERSION
80/tcp    open     http           nginx 1.14.2
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.14.2
5633/tcp  filtered beorl
9594/tcp  filtered msgsys
32772/tcp filtered sometimes-rpc7
```

## Enumeration

While analyzing the Nmap output, I found that port `80` was open. Since this is the only open port, I decided to perform directory fuzzing to discover interesting directories, files, or endpoints.

```bash
dirb http://10.129.12.119/                                                                                                                                                                       

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sat Feb 15 22:14:26 2025
URL_BASE: http://10.129.12.119/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.129.12.119/ ----
+ http://10.129.12.119/admin.php (CODE:200|SIZE:999)   
```

Let's visit `http://10.129.12.119/admin.php`.

![Target Website](/assets/images/starting-point/Preignition-HTB/1.png)

I discovered a login page for an admin console. Typically, admin consoles use default usernames such as `admin`, `administrator`, or `root`, with common passwords like `admin`or `password`. 

I attempted various username/password combinations to log in to the admin console.

After testing multiple possibilities, the combination `admin:admin` was successful, granting me access to the admin console.

![Admin Console](/assets/images/starting-point/Preignition-HTB/2.png)


## Tasks

### Directory Brute-forcing is a technique used to check a lot of paths on a web server to find hidden pages. Which is another name for this? (i) Local File Inclusion, (ii) dir busting, (iii) hash cracking.

```plaintext
dir busting
```

### What switch do we use for nmap's scan to specify that we want to perform version detection

```plaintext
-sV
```

### What does Nmap report is the service identified as running on port 80/tcp?

```plaintext
http
```

### What server name and version of service is running on port 80/tcp?

```plaintext
nginx 1.14.2
```

### What switch do we use to specify to Gobuster we want to perform dir busting specifically?

```plaintext
dir
```

### When using gobuster to dir bust, what switch do we add to make sure it finds PHP pages?

```plaintext
-x php
```

### What page is found during our dir busting activities?

```plaintext
admin.php
```

### What is the HTTP status code reported by Gobuster for the discovered page?

```plaintext
200
```

### Submit root flag

```plaintext
6483bee07c1c1d57f14e5b0717503c73
```

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.