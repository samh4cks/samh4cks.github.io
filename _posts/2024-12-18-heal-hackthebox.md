---
title: Heal - HackTheBox
authors: Samarth
date: 2024-12-18 09:15:00 +0530
categories: [HackTheBox Machines]
tags: [Linux]
math: true
mermaid: true
---

![Heal - HTB](/assets/images/writeups/Heal-HTB/banner.png)

## TL;DR



## Scanning Network

I began by performing an Nmap scan, which revealed open ports 22 and 80, corresponding to `SSH` and `Nginx 1.18.0`. Here are the results from Nmap scan:

```bash
nmap -sC -sV -A -T4 -Pn 10.10.11.46 -oN scan/normal.scan
Starting Nmap 7.94 ( https://nmap.org ) at 2024-12-18 11:44 IST
Nmap scan report for 10.10.11.46
Host is up (0.21s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 68:af:80:86:6e:61:7e:bf:0b:ea:10:52:d7:7a:94:3d (ECDSA)
|_  256 52:f4:8d:f1:c7:85:b6:6f:c6:5f:b2:db:a6:17:68:ae (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://heal.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Two services, SSH and HTTP, were detected. Let’s proceed with enumerating the HTTP service.

## Enumeration

The Nmap scan revealed that the IP address is linked to the domain name `heal.htb`. Therefore, we need to add this domain to the `"/etc/hosts"` file.

Then, I visited [__http://linkvortex.htb/__]().

![Browser View](/assets/images/writeups/Heal-HTB/1.png)

Website's title `Fast Resume builder` confirms that this website is being used to create resume. Website provided `sign up` and `sign in` option.

Let's create a random user on this website.

![Creating account](/assets/images/writeups/Heal-HTB/2.png)

Successfully created the account and now I have logged in.

![Resume Builder](/assets/images/writeups/Heal-HTB/3.png)

While browsing the resume builder website, I found new subdomain on `survey` tab that was `take-survey.heal.htb`, so let's add it in `/etc/hosts` file.

![take-survey.heal.htb](/assets/images/writeups/Heal-HTB/4.png)

The `take-survey.heal.htb` revealed the adminsitrator email that was `ralph@heal.htb`.

I performed the directory fuzzing on `take-survey.heal.htb` and found interesting files and directories but interestingly I found the `/admin` directory.

```bash
wfuzz -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -u http://take-survey.heal.htb/FUZZ --hc 404,403 -f take-survey.heal.fuzzing
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://take-survey.heal.htb/FUZZ
Total requests: 20476

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000896:   302        0 L      0 W        0 Ch        "Admin"
000000966:   200        974 L    8007 W     49474 Ch    "LICENSE"
000001817:   301        7 L      12 W       178 Ch      "admin"
000002498:   301        7 L      12 W       178 Ch      "application"
000002709:   302        0 L      0 W        0 Ch        "assessment"
000002717:   301        7 L      12 W       178 Ch      "assets"
000006263:   301        7 L      12 W       178 Ch      "docs"
000006665:   301        7 L      12 W       178 Ch      "editor"
000009739:   301        7 L      12 W       178 Ch      "installer"
000011008:   301        7 L      12 W       178 Ch      "locale"
000011970:   301        7 L      12 W       178 Ch      "modules"
000013133:   302        0 L      0 W        0 Ch        "optout"
000013127:   302        0 L      0 W        0 Ch        "optin"
000014021:   301        7 L      12 W       178 Ch      "plugins"
000015400:   302        0 L      0 W        0 Ch        "responses"
000017489:   200        1085 L   4127 W     74948 Ch    "surveys"
000018031:   301        7 L      12 W       178 Ch      "themes" 
000018177:   301        7 L      12 W       178 Ch      "tmp" 
000018772:   401        100 L    294 W      4569 Ch     "uploader"
000018749:   301        7 L      12 W       178 Ch      "upload"           
000019083:   301        7 L      12 W       178 Ch      "vendor"  
```
`/admin` rendered to `/index.php/admin/authentication/sa/login`.

![LimeSurvey Admin](/assets/images/writeups/Heal-HTB/5.png)

`LimeSurvey` is an open-source web application designed for creating, managing, and analyzing online surveys.

Later on, I have created the resume and exported it in PDF and intercepted all the web request in `Burp Suite`. I found that the `api.heal.htb` is being called to export the resume in PDF, which means I found one new subdomain `api.heal.htb` to add in `/etc/hosts` file.

![Resume Making](/assets/images/writeups/Heal-HTB/6.png)

![api.heal.htb](/assets/images/writeups/Heal-HTB/7.png)

PDF is successfully exported in PDF format. I will analyse the PDF later but first I will visit [__http://api.heal.htb/__]().

![API](/assets/images/writeups/Heal-HTB/8.png)

I found `Rail version` as `7.1.4` and `Ruby version` as `ruby 3.3.5`. Let's just keep this information in notes but first I will review exported PDF as resume.

I have used `exiftool` to read metadata of exported PDF.

`ExifTool` is a powerful, open-source software tool used for reading, writing, and editing metadata in a wide variety of file types, including images, audio files, video files, and documents.

![exiftool](/assets/images/writeups/Heal-HTB/9.png)

I found that the resume builder used `wkhtmltopdf 0.12.6` tool to convert html file to PDF file.

I have collected all the above information. Now, I have performed directory listing on `api.heal.htb` as well as on `take-survey.heal.htb` 

```bash
wfuzz -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -u http://api.heal.htb/FUZZ --hc 404,403 -f api.heal.fuzzing
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://api.heal.htb/FUZZ
Total requests: 20476

=====================================================================
ID           Response   Lines    Word       Chars       Payload                        
=====================================================================
000006362:   401        0 L      2 W        26 Ch       "download" 
000014522:   401        0 L      2 W        26 Ch       "profile"                       
000015419:   401        0 L      2 W        26 Ch       "resume"                 
000015556:   200        1 L      12 W       99 Ch       "robots.txt"  
```

First I had navigated to `http://api.heal.htb/download`, it was showing response as `invalid-token`.

![invalid token](/assets/images/writeups/Heal-HTB/10.png)

While connecting the dots between `heal.htb` and `api.heal.htb`, I found that `Authorization-Bearer` is being used in login panel on `heal.htb`. 

![Authorization Bearer](/assets/images/writeups/Heal-HTB/11.png)

I have used the `authorization bearer` for the `http://api.heal.htb/download`. The API didn't gave the same `invalid-token` error. 

![Success for authorization bearer](/assets/images/writeups/Heal-HTB/12.png)

I think `/download` may use endpoint to download the file. I remembered that when I have exported the PDF and intercepted the web request, the response consisted of `filename` as parameter which stored the PDF name.

![Filename parameter](/assets/images/writeups/Heal-HTB/13.png)

I have used the `/download` directory and `filename` as endpoint to read a random file using `authorization bearer` as token.

![File not found](/assets/images/writeups/Heal-HTB/14.png)

I was sucessfully able to browse the file on the webserver by providing file name to `filename` parameter.

I had capability to read the web server files which tunred out that the `filename` parameter is vulnerable to `Local File Inclusion`.

`LFI (Local File Inclusion)` is a type of web application vulnerability that allows an attacker to include files from the server's file system in their requests. It occurs when a web application improperly validates or sanitizes user input that is used in file paths, enabling the attacker to manipulate the file path and access sensitive files on the server.

I tried reading the content of `/etc/passwd` using `filename` parameter and it was succcessfully which ensured the `LFI`.

![/etc/passwd LFI](/assets/images/writeups/Heal-HTB/15.png)

I did some Googling and found some interesting file paths for `Rails` configuration.

![Rail Configuration](/assets/images/writeups/Heal-HTB/16.png)

I tried reading `/config/database.yml` file and it revealed the storage file path which consists of `.sqlite3` file.

![Database.yml](/assets/images/writeups/Heal-HTB/17.png)

I used `wget` to download the `.sqlite3` file to local machine.

![.sqlite3 download](/assets/images/writeups/Heal-HTB/18.png)

I imported `.sqlite3` and found `administrator(ralph)` user credentials.

![Administrator's hash](/assets/images/writeups/Heal-HTB/19.png)

I used `john` to crack the bcrypt hash and I found the `ralph's` password.

![Ralph's password](/assets/images/writeups/Heal-HTB/20.png)

I used the combination of `ralph's` credential on `Resume Builder` as well as `LimeSurvey`. Both the login was successfull but interestingly I got logged into `LimeSurvey's` admin panel.

![LimeSurvey Admin Panel](/assets/images/writeups/Heal-HTB/21.png)

While browsing the `LimeSurvey` admin panel, I found it's running version was `6.6.4`.

![LimeSurvey Version](/assets/images/writeups/Heal-HTB/22.png)

I Googled for a while and came across `LimeSurvey RCE` but that was vulnerable to version till 5.X but I wanted to try it as the vulnerable endpoint is `/index.php/admin/authentication/sa/login`. 

`LimeSurvey RCE` allows attacker to upload php reverse shell in the form of plugin which can be created by the administrator.

I found one [__exploit __](https://github.com/Y1LD1R1M-1337/Limesurvey-RCE) which I used and it worked for me.























Writeup will be uploaded soon...

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t).