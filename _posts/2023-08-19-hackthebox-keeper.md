---
title: HackTheBox Keeper Writeup
authors: Samarth
date: 2023-08-24 16:00:00 +0530
categories: [HackTheBox Machines]
tags: [KeePass, Linux, CVE-2023-32784]
math: true
mermaid: true
---

![Keeper - HTB](/assets/images/writeups/Keeper-HTB/banner.png)

## TL:DR

This write-up is based on the [__Keeper__](https://app.hackthebox.com/machines/Keeper) machine, which is an easy-rated Linux box on Hack the Box. The machine hosts a Best Practical open-source ticketing system accessible via an HTTP service. By utilizing default credentials, unauthorized access to the Admin panel was achieved. Additionally, a privileged user's password was discovered, allowing for user-level SSH login.

Within the compromised environment, a memory dump and database file of KeePass were found. Exploiting the `CVE-2023-32784` vulnerability in KeePass provided the master password necessary to access the database dump. With this database dump, a Putty Private Key was extracted, subsequently converted into OpenSSH format. This key was then used to escalate privileges and gain root access.

## Scanning Network

I began with an Nmap scan and identified open ports 22 and 80 for SSH and nginx, respectively. By extracting banners using Nmap, we determined that the nginx version is 1.18.0. Let's review the Nmap results.

```bash
Command - nmap -sV -sC -A <ip address>

Nmap scan report for 10.10.11.227
Host is up (0.15s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
|_  256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We have discovered two services: SSH and HTTP. Let's begin by enumerating the HTTP service. Allow us to delve into the enumeration phase.

## Enumeration

Let's see the IP on the browser.

![Browser](/assets/images/writeups/Keeper-HTB/1.png)

We have observed that IP address gives us a reference to a domain name `tickets.keeper.htb`. So, we have to add this domain to `"/etc/hosts"` file.

Let's open [http://tickets.keeper.htb/rt/](https://tickets.keeper.htb/rt/).

![Ticket System](/assets/images/writeups/Keeper-HTB/2.png)

There is a login page which redirects you to ticket system on successful login.

We have observed the `Best Practical`, which is an open-source ticketing system and it also disclosed its version as `RT 4.4.4`.

We can search for public exploits and default credentials used by the ticket system.

## Exploitation

We have found some exploits but that are non-exploitable in our situation because those exploits are exploiting the functionality of ticket system after login. 

Let's try to search for default credentials for this ticket system.

![Default Creds](/assets/images/writeups/Keeper-HTB/3.png)

We got the default credentials as `root:password`. Let's try to login.

![Successful login](/assets/images/writeups/Keeper-HTB/4.png)

We have successfully logged in ticket system as `root`, it means we can browse the ticket system and try to find information. We have access to view privileged users and their information.

![Viewing information](/assets/images/writeups/Keeper-HTB/5.png)

We have found a user named `Lise Nørgaard`. Let's select this user and view the information.

![Found user details](/assets/images/writeups/Keeper-HTB/6.png)

We have found many information about the user. We have found the `username`, `email`, `language` and `password` (in comment section).

It seems admin created this user recently and assigned with a initial password. If we notice, we have `SSH` service running on. Possibly this password can be used to access the system as `lnorgaard`. 

We will try to use this password (`Welcome2023!`) to login into system as `lnorgaard` via SSH.

![Got password](/assets/images/writeups/Keeper-HTB/7.png)

We have successfully logged into the system as `lnorgaard`. Let's perform listing of directory.

![Logged in as user](/assets/images/writeups/Keeper-HTB/8.png)

We found a compressed file. Let's try to compress it.

![Found compressed file](/assets/images/writeups/Keeper-HTB/9.png)

We have observed that compressed file contains a memory dump of KeePass process as well as KeePass database. Now, we need a master password to unlock the KeePass password database. We will get those file to our local system. Let's try to search for KeePass vulnerability which is related to cracking master password.

I have found a CVE which is related to recover master password.

### CVE-2023-32784

In KeePass 2.x before 2.54, it is possible to recover the cleartext master password from a memory dump, even when a workspace is locked or no longer running. The memory dump can be a KeePass process dump, swap file (pagefile.sys), hibernation file (hiberfil.sys), or RAM dump of the entire system. The first character cannot be recovered. In 2.54, there is different API usage and/or random string insertion for mitigation.

We will search for available exploit to recover the master password from a memory dump.

I have found a github based tool which can be used to find the master password. 

```plaintext
https://github.com/CMEPW/keepass-dump-masterkey
```

Let's use the tool which is made by [@CMEPW](https://github.com/CMEPW).

I have used the available exploit using the available KeePass memory dump. I have found a pattern of password.

![KeePass memory dump](/assets/images/writeups/Keeper-HTB/10.png)

We will use this password to login as `root` via SSH.

![Tried root login](/assets/images/writeups/Keeper-HTB/11.png)

We were not able to login. Let's try to search this password on Google.

![Searched on Google](/assets/images/writeups/Keeper-HTB/12.png)

TThe password we obtained using the tool leads to `rødgrød med fløde`, which is a Danish dessert. It's worth noting that the user we discovered on the ticket system, `lnorgaard`, is known to speak Danish.`NOTE - It's an unusal way to obtain a password`.

We will use this password to login as a root.

![Found password](/assets/images/writeups/Keeper-HTB/13.png)

We have to find a way to use this password to login. Let's search on Google to use master password to access `passcodes.kbdx`.

I have found a command line interface shell called `kpcli` to access the database file.

To instal `kpcli`, use the below command -

```bash
sudo apt-get install kpcli libterm-readline-gnu-perl libdata-password-perl
```

![KeePass CLI](/assets/images/writeups/Keeper-HTB/14.png)

We have option to open database file and we can use the found master password to access it.

![Opening database file](/assets/images/writeups/Keeper-HTB/15.png)

We have successfully able to access database file. Let's access each directory.

![Accessed database file](/assets/images/writeups/Keeper-HTB/16.png)

We have found Putty-User-Key-File-3 of `root` user. We need to convert PuTTY private key format t an OpenSSH format. We have to save the key in `key.ppk`.

![Found PPK file](/assets/images/writeups/Keeper-HTB/17.png)

Let's use `puttygen` to convert `key.ppk`OpenSSH format.

Command - 
```bash
puttygen key.ppk -O private-openssh -o id_rsa
```
We will use this `id_rsa` to login as root via SSH.

![Logged in as a root user](/assets/images/writeups/Keeper-HTB/18.png)

That's all in this writeup.

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t).