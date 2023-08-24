---
title: Keeper - HackTheBox
authors: Samarth
date: 2023-08-19 16:00:00 +0530
categories: [HackTheBox]
tags: [KeePass, Linux, Samba]
pin: true
math: true
mermaid: true
---

![](/assets/images/writeups/Keeper-HTB/banner.png)

This writeup is based on Keeper on Hack the box.

## TL:DR

This writeup is based on [__Keeper__](https://app.hackthebox.com/machines/Keeper) which is an easy-rated machine on Hack the box. It was a Linux box.  There is a Best Practical open-source ticketing system running on HTTP service. By using default credentials, it leads to access of Admin panel. Found one privileged user's password to logged in as a user via SSH. There is a KeePass memory dump and database file available and the KeePass is vulnerable of `CVE-2023-32784` which gaves the master password to access the database dump. Using the database dump, we got Putty Private Key which is converted into OpenSSH format to login as a root.

## Scanning Network

I started with a Nmap scan, I found ports 22, 80 as SSH, nginx respectively. By Nmap’s banner grabbing, we got the nginx version that is 1.18.0. Let’s see the Nmap result.

```javascript
Command - nmap -sV -sC -A <ip address>
```

```bash
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
We have found two services, SSH and HTTP. First, we will enumerate HTTP. Let's jump into it in enumeration phase.

## Enumeration

Let's see the IP on the browser.

![](/assets/images/writeups/Keeper-HTB/1.png)

We have observed that IP address redirects us on the domain `tickets.keeper.htb`. So, we have to add this domain to `"/etc/hosts"` file.

We will try to open [http://tickets.keeper.htb/rt/](http://tickets.keeper.htb/rt/).

![](/assets/images/writeups/Keeper-HTB/2.png)

There is a login page which redirects you to ticket system on successful login.

We have observed the `Best Practical`, which is an open-source ticketing system and it also disclosed its version as `RT 4.4.4`.

We can search for public exploits and default credentials used by the ticket system.

## Exploitation

We have found some exploits but that are non-exploitable in our situation because those exploits are exploiting the functionality of ticket system after login. 

Let's try to search for default credentials for this ticket system.

![](/assets/images/writeups/Keeper-HTB/3.png)

We got the default credentials as `root:password`. Let's try to login.

![](/assets/images/writeups/Keeper-HTB/4.png)

We have successfully logged in ticket system as `root`, it means we can browse the ticket system and try to find information. We have access to view privileged users and their information.

![](/assets/images/writeups/Keeper-HTB/5.png)

We have found a user named `Lise Nørgaard`. Let's select this user and view the information.

![](/assets/images/writeups/Keeper-HTB/6.png)

We have found many information about the user. We have found the `username`, `email`, `language` and `password` (in comment section).

It seems admin created this user recently and assigned with a initial password. If we notice, we have `SSH` service running on. Possibly this password can be used to access the system as `lnorgaard`. 

We will try to use this password (`Welcome2023!`) to login into system as `lnorgaard` via SSH.

![](/assets/images/writeups/Keeper-HTB/7.png)

We have successfully logged into the system as `lnorgaard`. Let's perform listing of directory.

![](/assets/images/writeups/Keeper-HTB/8.png)

We found a compressed file. Let's try to compress it.

![](/assets/images/writeups/Keeper-HTB/9.png)

We have observed that compressed file contains a memory dump of KeePass process as well as KeePass database. Now, we need a master password to unlock the KeePass password database. We will get those file to our local system. Let's try to search for KeePass vulnerability which is related to cracking master password.

I have found a CVE which is related to recover master password.

### CVE-2023-32784

In KeePass 2.x before 2.54, it is possible to recover the cleartext master password from a memory dump, even when a workspace is locked or no longer running. The memory dump can be a KeePass process dump, swap file (pagefile.sys), hibernation file (hiberfil.sys), or RAM dump of the entire system. The first character cannot be recovered. In 2.54, there is different API usage and/or random string insertion for mitigation.

We will search for available exploit to recover the master password from a memory dump.

I have found a github based tool which can be used to find the master password. 

```html
https://github.com/CMEPW/keepass-dump-masterkey
```

Let's use the tool which is made by [@CMEPW](https://github.com/CMEPW).

I have used the available exploit using the available KeePass memory dump. I have found a pattern of password.

![](/assets/images/writeups/Keeper-HTB/10.png)

We will use this password to login as `root` via SSH.

![](/assets/images/writeups/Keeper-HTB/11.png)

We were not able to login. Let's try to search this password on Google.

![](/assets/images/writeups/Keeper-HTB/12.png)

The password we found using the tool leads to `rødgrød med fløde` which is a Danish dessert. If we remember, user we found on ticket system, `lnorgaard` use to speak Danish Language. `NOTE - It's an unusal way to obtain a password`.

We will use this password to login as a root.

![](/assets/images/writeups/Keeper-HTB/13.png)

We have to find a way to use this password to login. Let's search on Google to use master password to access `passcodes.kbdx`.

I have found a command line interface shell called `kpcli` to access the database file.

To instal `kpcli`, use the below command -

```bash
sudo apt-get install kpcli libterm-readline-gnu-perl libdata-password-perl
```

![](/assets/images/writeups/Keeper-HTB/14.png)

We have option to open database file and we can use the found master password to access it.

![](/assets/images/writeups/Keeper-HTB/15.png)

We have successfully able to access database file. Let's access each directory.

![](/assets/images/writeups/Keeper-HTB/16.png)

We have found Putty-User-Key-File-3 of `root` user. We need to convert PuTTY private key format t an OpenSSH format. We have to save the key in `key.ppk`.

![](/assets/images/writeups/Keeper-HTB/17.png)

Let's use `puttygen` to convert `key.ppk`OpenSSH format.

Command - 
```bash
puttygen key.ppk -O private-openssh -o id_rsa
```
We will use this `id_rsa` to login as root via SSH.

![](/assets/images/writeups/Keeper-HTB/18.png)

That's all in this writeup.

Thanks for reading this far. Hope you liked it.If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t).












