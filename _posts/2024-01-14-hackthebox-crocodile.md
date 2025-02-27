---
title: HackTheBox Crocodile Writeup
authors: Samarth
categories: [HackTheBox , Starting Point - Tier 1]
tags: [Linux, Custom Applications, Protocols, Apache, FTP, Reconnaissance, Web Site Structure Discovery, Clear Text Credentials, Anonymous/Guest Access]
math: true
mermaid: true
---

![Crocodile-HTB](/assets/images/starting-point/Crocodile-HTB/banner.png)

## TL;DR

This writeup is based on the [__Crocodile__](https://app.hackthebox.com/starting-point){:target="_blank"} machine, an easy-rated Linux box on Hack The Box. After scanning the target, I found that ports 21 (FTP) and 80 (HTTP) were open. The FTP service allowed anonymous login, revealing two files containing usernames and passwords. Suspecting a login portal on the web service, I manually checked `/login.php` and found a login page. Using the extracted credentials, I performed a brute-force attack and successfully logged in as `admin`. This granted access to the flag.

## Scanning Network

I began by performing an Nmap scan, which revealed open port `21` and `80`, corresponding to `FTP` and `HTTP`. Here are the results from the Nmap scan:


```bash
nmap -sC -sV -A -T4 -Pn 10.129.163.51 -oN scan/normal.scan
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-17 22:55 IST
Nmap scan report for 10.129.163.51
Host is up (0.21s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.10
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp            33 Jun 08  2021 allowed.userlist
|_-rw-r--r--    1 ftp      ftp            62 Apr 20  2021 allowed.userlist.passwd
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Smash - Bootstrap Business Template
|_http-server-header: Apache/2.4.41 (Ubuntu)
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Unix
```

## Enumeration

During Nmap scan, I have found `FTP` and `HTTP` services running on the target. So, let's start with `FTP` service first.

`FTP` service running it's latest stable version as `vsftpd 3.0.3` but I can see that `Anonymous` user login is allowed so I will be log in as `anonymous` user.

```bash
ftp 10.129.163.51
Connected to 10.129.163.51.
220 (vsFTPd 3.0.3)
Name (10.129.163.51:samh4cks): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||47154|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp            33 Jun 08  2021 allowed.userlist
-rw-r--r--    1 ftp      ftp            62 Apr 20  2021 allowed.userlist.passwd
```

I have successfully logged in as `anonymous` user and found some interesting files as `allowed.userlist` and `allowed.userlist.passwd`.

Now, I have found username and password list, which gave me hint that port `80` which is having `HTTP` service might be having some login page so let's visit there.

![Target Website](/assets/images/starting-point/Crocodile-HTB/1.png)

I haven't found any login functionality in any of those tabs on website. Let's do directory fuzzing to find any login endpoint.

While checking all the technology is being used in the application, I got to know that `PHP` programming language is being used so I tried checking existence of `/login.php` and it was a success!

![Login Panel](/assets/images/starting-point/Crocodile-HTB/2.png)

## Exploitation

Now, I have list of username and password and a login page. Let's utilise the list and try to login via brute force attack.

![Login successful](/assets/images/starting-point/Crocodile-HTB/3.png)

While inspecting brute force attack, I have found one single request which has different content length and status code as `302` which means redirect.

I have used the credential to use it on `/login.php`, the credentials are:

```plaintext
admin:rKXM59ESxesUFHAd
```

![Flag](/assets/images/starting-point/Crocodile-HTB/4.png)

```plaintext
Flag - c7110277ac44d78b6a9fff2232434d16
```

## Tasks

### What Nmap scanning switch employs the use of default scripts during a scan?

```plaintext
-sC
```

### What service version is found to be running on port 21?

```plaintext
vsftpd 3.0.3
```

### What FTP code is returned to us for the "Anonymous FTP login allowed" message?

```plaintext
230
```

### After connecting to the FTP server using the ftp client, what username do we provide when prompted to log in anonymously?

```plaintext
anonymous
```

### After connecting to the FTP server anonymously, what command can we use to download the files we find on the FTP server?

```plaintext
get
```

### What is one of the higher-privilege sounding usernames in 'allowed.userlist' that we download from the FTP server?

```plaintext
admin
```

### What version of Apache HTTP Server is running on the target host?

```plaintext
Apache httpd 2.4.41
```

### What switch can we use with Gobuster to specify we are looking for specific filetypes?

```plaintext
-x
```

### Which PHP file can we identify with directory brute force that will provide the opportunity to authenticate to the web service?

```plaintext
login.php
```

### Submit root flag

```plaintext
c7110277ac44d78b6a9fff2232434d16
```

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.