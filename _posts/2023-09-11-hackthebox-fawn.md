---
title: HackTheBox - Faw
authors: Samarth
date: 2023-09-11 14:00:00 +0530
categories: [HackTheBox , Starting Point - Tier 0]
tags: [Linux, FTPd, Reconnaissance, Anonymous/Guest Access]
math: true
mermaid: true
---

![Fawn-HTB](/assets/images/starting-point/Fawn-HTB/banner.png)

## TL;DR

This writeup is based on the [__Fawn__](https://app.hackthebox.com/starting-point){:target="_blank"} machine, which is an easy-rated Linux box on Hack the Box. I began by scanning the target and found an open FTP port (21) running vsFTPd 3.0.3. The FTP service allowed anonymous login, so I logged in without a password and found a file named `flag.txt` in the directory listing. I downloaded the file, read its contents, and captured the flag.

## Scanning Network

I began by performing an Nmap scan, which revealed open ports 21 , corresponding to FTP. Here are the results from Nmap scan:

```bash
nmap -sC -sV -A -T4 -Pn 10.129.1.14 -oN scan/normal.scan
Starting Nmap 7.94 ( https://nmap.org ) at 2025-02-15 11:00 IST
Nmap scan report for 10.129.1.14
Host is up (0.21s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0              32 Jun 04  2021 flag.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.6
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
Service Info: OS: Unix
```

## Enumeration

`vsFTPd 3.0.3` is an outdated version of the FTP service.

`FTP` (File Transfer Protocol) is a network protocol used to transfer files between a client and a server over a TCP/IP network. FTP allows users to upload, download, and manage files on a remote server. However, since it transmits data in plaintext, it poses security risks, especially with anonymous access, making secure alternatives like SFTP and FTPS more commonly used for sensitive data transfers.

While inspecting the Nmap scan output, I discovered that anonymous FTP login was allowed.

FTP supports both authenticated and anonymous access, where anonymous users log in with the username **anonymous** and typically don’t need a password, although some servers may request an email address.

## Exploitation

I attempted to log into FTP using the `anonymous` user.

```bash
ftp 10.129.1.14
Connected to 10.129.1.14.
220 (vsFTPd 3.0.3)
Name (10.129.1.14:samh4cks): anonymous
331 Please specify the password.
Password: 
230 Login successful.
```

I successfully logged in as the `anonymous` user, so let's read the flag.

```bash
 ftp 10.129.1.14
Connected to 10.129.1.14.
220 (vsFTPd 3.0.3)
Name (10.129.1.14:samh4cks): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||11289|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0              32 Jun 04  2021 flag.txt
226 Directory send OK.
ftp> get flag.txt
local: flag.txt remote: flag.txt
229 Entering Extended Passive Mode (|||44195|)
150 Opening BINARY mode data connection for flag.txt (32 bytes).
226 Transfer complete.
32 bytes received in 00:00 (0.14 KiB/s)
ftp> exit
221 Goodbye.
```

```bash
cat flag.txt
035db21c881520061c53e0536e44f815
```

## Tasks

### What does the 3-letter acronym FTP stand for?

```plaintext
File Transfer Protocol (FTP)
```

### Which port does the FTP service listen on usually?

```plaintext
21
```

### FTP sends data in the clear, without any encryption. What acronym is used for a later protocol designed to provide similar functionality to FTP but securely, as an extension of the SSH protocol?

```plaintext
SFTP
```

### What is the command we can use to send an ICMP echo request to test our connection to the target?

```plaintext
ping
```

### From your scans, what version is FTP running on the target?

```plaintext
vsFTPd 3.0.3
```

### From your scans, what OS type is running on the target?

```plaintext
Unix
```

### What is the command we need to run in order to display the 'ftp' client help menu?

```plaintext
ftp -?
```

### What is username that is used over FTP when you want to log in without having an account?

```plaintext
anonymous
```

### What is the response code we get for the FTP message 'Login successful'?

```plaintext
230
```

### There are a couple of commands we can use to list the files and directories available on the FTP server. One is dir. What is the other that is a common way to list files on a Linux system.

```plaintext
ls
```

### What is the command used to download the file we found on the FTP server?

```plaintext
get
```

### Submit root flag

```plaintext
035db21c881520061c53e0536e44f815
```

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.

