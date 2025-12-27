---
title: HackTheBox - Appointment
authors: Samarth
categories: [HackTheBox , Starting Point - Tier 1]
tags: [Linux, Databases, Apache, MariaDB, PHP, SQL, Reconnaissance, SQL Injection]
math: true
mermaid: true
---

![Appointment-HTB](/assets/images/starting-point/Appointment-HTB/banner.png)

## TL;DR

This writeup is based on the [__Appointment__](https://app.hackthebox.com/starting-point){:target="_blank"} machine, an easy-rated Linux box on Hack The Box. After scanning the target, I found that port `80` was open, running `Apache httpd 2.4.38`. Visiting the website revealed a login page, so I performed directory fuzzing but found no useful files. I then attempted common login credentials but was unsuccessful. Next, I tested for SQL injection vulnerabilities and found that the login form was vulnerable. Using a simple SQL injection payload, I bypassed authentication and gained access, revealing a flag on the webpage.

## Scanning Network

I began by performing an Nmap scan, which revealed open port `80`, corresponding to `Apache httpd 2.4.38`. Here are the results from the Nmap scan:

```bash
nmap -sC -sV -A -T4 -Pn 10.129.12.234 -oN scan/normal.scan
Starting Nmap 7.94 ( https://nmap.org ) at 2025-02-16 16:09 IST
Nmap scan report for 10.129.12.234
Host is up (0.21s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Login
|_http-server-header: Apache/2.4.38 (Debian)
```

## Enumeration

Let's visit `http://10.129.12.234/`.

![Target Site](/assets/images/starting-point/Appointment-HTB/1.png)

I came across a login page, so before investigating the login form, I will start directory fuzzing.

```bash
gobuster dir -u http://10.129.12.234/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt -o gobuster.dir-fuzz
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.12.234/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 315] [--> http://10.129.12.234/images/]
/js                   (Status: 301) [Size: 311] [--> http://10.129.12.234/js/]
/css                  (Status: 301) [Size: 312] [--> http://10.129.12.234/css/]
/fonts                (Status: 301) [Size: 314] [--> http://10.129.12.234/fonts/]
/vendor               (Status: 301) [Size: 315] [--> http://10.129.12.234/vendor/]
/server-status        (Status: 403) [Size: 278]
Progress: 17770 / 17771 (99.99%)
===============================================================
Finished
===============================================================
```

I didn't find any interesting directories or files during directory fuzzing, so let's now investigate the login page.

## Exploitation

The first step in attacking a login page is to test for weak or default credentials such as:

```plaintext
admin:admin
admin:password
administrator:password
root:root
```

After attempting all the above combinations, I was still unable to log in. The next logical step is to test for **SQL Injection** vulnerabilities.

![SQL Query](/assets/images/starting-point/Appointment-HTB/2.png)

Since the website is likely built using PHP, we can try SQL injection payloads in the username and password fields to check if they are vulnerable.

In PHP, the `#` symbol is used to comment out the rest of a SQL query. This can be exploited to bypass authentication.

![username vulnerable to SQL](/assets/images/starting-point/Appointment-HTB/3.png)

After submitting the form, we get a page like this:

![Flag](/assets/images/starting-point/Appointment-HTB/4.png)

Successfully, I have got the flag.

```plaintext
e3d0796d002a446c0e622226f42e9672
```

## Tasks

### What does the acronym SQL stand for?

```plaintext
Structed Query Language
```

### What is one of the most common type of SQL vulnerabilities?

```plaintext
SQL Injection
```

### What is the 2021 OWASP Top 10 classification for this vulnerability?

```plaintext
A03:2021-Injection
```

### What does Nmap report as the service and version that are running on port 80 of the target?

```plaintext
Apache httpd 2.4.38 ((Debian))
```

### What is the standard port used for the HTTPS protocol?

```plaintext
443
```

### What is a folder called in web-application terminology?

```plaintext
directory
```

### What is the HTTP response code is given for 'Not Found' errors?

```plaintext
404
```

### Gobuster is one tool used to brute force directories on a webserver. What switch do we use with Gobuster to specify we're looking to discover directories, and not subdomains?

```plaintext
dir
```

### What single character can be used to comment out the rest of a line in MySQL?

```plaintext
#
```

### If user input is not handled carefully, it could be interpreted as a comment. Use a comment to login as admin without knowing the password. What is the first word on the webpage returned?

```plaintext
Congratulations
```

### Submit root flag

```plaintext
e3d0796d002a446c0e622226f42e9672
```

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.