---
layout: protected

title: HackTheBox - CCTV
authors: Samarth
date: 2026-03-21 09:30:00 +0530
categories: [HackTheBox, Machines]
tags: [Linux, ZoneMinder, CVE-2024-51482, CVE-2025-60787, SQLi, MotionEye]
math: true
mermaid: true
---
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


<script src="/assets/js/protected/hackthebox-cctv.js"></script>
