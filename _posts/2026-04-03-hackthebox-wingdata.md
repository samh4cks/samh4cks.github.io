---
layout: post
title: HackTheBox - WingData
authors: Samarth
date: 2026-04-03 12:30:00 +0530
categories: [HackTheBox, Machines, Protected]
tags: [Linux, Wing FTP Server, CVE-2025-47812, CVE-2025-4517, hashcat, tarfile]
math: true
mermaid: true
protected: true
post_id: hackthebox-wingdata
---

## Scanning Network
 
I began by performing an Nmap scan, which revealed open ports 22 and 80, corresponding to `SSH` and `Apache httpd`. Here are the results from the Nmap scan:
 
```bash
nmap -sC -sV -p- -T4 -vv -oN full_port.scan 10.129.244.106
 
# Nmap 7.94SVN scan initiated Fri Apr  3 03:18:16 2026
Nmap scan report for 10.129.244.106
Host is up, received echo-reply ttl 63 (0.29s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey:
|   256 a1:fa:95:8b:d7:56:03:85:e4:45:c9:c7:1e:ba:28:3b (ECDSA)
|_  256 9c:ba:21:1a:97:2f:3a:64:73:c1:4c:1d:ce:65:7a:2f (ED25519)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.66
|_http-title: Did not follow redirect to http://wingdata.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.66 (Debian)
Service Info: Host: localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```