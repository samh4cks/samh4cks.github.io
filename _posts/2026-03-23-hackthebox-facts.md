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