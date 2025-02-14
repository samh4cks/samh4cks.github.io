---
title: HackTheBox EscapeTwo Writeup
authors: Samarth
date: 2025-01-19 18:00:00 +0530
categories: [HackTheBox, Machines]
tags: [Windows, Active Directory, SMB, LDAP, MS-SQL]
math: true
mermaid: true
---

![Cicada - HTB](/assets/images/writeups/EscapeTwo-HTB/banner.png)

## TL;DR



## Scanning Network

I started with an Nmap scan and found ports 53, 88, 135, 139, 389, 445, 464, 593, 636, 1433, 3268, and 3269 open, corresponding to Simple DNS Plus, Kerberos, MSRPC, NetBIOS-SSN, LDAP, Microsoft-DS, Kpasswd5, RPC over HTTP, SSL/LDAP, MS SQL and Active Directory services. The host appears to be a Windows domain controller (`DC01`) with Active Directory services, including LDAP and SMB, potentially offering attack vectors. Let's see the Nmap results.

```bash
nmap -sC -sV -A -T4 -Pn 10.10.11.51 -oN scan/normal.scan
Starting Nmap 7.94 ( https://nmap.org ) at 2025-02-13 20:29 IST
Nmap scan report for 10.10.11.51
Host is up (0.22s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-13 15:00:14Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-13T15:01:38+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-13T15:01:38+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.10.11.51:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2025-02-13T15:01:38+00:00; 0s from scanner time.
| ms-sql-ntlm-info: 
|   10.10.11.51:1433: 
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-02-13T13:21:31
|_Not valid after:  2055-02-13T13:21:31
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-13T15:01:38+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-13T15:01:38+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-02-13T15:01:01
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

Starting enumeration with SMB is crucial because it often reveals shared resources, sensitive files, and user information, making it a rich source of data in Windows environments. Additionally, SMB frequently suffers from misconfigurations and vulnerabilities, providing potential attack vectors for further exploitation.

## Enumeration

In the enumeration phase, the focus will be on enumerating `SMB/NetBIOS` on ports 139 and 445.

We will use `smbclient` to list the shares on the target.


