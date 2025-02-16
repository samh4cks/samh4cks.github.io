---
title: HackTheBox Explosion Writeup
authors: Samarth
categories: [HackTheBox , Starting Point - Tier 0]
tags: [Windows, Programming, RDP, Reconnaissance, Weak Credentials]
math: true
mermaid: true
---

![Explosion-HTB](/assets/images/starting-point/Explosion-HTB/banner.png)

## TL;DR

This writeup is based on the [__Explosion__](https://app.hackthebox.com/starting-point){:target="_blank"} machine, an easy-rated Windows box on Hack the Box. After scanning the target, I found several open ports, including SMB (445) and RDP (3389). SMB enumeration did not reveal useful information, so I attempted to access the system via RDP. Initially, I encountered a certificate mismatch error, but I bypassed it and tried common usernames. The `administrator` account allowed access, granting me a remote desktop session. On the desktop, I found a `flag.txt` file, which contained the flag for the machine.

## Scanning Network

I started with an Nmap scan and found ports 135, 139, 445, 3389, open, which correspond to MSRPC, NetBIOS-SSN, Microsoft-DS, and Microsoft Terminal services. Let’s see the Nmap results.

```bash
nmap -sC -sV -A -T4 -Pn 10.129.12.69 -oN scan/normal.scan
Starting Nmap 7.94 ( https://nmap.org ) at 2025-02-15 20:16 IST
Nmap scan report for 10.129.12.69
Host is up (0.22s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=Explosion
| Not valid before: 2025-02-14T14:20:12
|_Not valid after:  2025-08-16T14:20:12
|_ssl-date: 2025-02-15T14:46:57+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: EXPLOSION
|   NetBIOS_Domain_Name: EXPLOSION
|   NetBIOS_Computer_Name: EXPLOSION
|   DNS_Domain_Name: Explosion
|   DNS_Computer_Name: Explosion
|   Product_Version: 10.0.17763
|_  System_Time: 2025-02-15T14:46:48+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-02-15T14:46:49
|_  start_date: N/A
```

## Enumeration

`Windows RPC` is used for remote procedure calls on Windows systems. It's often associated with various Windows services. I can further enumerate `RPC` service further using `rpcclient` or `wmiexec`.

`NetBION-ssn` is used for file and printer sharing in older Windows versions. NetBIOS could allow for enumeration of shares and users on the system. I can further enumerate shares, users and other information using `nmblookup` or `enum4linux`.

`Microsoft-DS` is used by modern versions of Windows for SMB (Server Message Block). I can further enumerate SMB shares, users and more using `smbclient` or `smbmap`.

`Remote Desktop Protocol (RDP)` is a proprietary protocol developed by Microsoft that provides a graphical interface for users to connect to a remote computer over a network. It is typically used for remote administration and remote desktop access. I can use `xfreerdp` or `rdesktop`.

Let's start with enumerating `SMB` shares.

```bash
smbclient -L \\\\10.129.12.69\\ --option='client min protocol=SMB2'
Password for [WORKGROUP\samh4cks]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
```

While inspecting `SMB` shares, I did not find anything interesting but `RDP` service caught my attention as it provides remote desktop access.

I will be using `xfreerdp` to connect with the computer.

```bash
xfreerdp /v:10.129.12.69
[20:46:46:526] [146371:146372] [INFO][com.freerdp.client.x11] - No user name set. - Using login name: samh4cks
[20:46:47:532] [146371:146372] [INFO][com.freerdp.crypto] - creating directory /home/samh4cks/.config/freerdp
[20:46:47:532] [146371:146372] [INFO][com.freerdp.crypto] - creating directory [/home/samh4cks/.config/freerdp/certs]
[20:46:47:532] [146371:146372] [INFO][com.freerdp.crypto] - created directory [/home/samh4cks/.config/freerdp/server]
[20:46:48:080] [146371:146372] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[20:46:48:080] [146371:146372] [WARN][com.freerdp.crypto] - CN = Explosion
[20:46:48:082] [146371:146372] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[20:46:48:082] [146371:146372] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[20:46:48:082] [146371:146372] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[20:46:48:082] [146371:146372] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.12.69:3389) 
[20:46:48:082] [146371:146372] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[20:46:48:082] [146371:146372] [ERROR][com.freerdp.crypto] - Common Name (CN):
[20:46:48:082] [146371:146372] [ERROR][com.freerdp.crypto] - 	Explosion
[20:46:48:082] [146371:146372] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.12.69:3389 (RDP-Server):
	Common Name: Explosion
	Subject:     CN = Explosion
	Issuer:      CN = Explosion
	Thumbprint:  09:0f:ce:b8:98:3a:4a:f0:b6:72:62:01:0f:a3:da:bd:c7:24:82:68:43:b4:bc:c8:df:c8:c7:28:64:8c:03:44
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
Domain:   EXPLOSION
Password: 
[20:47:00:884] [146371:146372] [ERROR][com.freerdp.core] - transport_ssl_cb:freerdp_set_last_error_ex ERRCONNECT_PASSWORD_CERTAINLY_EXPIRED [0x0002000F]
[20:47:00:884] [146371:146372] [ERROR][com.freerdp.core.transport] - BIO_read returned an error: error:0A000438:SSL routines::tlsv1 alert internal error
```

By executing the `xfreerdp /v:10.129.12.69` command, the certificate mismatch error occured so I decided to ignore the certificate and would try logging in via some default or common usernames as `admin`, `administrator`, `root`, etc.

```bash
xfreerdp /v:10.129.12.69 /u:admin /cert:ignore 
Password: 
[21:31:40:252] [169600:169601] [ERROR][com.freerdp.core] - transport_ssl_cb:freerdp_set_last_error_ex ERRCONNECT_PASSWORD_CERTAINLY_EXPIRED [0x0002000F]
[21:31:40:346] [169600:169601] [ERROR][com.freerdp.core.transport] - BIO_read returned an error: error:0A000438:SSL routines::tlsv1 alert internal error
```

For the `admin` user, `RDP` did not allow access to the computer, so I decided to try `administrator`.

```bash
xfreerdp /v:10.129.12.69 /u:administrator /cert:ignore
Password: 
[21:32:02:974] [169772:169773] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: Asia/Kolkata
[21:32:02:583] [169772:169773] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[21:32:02:583] [169772:169773] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[21:32:02:633] [169772:169773] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[21:32:02:634] [169772:169773] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
```

![RDP](/assets/images/starting-point/Explosion-HTB/1.png)

`RDP` allowed remote desktop access to `administrator` user. The desktop consist of text file named as `flag.txt` which will be containing flag.

![Flag](/assets/images/starting-point/Explosion-HTB/2.png)

## Tasks

### What does the 3-letter acronym RDP stand for?

```plaintext
Remote Desktop Protocol
```

### What is a 3-letter acronym that refers to interaction with the host through a command line interface?

```plaintext
cli
```

### What about graphical user interface interactions?

```plaintext
GUI
```

### What is the name of an old remote access tool that came without encryption by default and listens on TCP port 23?

```plaintext
telnet
```

### What is the name of the service running on port 3389 TCP?

```plaintext
ms-wbt-server
```

### What is the switch used to specify the target host's IP address when using xfreerdp?

```plaintext
/v:
```

### What username successfully returns a desktop projection to us with a blank password?

```plaintext
administrator
```

### Submit root flag

```plaintext
951fa96d7830c451b536be5a6be008a0
```