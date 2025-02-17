---
title: HackTheBox Sequel Writeup
authors: Samarth
categories: [HackTheBox , Starting Point - Tier 1]
tags: [Linux, Reconnaissance, Vulnerability Assessment, Databases, MySQL, SQL, Weak Credentials]
math: true
mermaid: true
---

![Sequel-HTB](/assets/images/starting-point/Sequel-HTB/banner.png)

## TL;DR

This writeup is based on the [__Sequel__](https://app.hackthebox.com/starting-point){:target="_blank"} machine, an easy-rated Linux box on Hack The Box. After scanning the target, I found that port `3306` was open, running `5.5.5-10.3.27-MariaDB-0+deb10u1`. Since this was an outdated version, I attempted to log in using default MySQL credentials. The `root` account allowed access without a password. Once inside, I explored the database and found a table named `config`, which contained the flag.

## Scanning Network

I began by performing an Nmap scan, which revealed open port `3306`, corresponding to `MySQL`. Here are the results from the Nmap scan:

```bash
nmap -sC -sV -A -T4 -Pn 10.129.68.71 -oN scan/normal.scan
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-17 16:56 IST
Stats: 0:00:54 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 0.00% done
Nmap scan report for 10.129.68.71
Host is up (0.23s latency).
Not shown: 999 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
3306/tcp open  mysql?
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.3.27-MariaDB-0+deb10u1
|   Thread ID: 66
|   Capabilities flags: 63486
|   Some Capabilities: Speaks41ProtocolOld, LongColumnFlag, FoundRows, InteractiveClient, Support41Auth, SupportsTransactions, ConnectWithDatabase, IgnoreSigpipes, SupportsLoadDataLocal, ODBCClient, DontAllowDatabaseTableColumn, IgnoreSpaceBeforeParenthesis, SupportsCompression, Speaks41ProtocolNew, SupportsMultipleResults, SupportsAuthPlugins, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: T'fL+1T4C8+prmN{C{c\
|_  Auth Plugin Name: mysql_native_password
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5.0
OS details: Linux 5.0, Linux 5.0 - 5.14
```

## Enumeration

`5.5.5-10.3.27-MariaDB-0+deb10u1` is an outdated MariaDB version that may have known vulnerabilities, posing a security risk during enumeration.

Let's try to connect to the target's `MySQL` server as the default user `root`.

![mysql login](/assets/images/starting-point/Sequel-HTB/1.png)

## Exploitation

The `MySQL` login requires SSL, so let's disable SSL/TLS encryption for the connection.

![mysql login successful](/assets/images/starting-point/Sequel-HTB/2.png)

I have successfully logged in, so let's extract sensitive information.

![Flag extracted](/assets/images/starting-point/Sequel-HTB/3.png)

I extracted the flag from `config` table.

```bash
flag - 7b4bec00d1a39e3dd4e021ec3d915da8
```

## Tasks

### During our scan, which port do we find serving MySQL?

```plaintext
3306
```

### What community-developed MySQL version is the target running?

```plaintext
MariaDB
```

### When using the MySQL command line client, what switch do we need to use in order to specify a login username?

```plaintext
-u
```

### Which username allows us to log into this MariaDB instance without providing a password?

```plaintext
root
```

### In SQL, what symbol can we use to specify within the query that we want to display everything inside a table?

```plaintext
*
```

### In SQL, what symbol do we need to end each query with?

```plaintext
;
```

### There are three databases in this MySQL instance that are common across all MySQL instances. What is the name of the fourth that's unique to this host?

```plaintext
htb
```

### Submit root flag

```plaintext
7b4bec00d1a39e3dd4e021ec3d915da8
```

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.