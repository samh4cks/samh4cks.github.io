---
title: HackTheBox - Sau
authors: Samarth
date: 2023-08-26 10:00:00 +0530
categories: [HackTheBox, Machines]
tags: [Linux, SSRF, OS Command Injection, CVE-2023-27163]
math: true
mermaid: true
---

![Sau - HTB](/assets/images/writeups/Sau-HTB/banner.png)

## TL:DR

This write-up is based on the [__Sau__](https://app.hackthebox.com/machines/Sau){:target="_blank"} machine, which is an easy-rated Linux box on Hack the Box. The machine hosts a service called `Request Baskets` accessible on port 55555. The version of Request Baskets used by the machine is vulnerable to `CVE-2023-27163` via `Server-Side Request Forgery (SSRF)`, enabling access to the Maltrail system running on the localhost. The Maltrail system used by the machine is outdated and susceptible to `Unauthenticated OS Command Injection`, leading to the acquisition of a user shell. By exploiting the privilege escalation of the `sudo systemctl` service manager, we were able to attain root access on the machine.

## Scanning Network

I began with an Nmap scan and identified open ports 22 and 55555 for SSH and `Request Baskets` (HTTP requests collector to test webhooks), respectively. By extracting banners using Nmap, we determined that the Request Baskets version is 1.2.1. Let's review the Nmap results.

```bash
Command - nmap -sC -sV -A <ip address>

Nmap scan report for 10.10.11.224
Host is up (0.17s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
|_  256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
55555/tcp open     unknown
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Sat, 26 Aug 2023 05:37:38 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Sat, 26 Aug 2023 05:37:10 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Sat, 26 Aug 2023 05:37:10 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port55555-TCP:V=7.94%I=7%D=8/26%Time=64E98F84%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,A2,"HTTP/1\.0\x20302\x20Found\r\nContent-Type:\x20text/html;\
SF:x20charset=utf-8\r\nLocation:\x20/web\r\nDate:\x20Sat,\x2026\x20Aug\x20
SF:2023\x2005:37:10\x20GMT\r\nContent-Length:\x2027\r\n\r\n<a\x20href=\"/w
SF:eb\">Found</a>\.\n\n")%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Re
SF:quest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x
SF:20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,60,"HTTP/1\.0\x202
SF:00\x20OK\r\nAllow:\x20GET,\x20OPTIONS\r\nDate:\x20Sat,\x2026\x20Aug\x20
SF:2023\x2005:37:10\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest
SF:,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;
SF:\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request"
SF:)%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20tex
SF:t/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20
SF:Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCon
SF:tent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\
SF:r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x20400\
SF:x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nC
SF:onnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,67,"
SF:HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20c
SF:harset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(K
SF:erberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text
SF:/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20R
SF:equest")%r(FourOhFourRequest,EA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\n
SF:Content-Type:\x20text/plain;\x20charset=utf-8\r\nX-Content-Type-Options
SF::\x20nosniff\r\nDate:\x20Sat,\x2026\x20Aug\x202023\x2005:37:38\x20GMT\r
SF:\nContent-Length:\x2075\r\n\r\ninvalid\x20basket\x20name;\x20the\x20nam
SF:e\x20does\x20not\x20match\x20pattern:\x20\^\[\\w\\d\\-_\\\.\]{1,250}\$\
SF:n")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:
SF:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20
SF:Bad\x20Request")%r(LDAPSearchReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request
SF:\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20clo
SF:se\r\n\r\n400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We have discovered two services: SSH and Request Baskets. Let's begin by enumerating the Request Baskets. Allow us to delve into the enumeration phase.

## Enumeration

Let's see IP on the browser.

![Browser View](/assets/images/writeups/Sau-HTB/1.png)

We have noticed the usage of `Request Baskets`. [__Request Baskets__](https://rbaskets.in/){:target="_blank"} is a web service designed to gather arbitrary HTTP requests and allow inspection via a RESTful API or a simple web UI.

Upon further enumeration, we found that the version of `Request Baskets` in use is `1.2.1`.

However, the most recent version of `Request Baskets` is `1.2.3`. Given the usage of an outdated version, it's worth considering the possibility of searching for public exploits.

## Exploitation

We have found one exploit that uses Request Baskets's version 1.2.1 and it is vulnerable to [__CVE-2023-27163__](https://nvd.nist.gov/vuln/detail/CVE-2023-27163){:target="_blank"} via `Server-Side Request Forgery (SSRF)`.

We will look for the available exploit for this CVE. 

### Server-Side Request Forgery (SSRF)

`CVE-2023-27163` - Request-Baskets upto v1.2.1 was discovered to contain a Server-Side Request Forgery (SSRF) via the component `/api/baskets/{name}`. This vulnerability allows attackers to access network resources and sensitive information via a crafted API request.

You can find the details here about [__CVE-2023-27163__](https://gist.github.com/b33t1e/3079c10c88cad379fb166c389ce3b7b3){:target="_blank"}.

Let's navigate to the website and create a new basket, capturing the request in Burp Suite.

![Creating new basket](/assets/images/writeups/Sau-HTB/2.png)

I have created a Python based tool called [CVE-2023-27163-InternalProber](https://github.com/samh4cks/CVE-2023-27163-InternalProber){:target="_blank"} which will perform port scanning on the internal IP and try to find the open ports for us.

The tool will generate a random basket and then configure the basket in a loop for each port, and then determine all the open ports.

Let's begin by executing the tool.

![Using automation tool](/assets/images/writeups/Sau-HTB/14.png)

The tool requires a target URL to perform the actions.

![Provided target URL](/assets/images/writeups/Sau-HTB/15.png)

We've noticed that the tool created the new basket along with authorization token and has identified port 80 as open and provided the internal URL.

Now, we have to add a payload with the API call. 

```bash
   {
  "forward_url": "http://127.0.0.1:80",
  "proxy_response": false,
  "insecure_tls": false,
  "expand_path": false,
  "capacity": 250
   }
```

The provided payload indicates that whenever a user requests the desired basket, the request will be forwarded or redirected to the localhost of the system.

We need to edit `proxy_response` as `true`. I will explain why I set `proxy_response` to `true`. After reading the docs for request-baskets, I got a general concept of what it is and how it's supposed to work. If you set a Forward URL, it catches your request in a basket and forwards it to the URL you set. And if you set Proxy response to true, when you request basket URL, not only will it forward your request to Forward URL, but it will show you response in the browser. 

![Proxy setting](/assets/images/writeups/Sau-HTB/3.png)

Let's send this request and wait for the response.

![Found response](/assets/images/writeups/Sau-HTB/4.png)

We obtain an authentication token in the response. When someone wishes to access the basket, they will be prompted to input the token for authentication purposes. 

Let's view the basket we created.

![Viewing basket](/assets/images/writeups/Sau-HTB/5.png)

We can observe that all request will be collected by basket on [http://10.10.11.224:55555/samh4cks](https://10.10.11.224:55555/samh4cks){:target="_blank"}.

Let's visit the website of our own basket.

![Visiting basket](/assets/images/writeups/Sau-HTB/6.png)

We have observed that we got forwarded on the localhost of the system and we found `Maltrail` hosted on the localhost. Its version is disclosed as `v0.53`. 

I have searched on Google for the latest version of `Maltrail`, which is `v0.60`. This indicates that the version used by the machine is outdated. Let's search for available vulnerabilities for this specific version.

I have found that this version is vulnerable to `Unauthenticated OS Command Injection (RCE)`.

### Unauthenticated OS Command Injection (RCE)

The vulnerability exists in the login page and can be exploited via the `username` parameter.

The username parameter of the login page doesn't properly sanitize the input, allowing an attacker to inject OS commands.

The service uses the subprocess.check_output() function to execute a shell command that logs the username provided by the user. If an attacker provides a specially crafted username, they can inject arbitrary shell commands that will be executed on the server.

I have found an exploit available on [ExploitDB](https://www.exploit-db.com/exploits/51676){:target="_blank"}.

I am going to use the above exploit but before that I have to change the `forward URL` in our basket configuration.

![Changing parameter](/assets/images/writeups/Sau-HTB/7.png)

We have used the `login` page because `username` parameter in the login page is vulnerable to `OS command Injection`.

Now, I have to modify the exploit by removing the `/login` parameter because we already implemented it in our forward URL.

![Removing parameter](/assets/images/writeups/Sau-HTB/8.png)

Now, we are ready to use the exploit to perform `OS Command Injection`. The usage of exploit is to provide `listening IP`, `listening port` and `target URL`.

Let's setup a listener to capture the response.

![Setup listener](/assets/images/writeups/Sau-HTB/9.png)

Let's use the exploit and wait for the response on the listener.

![Response](/assets/images/writeups/Sau-HTB/10.png)

We have observed that the exploit is running successfully so let's check the listener.

![We got shell](/assets/images/writeups/Sau-HTB/11.png)

We successfully performed `OS Command Injection` and got the user shell.

Let's list the allowed commands to invoking the user using `sudo -l`.

![Listing all allowed commands](/assets/images/writeups/Sau-HTB/12.png)

We noted that the ability to access the status of `trail.service` using `systemctl` is permitted. Let's search for information on `sudo systemctl privilege escalation` on Google.

I have found a great resource for privilege escalation of sudo systemctl [Exploit Notes](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-systemctl-privilege-escalation/){:target="_blank"}.

I have found a way to spawn shell in the pager using the above resource. 

![Spawn shell](/assets/images/writeups/Sau-HTB/13.png)

[![Pwned](/assets/images/writeups/Sau-HTB/pwned.png)](https://www.hackthebox.com/achievement/machine/337503/551){:target="_blank"}

That's all in this writeup.

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.