#!/usr/bin/python2
#
# Chaosmap
#
# Chaosmap is an information gathering tool and 
# dns / whois / web server scanner.
# For wider description and example usages see the README
#
# Coded by Balle
# http://www.datenterrorist.de
# License GPLv3

version = "1.2"

###[ Import modules

import sys
import getopt
import re
import socket
from random import randint
from time import sleep
import urllib2

sys.path.append('lib')
import httplib2
import socks
from cymruwhois import Client as WhoisClient
import google

#httplib2.debuglevel=4


###[ Globals

domains = None
dict_files = None
start_ip = None
stop_ip = None
web_proxy = None
web_port = "80"
base_url = ""
web_user = None
web_pass = None
proxy_user = None
proxy_pass = None
delay = 0
name_lookup = False
salt = False
urlencode = False
shut_up = False
web_lookup = False
email_lookup = False
google_dict_search = False
google_query_dict = False
whois = False
whois_client = WhoisClient()
web_client = httplib2.Http()


###[ Subroutines

def usage():
	"""
	Guess what ;)
	"""
	print "Chaosmap " + version
	print "Coded by Bastian Ballmann"
	print "http://www.datenterrorist.de\n"
	print "Usage: " + sys.argv[0] + """
	-b <base_url>
	-c <web_user:password>
	-C <proxy_user:password>
	-d <domains,domain2,domain3> 
	-D <delay_in_sec>
	-e(mail_search)
	-f <dict_file,ddict_files,dict_file3> 
	-g(oogle_dict_search)
	-G(oogle_only)
	-h(elp)
	-i <start_ip>-<stop_ip> 
	-n(ame_lookup) 
	-p <webserver_port> 
	-P <proxy_ip:port>
	-q(uiet)
	-Q (input in dict are google hack queries)
	-s(alt) 
	-u(rlencode)
	-v(ersion) 
	-w(eb) 
	-W(hois)"""

	print "\nFor examples see the README"
	sys.exit(1)

def do_dns_lookup(lookup_name):
	"""
	do the actual dns lookup or print error
	"""
	try:
		print lookup_name + ": " + socket.gethostbyname(lookup_name)
	except socket.gaierror, e:
		print lookup_name + ": " + str(e)

def do_url_encoding(path):
	hex = '%'.join(["%02x" % ord(x) for x in path])
	return '%' + hex

def dns_dict_lookup():
	"""
	make a dns dictionay lookups
	if salt is true construct names like www2 www-2 www02 
	"""
	for file in dict_files.split(","):
		try:
			fh = open(file, "r")
			salted_dns = []

			if salt == True:
				salt_chars = ["", "0", "-", "-0", "_", "_0"]

				for chars in salt_chars:
					for i in range(1, 9):
						salted_dns.append(word.strip() + chars + str(i) + "." + domain)

			for word in fh.readlines():
				for domain in domains.split(","):
					do_dns_lookup(word.strip() + "." + domain)

					while len(salted_dns) > 0:
						i = randint(0, len(salted_dns) - 1)
						do_dns_lookup(salted_dns[i])
						del salted_dns[i]

						if delay > 0:
							sleep(delay)

			fh.close()
		except IOError:
			print "Cannot read dictionary " + file

def get_ips(start_ip, stop_ip):
	"""
	return a list all ip addresses from start_ip to stop_ip 
	"""
	ips = []
	start_dec = long(''.join(["%02X" % long(i) for i in start_ip.split('.')]), 16)
	stop_dec = long(''.join(["%02X" % long(i) for i in stop_ip.split('.')]), 16)

        while(start_dec < stop_dec + 1):
                bytes = []
                bytes.append(str(int(start_dec / 16777216)))
                rem = start_dec % 16777216
                bytes.append(str(int(rem / 65536)))
                rem = rem % 65536
                bytes.append(str(int(rem / 256)))
                rem = rem % 256
                bytes.append(str(rem))
                ips.append(".".join(bytes))
                start_dec += 1
	return ips

def dns_reverse_lookup():
	"""
	do a dns reverse lookup in random order
	"""
	ips = get_ips(start_ip, stop_ip)

	while len(ips) > 0:
		i = randint(0, len(ips) - 1)
		lookup_ip = str(ips[i])
		try:
			print lookup_ip + ": " + str(socket.gethostbyaddr(lookup_ip)[0])
		except socket.herror, e:
			print lookup_ip + ": " + str(e)
		except socket.error, e:
			print lookup_ip + ": " + str(e)

		if whois:
			info = whois_client.lookup(lookup_ip)
			print info.owner

		if delay > 0:
			sleep(delay)

		del ips[i]

def do_web_lookup(host, path):
	"""
	do the actual web lookup, maybe mixin salt and
	search the path on host with google, print the result
	"""
	url = ""
	got_google_result = False
	chars = ["/"]

	if salt == True:
		chars = ["/", "//", "/mooh/../", "/./"]

#	if base_url != "" and re.search("/$", base_url) == None:
#		base_url += "/"

	if google_dict_search:
		if not shut_up: print "Google dict search " + path + " on " + host
		google_search_string = "+site:" + host + " inurl:" + base_url + "/" + path
		if google_query_dict: google_search_string = "+site:" + host + " " + path
		results = google.search(google_search_string, stop = 3)

		try:
			for link in results:
				if re.match("^https?://" + host, link):
					print "FOUND with Google:" + link
					got_google_result = True
					break
		except KeyError:
			pass
		except urllib2.HTTPError, e:
			print "Google search failed: " + str(e)

		if not got_google_result:
			if not shut_up: print "No result"

	if web_lookup == True and (google_dict_search == False or (google_dict_search == True and got_google_result == False)):
		for char in chars:
			if web_port == "80":
				url = "http://" + host + char + base_url + path
			elif web_port == "443":
				url = "https://" + host + char + base_url + path
			else:
				url = "http://" + host + ":" + web_port + char + base_url + path

			try:
				if not shut_up: print "GET " + url
				response, content = web_client.request(url)

				if response.status == 200:
					print "FOUND " + url + " got " + response['content-location']

				if delay > 0:
					sleep(delay)

			except httplib2.ServerNotFoundError:
				print "Got error for " + url + ": Server not found"

def do_google_mail_search(site):
	"""
	search google for site and parse a list of emails
	"""
	emails = set()
	if not shut_up: print "Google search for emails on " + site
	results = google.search("+site:" + site, num = 100, tld = "de", stop = 23)

	try:
		for link in results:
			if link.find("youtube") > 0 or re.search("[html?|phtml|php|asp|jsp|txt|/][\\?$]", link) == None:
				continue

			if not shut_up: print "GET " + link
			response, content = web_client.request(link)

			if response.status == 200:
				matches = re.findall(".*?([a-zA-Z0-9\\._\\-\\+]+@.+?\\.\w{2,4})", content)

				if matches != None:
					for match in matches:
						emails.add(match)
	except KeyError:
		pass
	except urllib2.HTTPError, e:
		print "Google search failed: " + str(e)

	if len(emails) == 0:
		if not shut_up: print "No emails found for " + site
	else:
		print "Emails found for " + site + ":"
		for email in emails:
			print email

def scan_webserver():
	"""
	scan a web server for hidden paths based on a dictionary
	"""
	for file in dict_files.split(","):
		try:
			fh = open(file, "r")

			for word in fh.readlines():
				path = word.strip()

				if urlencode:
					path = do_url_encoding(path)

				if domains != None:
					for domain in domains.split(","):
						do_web_lookup(domain, path)
				else:
					ips = get_ips(start_ip, stop_ip)

					while len(ips) > 0:
						i = randint(0, len(ips) - 1)
						lookup_ip = str(ips[i])
						del ips[i]
						do_web_lookup(lookup_ip, path)

			fh.close()
		except IOError:
			print "Cannot read dictionary " + file

###[ MAIN PART

if(len(sys.argv) < 2):
	usage();

try:
	cmd_opts = "b:c:C:d:D:ef:gi:np:P:qQsuvwW"
	opts, args = getopt.getopt(sys.argv[1:], cmd_opts)
except getopt.GetoptError:
	usage()

for opt in opts:
	if opt[0] == "-b":
		base_url = opt[1]
	elif opt[0] == "-c":
			web_user, web_pass = opt[1].split(":")
	elif opt[0] == "-C":
			proxy_user, proxy_pass = opt[1].split(":")
	elif opt[0] == "-d":
		domains = opt[1]
	elif opt[0] == "-D":
		delay = int(opt[1])
	elif opt[0] == "-e":
		email_lookup = True
	elif opt[0] == "-f":
		dict_files = opt[1]
	elif opt[0] == "-g":
		google_dict_search = True
	elif opt[0] == "-h":
		usage()
	elif opt[0] == "-i":
		start_ip, stop_ip = opt[1].split('-')
	elif opt[0] == "-n":
		name_lookup = True
	elif opt[0] == "-p":
		web_port = opt[1]
	elif opt[0] == "-P":
		web_proxy = opt[1]
	elif opt[0] == "-q":
		shut_up = True
	elif opt[0] == "-Q":
		google_query_dict = True
	elif opt[0] == "-s":
		salt = True
	elif opt[0] == "-u":
		urlencode = True
	elif opt[0] == "-v":
		print version
		sys.exit(1)
	elif opt[0] == "-w":
		web_lookup = True
	elif opt[0] == "-W":
		whois = True

if web_proxy != None:
	proxy_ip, proxy_port = web_proxy.split(":")

	if proxy_ip != "" and proxy_port != "":
		proxy_info = httplib2.ProxyInfo(
			proxy_type = socks.PROXY_TYPE_HTTP,
			proxy_host = proxy_ip,
			proxy_port = int(proxy_port),
			proxy_rdns = True,
			proxy_username = proxy_user,
			proxy_password = proxy_pass
		)

		web_client = httplib2.Http(proxy_info = proxy_info)
	else:
		print "Proxy settings should be proxy_ip:port"
		sys.exit(1)

if web_user != None and web_pass != None:
	web_client.add_credentials(web_user, web_pass)

if(start_ip != None and stop_ip != None):
	if name_lookup:
		dns_reverse_lookup()
	elif web_lookup == True and dict_files != None:
		scan_webserver()
	else:
		print "You need to either specify -n for dns or -w for web server mapping"
		sys.exit(1)
elif(domains != None and dict_files != None):
	if name_lookup:
		dns_dict_lookup()
	elif web_lookup:
		scan_webserver()
	elif google_dict_search:
		scan_webserver()
	else:
		print "You need to either specify -n for dns or -w for web server mapping"
		sys.exit(1)
elif(domains != None and email_lookup):
	do_google_mail_search(domains)
else:
	usage()

# EOF dude ;)
