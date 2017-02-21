import argparse
import logging
import sys
from cbapi.auth import CredentialStore
from cbapi.errors import ServerError
from cbapi.response import CbResponseAPI
from cbapi.response import CbEnterpriseResponseAPI
from cbapi.response.models import BannedHash
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler

def main():
	init()
	parser = argparse.ArgumentParser(description=banner)
	parser.add_argument("-m", "--md5hash", dest="md5hash", help="MD5 hash of the binary to be banned")
	parser.add_argument("-t", "--text", dest="text", help="Notes for banning the binary")
	parser.add_argument("-l", "--list", dest="list_file", help="List file of binaries to be banned")
	
	opts = parser.parse_args()
	note = "Banned from API"
	
	if opts.text:
		note = opts.text
	
	if opts.md5hash:
		ban_hash(opts.md5hash, note)
	elif opts.list_file:		
		hash_list = open(opts.list_file, 'r')
		lines = [line.rstrip('\n') for line in hash_list]
		print("Banning {} hashes. Reading from list file.".format(len(lines)))
		root.info("Banning {} hashes. Reading from list file.".format(len(lines)))
		for h in lines:
			ban_hash(h, note)
		hash_list.close()
	else:
		parser.parse_args(['-h'])
		print("Please provide either a hash value or a list of hashes")

def ban_hash(md5_hash, note):
	try:
		bh = cb.create(BannedHash)
		bh.md5hash = md5_hash
		bh.text = note
		bh.save()
		root.info("Banned {0} with note: {1}".format(md5_hash, note))
	except ServerError as se:
		root.info("Unable to ban {0}: {1}".format(md5_hash, se))

def init():
	global script_message
	global cb
	global banner
	global root
	root = logging.getLogger("cbapi")
	logging.basicConfig(filename=datetime.now().strftime('ban_hash_%H_%M_%d_%m_%Y.log'), level=logging.INFO)
	#~ global creds
	#~ global server_url
	#~ global token
	banner = "Script for banning hashes v1"
	#~ creds = CredentialStore("response").get_credentials()
	#~ server_url = creds['url']
	#~ token = creds['token']
	#~ cb = CbApi(server_url, token=token, ssl_verify=False)
	cb = CbResponseAPI()	

if __name__ == "__main__":
	sys.exit(main())
