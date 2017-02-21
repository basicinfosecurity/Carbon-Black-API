import argparse
import logging
import os
import shutil
import sys
from cbapi.errors import ObjectNotFoundError
from cbapi.response import CbResponseAPI
from cbapi.response.models import Binary
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler

def main():
	__init__()
	parser = argparse.ArgumentParser(description=banner)
	parser.add_argument("-m", "--md5hash", dest="md5hash", help="MD5 hash of the binary to be downloaded")
	parser.add_argument("-l", "--list", dest="list_file", help="List file of binaries to be downloaded")
	
	opts = parser.parse_args()
	print("Retrieving file/s")
	if opts.md5hash:
		download_binary(opts.md5hash)
	elif opts.list_file:
		hash_list = open(opts.list_file, 'r')
		lines = [line.rstrip('\n') for line in hash_list]
		print("Downloading {} hashes. Reading from list file.".format(len(lines)))
		for h in lines:
			temp_text = "Downloading {}".format(h)
			root.info(temp_text)
			download_binary(h)
		hash_list.close()
	else:
		parser.parse_args(['-h'])
		print("\nPlease provide either a hash value or a list of hashes")
		
def download_binary(md5_hash):
	temp_text = "Download successful"
	try:
		binary = cb.select(Binary, md5_hash)
		filename = os.path.join(path, binary.original_filename)
		if binary.original_filename == "(unknown)":
			filename = os.path.join(path, md5_hash.upper())
		if not os.path.isfile(filename):
			shutil.copyfileobj(binary.file, open(filename, "wb"))			
		else:
			temp_text = "File exists."
	except ObjectNotFoundError:
		temp_text = "File was not found"
	root.info(temp_text)

def __init__():
	global root
	global script_message
	global cb
	global banner
	global path
	root = logging.getLogger("cbapi")
	logging.basicConfig(filename=datetime.now().strftime('dl_bin_%H_%M_%d_%m_%Y.log'), level=logging.INFO)
	#~ logging.basicConfig(level=logging.DEBUG)
	banner = "Script for downloading hashes v1"
	cb = CbResponseAPI()
	path = "files"
	if not os.path.exists(path):
		os.makedirs(path)

if __name__ == "__main__":
	sys.exit(main())
