import argparse
import csv
import json
import traceback
import logging
import os
import re
import requests
import sys
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler
from urlparse import urlparse

def main():
	init()
	parser = argparse.ArgumentParser(description=banner)
	parser.add_argument("-u", "--url", dest="server_url", help="Cb Response Server URL [e.g. \"http://cb.example.com\"]")
	parser.add_argument("-t", "--token", dest="api_token", help="Cb Response API Token")
	parser.add_argument("-m", "--md5hash", dest="md5hash", help="MD5 hash of the binary to be banned")
	parser.add_argument("-n", "--notes", dest="text", help="Notes for banning the binary")
	parser.add_argument("-l", "--list", dest="list_file", help="List file of binaries to be banned. Also accepts csv files.")
	parser.add_argument("-x", "--export", help="Export ban list to csv", action='store_true')
	
	opts = parser.parse_args()
	note = "Banned from API"
	global request_url
	global headers
	#~ global data
	
	try:
		server_url = urlparse(opts.server_url)
		if not opts.server_url or (server_url.scheme != "http" and server_url.scheme != "https"):
			raise InvalidApiTokenError(sys.exc_info(), "Invalid server URL {}".format(opts.server_url))
		elif not opts.api_token or (re.match(r"([a-fA-F\d]{40})", opts.api_token) is None):
			raise InvalidApiTokenError(sys.exc_info(), "Invalid API Token {}".format(opts.api_token))
		else:
			request_url = "{0}{1}".format(server_url.geturl(), '/api/v1/banning/blacklist')
			headers = {"X-Auth-Token" : opts.api_token}
			
	except InvalidApiTokenError as iate:
		root.exception(iate)
		exit_code = iate.exit_code
	
	if opts.export:
		export_mode_msg = "Export mode. Fetching banned list from {}".format(opts.server_url)
		print(export_mode_msg)
		root.info(export_mode_msg)
		export = export_to_csv()
		if not export:
			exit_code = 1
		#~ sys.exit()
	
	if opts.text:
		note = opts.text
	
	if opts.md5hash:
		single_ban_mode_msg = "Single hash ban mode."
		print(single_ban_mode_msg)
		root.info(single_ban_mode_msg)
		b = ban_hash(opts.md5hash, note)
	elif opts.list_file:
		list_ban_mode = "Multiple hash ban mode. Reading list file"
		print(list_ban_mode)
		root.info(list_ban_mode)
		hash_list = open(opts.list_file, 'rb')
		ban_text = "Banning {} hashes. Reading from list file.".format(len(lines))
		print(ban_text)
		root.info(ban_text)
		if os.path.splitext(hash_list.name)[1] == '.csv':
			csv_reader = csv.DictReader(hash_list)
			found_msg = "Found {0} hashes in {1}".format(len(csv_reader), hash_list.name)
			print(found_msg)
			root.info(found_msg)
			for h in csv_reader:
				b = ban_hash(h['md5'], h['Note'])
		else:
			lines = [line.rstrip('\n') for line in hash_list]
			found_msg = "Found {0} hashes in {1}".format(len(lines), hash_list.name)
			print(found_msg)
			root.info(found_msg)
			for h in lines:
				b = ban_hash(h, note)
		hash_list.close()
		if md5_error_found:
			sys.exit(100)
	else:
		parser.parse_args(['-h'])
		#~ print("Please provide either a hash value or a list of hashes")
	sys.exit(exit_code)

def ban_hash(md5_hash, note):
	try:
		try:
			if re.match(r"([a-fA-F\d]{32})", md5_hash) is None:
				try:
					raise InvalidMD5Error(sys.exc_info(),"{} was not added to the list. It is not a valid md5 hash.".format(md5_hash))
				except InvalidMD5Error as ime:
					root.exception(ime)
					if not opts.list_file:
						sys.exit(ime.exit_code)
					else:
						md5_error_found = True
			
			data = {"md5hash" : md5_hash, "text" : note}
			bh = requests.post(url=request_url,headers=headers,verify=False, data=json.dumps(data))
			if bh.status_code == 409:
				raise ItemExistsError(sys.exc_info(), "Duplicate found")
			root.info("Banned {0} with note: {1}".format(md5_hash, note))
		except requests.exceptions.RequestException as re:
			root.exception("Server was unable to process request {0}: {1}".format(md5_hash, re))
		except ItemExistsError as iee:
			root.exception(iee)
			#~ else
				#~ sys.exit(400)
	except ApiError as ae:
		root.exception("Unable to ban hash {0}: {1}".format(md5_hash, ae))

def export_to_csv():
	success = True
	try:
		bh = requests.get(url=request_url,headers=headers,verify=False)
		ban_list = bh.json()
		temp = "Retrieved {} items.".format(len(ban_list)
		print(temp)
		root.info(temp)
		with open("export_ban_list_rest.csv", "wb") as export_csv:
			fieldnames = ['md5hash', 'username', 'timestamp', 'user_id', 'enabled', 'text']
			writer = csv.writer(export_csv)
			writer.writerow(fieldnames)
			for item in ban_list:
				writer.writerow([unicode(item.get(f)).encode('utf-8') for f in fieldnames])
		temp = "Exporting done."
		print(temp)
		root.info(temp)
		export_csv.close()
	except requests.exceptions.RequestException as re:
		root.info("Unable to fetch ban list {}".format(re))
		success = False
	except UnicodeEncodeError as uee:
		print(sys.exc_info())
		success = False
	except csv.Error as csv_error:
		root.info("Unable to export to csv {}".format(csv_error))
		success = False
	return success

def init():
	global script_message
	#~ global cb
	global banner
	global root
	root = logging.getLogger("")
	logging.basicConfig(filename=datetime.now().strftime('ban_hash_%H_%M_%d_%m_%Y.log'), level=logging.DEBUG)
	global creds
	global exit_code
	global server_url
	global api_token
	global md5_error_found
	md5_error_found = False
	exit_code = 0
	banner = "Script for banning hashes via REST API v3"
	print(banner)
	root.info(banner)

class ItemExistsError(ValueError):
	def __init__(self, expression, message):
		self.expression = expression
		self.message = message
		self.exit_code = 100

class InvalidApiTokenError(ValueError):
	def __init__(self, expression, message):
		self.expression = expression
		self.message = message
		self.exit_code = 200

class InvalidMD5Error(ValueError):
	def __init__(self, expression, message):
		self.expression = expression
		self.message = message
		self.exit_code = 300

class InvalidCommentError(ValueError):
	def __init__(self, expression, message):
		self.expression = expression
		self.message = message
		self.exit_code = 400

if __name__ == "__main__":
	sys.exit(main())
