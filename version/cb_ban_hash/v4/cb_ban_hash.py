import argparse
import csv
import traceback
import logging
import os
import re
import sys
from cbapi import CbApi
from cbapi.auth import CredentialStore
from cbapi.errors import ApiError
from cbapi.errors import CredentialError
from cbapi.errors import ServerError
from cbapi.response import CbResponseAPI
from cbapi.response import CbEnterpriseResponseAPI
from cbapi.response.models import BannedHash
from customerrors.errors import *
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler

def main():
	init()
	parser = argparse.ArgumentParser(description=banner)
	parser.add_argument("-u", "--url", dest="server_url", help="Cb Response Server URL [e.g. \"http://cb.example.com\"]")
	parser.add_argument("-t", "--token", dest="api_token", help="Cb Response API Token")
	
	parser.add_argument("-m", "--md5hash", dest="md5hash", help="MD5 hash of the binary to be banned")
	parser.add_argument("-n", "--notes", dest="text", help="Notes for banning the binary")
	parser.add_argument("-l", "--list", dest="list_file", help="List file of binaries to be banned. Also accepts csv files.")
	parser.add_argument("-e", "--enable", dest="enable", help="Enable flag. Include this flag to set the hash/es status to 'active' in the list.", action='store_true')
	parser.add_argument("-d", "--disable", dest="disable", help="Disable flag. Include this flag to set the hash/es status to 'inactive' in the list.", action='store_true')
	
	parser.add_argument("-x", "--export", help="Export ban list to csv", action='store_true')
	
	opts = parser.parse_args()
	note = "Banned from API"
	global cb
	exit_code = 0
	
	try:
		if opts.server_url and opts.api_token:
			if not(opts.server_url.startswith("http") or opts.server_url.startswith("https")):
				raise InvalidApiTokenError(sys.exc_info(), "Invalid server URL {}".format(opts.server_url))
			elif re.match(r"([a-fA-F\d]{40})", opts.api_token) is None:
				raise InvalidApiTokenError(sys.exc_info(), "Invalid API Token {}".format(opts.api_token))
			cb = CbResponseAPI(opts.server_url, token=opts.api_token, ssl_verify=False)
		
			if opts.export:
				export_mode_msg = "Export mode. Fetching banned list from {}".format(opts.server_url)
				print(export_mode_msg)
				root.info(export_mode_msg)
				export = export_to_csv()
				if not export:
					exit_code = 1
			else:
				if opts.text:
					note = opts.text
		
				if opts.md5hash:
					single_ban_mode_msg = "Single hash ban mode."
					print(single_ban_mode_msg)
					root.info(single_ban_mode_msg)
					if opts.enable:
						b = ban_hash(opts.md5hash, note, True)
					elif opts.disable:
						b = ban_hash(opts.md5hash, note, False)
					else:
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
							ban_hash(h['md5'], h['Note'])
					else:
						lines = [line.rstrip('\n') for line in hash_list]
						found_msg = "Found {0} hashes in {1}".format(len(lines), hash_list.name)
						print(found_msg)
						root.info(found_msg)
						for h in lines:
							ban_hash(h, note)
					hash_list.close()
					if md5_error_found:
						sys.exit(100)
		else:
			parser.parse_args(['-h'])
	except InvalidApiTokenError as iate:
		root.exception(iate)
		exit_code = iate.exit_code
	sys.exit(exit_code)

def ban_hash(md5_hash, note, disable_flag):
	return_code = 0
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
			bh = cb.create(BannedHash)
			bh.md5hash = md5_hash
			bh.text = note
			bh.save()
			root.info("Banned {0} with note: {1}".format(md5_hash, note))
		except ServerError as se:
			root.exception("Server was unable to process request {0}: {1}".format(md5_hash, se))
			if se.message.endswith("already exists"):
				sys.exit(100)
			#~ else
				#~ sys.exit(400)
	except ApiError as ae:
		root.exception("Unable to ban hash {0}: {1}".format(md5_hash, ae))
	return return_code

def export_to_csv():
	return_code = True
	try:
		bh_object = cb.select(BannedHash)
		ban_list = bh_object.results
		temp = "Retrieved {} items.".format(len(ban_list))
		print(temp)
		logging.info(temp)		
		with open("export_ban_list.csv", "wb") as export_csv:
			fieldnames = ['md5hash', 'username', 'timestamp', 'user_id', 'enabled', 'text']
			writer = csv.writer(export_csv)
			writer.writerow(fieldnames)
			for item in ban_list:
				writer.writerow([unicode(item.__getattr__(f)).encode('utf-8') for f in fieldnames])
		export_csv.close()
	except ApiError as ae:
		root.info("Unable to fetch ban list {}".format(ae))
	except UnicodeEncodeError as uee:
		print(sys.exc_info())
	except csv.Error as csv_error:
		root.info("Unable to export to csv {}".format(csv_error))
	return return_code

def init():
	global script_message
	#~ global cb
	global banner
	global root
	root = logging.getLogger("cbapi")
	logging.basicConfig(filename="logs\{}".format(datetime.now().strftime('ban_hash_%H_%M_%d_%m_%Y.log')), level=logging.INFO)
	global creds
	global server_url
	global api_token
	global md5_error_found
	md5_error_found = False
	banner = "Script for banning hashes v4"

if __name__ == "__main__":
	sys.exit(main())
