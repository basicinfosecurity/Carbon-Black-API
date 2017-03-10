import argparse
import csv
import json
import traceback
import logging
import os
import re as regex
import requests
import sys
from customerrors.errors import *
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
	#Not yet supported --enable flag
	parser.add_argument("-e", "--enable", dest="enable", help="Enable flag. Include this flag to set the hash/es status to 'active' in the list.", action='store_true')
	parser.add_argument("-d", "--disable", dest="enable", help="Disable flag. Include this flag to set the hash/es status to 'inactive' in the list.", action='store_false')
	
	parser.add_argument("-x", "--export", help="Export ban list to csv", action='store_true')
	
	opts = parser.parse_args()
	note = "Banned from API"
	global request_url
	global headers
	global exit_code
	exit_code = 0
	#~ global data
			
	try:
		if opts.server_url and opts.api_token:
			if not(opts.server_url.startswith("http") and opts.server_url.startswith("https")):
				raise InvalidApiTokenError(sys.exc_info(), "Invalid server URL {}".format(opts.server_url))
			elif regex.match(r"([a-fA-F\d]{40})", opts.api_token) is None:
				raise InvalidApiTokenError(sys.exc_info(), "Invalid API Token {}".format(opts.api_token))
			parse = urlparse(opts.server_url)
			request_url = "{0}://{1}{2}".format(parse.scheme, parse.hostname, "/api/v1/banning/blacklist")
			#~ request_url = "{0}{1}".format(opts.server_url, '/api/v1/banning/blacklist')
			headers = {"X-Auth-Token" : opts.api_token}
			print(opts.disable)
			if opts.export:
				export_mode_msg = "Export mode. Fetching banned list from {}".format(opts.server_url)
				print(export_mode_msg)
				logging.info(export_mode_msg)
				export = export_to_csv()
				if not export:
					exit_code = 1
			else:
				if opts.text:
					note = opts.text
				if opts.md5hash:
					single_ban_mode_msg = "Single hash ban mode."
					print(single_ban_mode_msg)
					logging.info(single_ban_mode_msg)
					b = ban_hash(opts.md5hash, note, opts.disable)
					exit_code = b
				elif opts.list_file:
					list_ban_mode = "Multiple hash ban mode. Reading list file"
					print(list_ban_mode)
					logging.info(list_ban_mode)
					hash_list = open(opts.list_file, 'rb')
					ban_text = "Banning {} hashes. Reading from list file.".format(len(lines))
					print(ban_text)
					logging.info(ban_text)
					if os.path.splitext(hash_list.name)[1] == '.csv':
						csv_reader = csv.DictReader(hash_list)
						found_msg = "Found {0} hashes in {1}".format(len(csv_reader), hash_list.name)
						print(found_msg)
						logging.info(found_msg)
						for h in csv_reader:
							b = ban_hash(h['md5'], h['Note'], opts.disable)
						exit_code = b
					else:
						lines = [line.rstrip('\n') for line in hash_list]
						found_msg = "Found {0} hashes in {1}".format(len(lines), hash_list.name)
						print(found_msg)
						logging.info(found_msg)
						for h in lines:
							b = ban_hash(h, note)
					exit_code = b
					hash_list.close()
		else:
			parser.parse_args(['-h'])			
	except InvalidApiTokenError as iate:
		logging.exception("No valid api token or Cb server url was provided. Please check your input")
		exit_code = iate.exit_code
		sys.exit(exit_code)
	print("Exit code is {}".format(exit_code))
	sys.exit(exit_code)

def ban_hash(md5_hash, note, enable_flag=True):
	return_code = 0
	try:
		if regex.match(r"([a-fA-F\d]{32})", md5_hash) is None:
			try:
				raise InvalidMD5Error(sys.exc_info(),"{} was not added to the list. It is not a valid md5 hash.".format(md5_hash))
			except InvalidMD5Error as ime:
				logging.exception(ime)
				return_code = ime.exit_code
		else:
			if enable_flag:
				data = {"md5hash" : md5_hash, "text" : note}
				bh = requests.post(url=request_url,headers=headers,verify=False, data=json.dumps(data))
				if bh.status_code == 409:
					if bh.text.endswith("already exists"):
						raise ItemExistsError(sys.exc_info(), "Duplicate found for ")
					else:
						raise ItemExistsError(sys.exc_info(), bh.text)
				msg = "Banned {0} with note: {1}".format(md5_hash, note)
			else:				
				bh = requests.get(url=''.join([request_url, '?filter=md5hash == ', md5_hash]),headers=headers,verify=False)
				latest_record = bh.json()[0]['audit'][0]
				#It seems that an entity body is allowed for this delete request
				data = {"text" : latest_record['text']}
				disable_binary = requests.delete(url=''.join([request_url, '/', md5_hash]),headers=headers,verify=False, data=json.dumps(data))
				msg = "Ban for {} has been disabled/deactivated".format(md5_hash)
			logging.info(msg)
	except requests.exceptions.RequestException as re:
		logging.exception("Server was unable to process request {}".format(md5_hash))
		return_code = 1
	except ItemExistsError as iee:
		logging.exception("{0} {1}".format(iee.message, md5_hash))
		return_code = iee.exit_code
		pass
	return return_code

def export_to_csv():
	export_success = True
	try:
		bh = requests.get(url=request_url,headers=headers,verify=False)
		ban_list = bh.json()
		temp = "Retrieved {} items.".format(len(ban_list))
		print(temp)
		logging.info(temp)
		with open("export_ban_list_rest.csv", "wb") as export_csv:
			fieldnames = ['md5hash', 'username', 'timestamp', 'user_id', 'enabled', 'text']
			writer = csv.writer(export_csv)
			writer.writerow(fieldnames)
			for item in ban_list:
				writer.writerow([unicode(item.get(f)).encode('utf-8') for f in fieldnames])
		temp = "Exporting done."
		print(temp)
		logging.info(temp)
		export_csv.close()
	except requests.exceptions.RequestException as re:
		logging.info("Unable to fetch ban list {}".format(re))
		export_success = False
	except UnicodeEncodeError as uee:
		print(sys.exc_info())
		export_success = False
	except csv.Error as csv_error:
		logging.info("Unable to export to csv {}".format(csv_error))
		export_success = False
	return export_success

def init():
	global script_message
	global banner
	global root
	#~ root = logging.getLogger("")
	logging.basicConfig(filename="logs\{}".format(datetime.now().strftime('ban_hash_%H_%M_%d_%m_%Y.log')), level=logging.INFO)
	global creds
	#~ global exit_code
	global server_url
	global api_token
	global success
	success = True
	#~ exit_code = 0
	banner = "Script for banning hashes via REST API v4"
	print(banner)
	logging.info(banner)

if __name__ == "__main__":
	sys.exit(main())
