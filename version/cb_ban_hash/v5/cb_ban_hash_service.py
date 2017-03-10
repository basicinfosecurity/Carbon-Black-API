import sys
from os import path
sys.path.append(r"path to whitelist module")
#~ print sys.path
import nsrl_query as nsrl
import re
from cbapi import CbApi
from cbapi.errors import ApiError
from cbapi.errors import CredentialError
from cbapi.errors import ServerError
from cbapi.response import CbResponseAPI
from cbapi.response import CbEnterpriseResponseAPI
from cbapi.response.models import BannedHash
from customerrors.errors import *
from multiprocessing.connection import Client,Listener
from time import sleep

def main():
	init()
	while True:
		try:			
			cb_conn = cb_listener.accept()
			if hasattr(cb_conn, 'recv'):
				print('CB Service listening on {}'.format(cb_address))
				print('Waiting')
				while True:
					if cb_conn.poll():
						cb_msg = cb_conn.recv()
						if cb_msg.upper() == 'CLOSE':
							cb_conn.close()
							break
						else:
							result_msg = whitelist_check(cb_msg)
							cb_conn.send(result_msg)
					else:
						sleep(0.1)
			else:
				print("Connection refused at {}".format(cb_address))
		except EOFError as eof:
			print("Lost connection to {}".format(cb_address))
		except KeyboardInterrupt as ki:
			print("Service stopped. {}".format(ki.message))
			cb_listener.close()
			sys.exit(1)

def init():
	global banner
	global note
	global cb_address
	global cb_listener
	banner = "CB Ban Hash Service v5"
	note = "Banned from API"
	cb_address = ('localhost', 6001)
	cb_listener = Listener(cb_address)
	print("Starting service {0}. Connecting to {1}".format(__file__, cb_address))

def cb_connect(server_url, api_token):
	message = "Connected to Cb Response server"	
	global cb
	try:
		if server_url and api_token:
			if not(server_url.startswith("http") or server_url.startswith("https")):
				raise InvalidApiTokenError(sys.exc_info(), "Invalid server URL {}".format(server_url))
			elif re.match(r"([a-fA-F\d]{40})", api_token) is None:
				raise InvalidApiTokenError(sys.exc_info(), "Invalid API Token {}".format(api_token))
			cb = CbResponseAPI(server_url, token=api_token, ssl_verify=False)
	except InvalidApiTokenError as iate:
		message = iate.message
	return message

def ban_hash(md5_hash, enable_flag, note="Banned from API"):
	return_code = 0
	message = "Banned {0} with note: {1}".format(md5_hash, note)
	try:
		if re.match(r"([a-fA-F\d]{32})", md5_hash) is None:
			raise InvalidMD5Error(sys.exc_info(),"{} was not added to the list. It is not a valid md5 hash.".format(md5_hash))
		check = whitelist_check(md5_hash)
		if check[0] > 0:
			raise WhitelistError
		exists = cb.select(BannedHash).where("md5hash:{}".format(md5_hash))
		if len(exists.results) > 1:
			exists[0].enabled = enable_flag
			exists[0].note = note
			exists[0]._update_object()
		else:
			bh = cb.create(BannedHash)
			bh.md5hash = md5_hash
			bh.text = note
			bh.save()
	except ApiError as ae:
		message = "Unable to ban hash {0}: {1}".format(md5_hash, ae.message)
		return_code = 1
	except InvalidMD5Error as ime:
		message = ime.message
		return_code = ime.exit_code
	except ServerError as se:
		message = "Server was unable to process request {0}: {1}".format(md5_hash, se)
		return_code = 1
	except WhitelistError as we:
		message = "Provided hash was found in whitelist {0}: {1}".format(md5_hash, we)
	#~ print([return_code, message])
	return [return_code, message]

def whitelist_check(md5_hash):
	return_code = 0
	message = "No hits found for {}".format(md5_hash)
	wl_addr = ('localhost', 6000)
	wl_conn = Client(wl_addr)
	try:
		wl_conn.send(md5_hash)
		msg = wl_conn.recv()
		print(msg)
		found = wl_conn.recv()
		if found:
			raise WhitelistError(sys.exc_info(), "Hit found for {}".format(md5_hash))
	except WhitelistError as we:
		return_code = 1
		message = we.message
	finally:
		print("Closing connection to {}".format(wl_addr))
		#~ wl_conn.send('close')
		wl_conn.close()
		return [return_code, message]

if __name__ == "__main__":
	exit(main())
