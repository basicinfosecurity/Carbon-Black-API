import os
import re
import sys
from cbapi import CbApi
from cbapi.errors import ApiError
from cbapi.errors import CredentialError
from cbapi.errors import ServerError
from cbapi.response import CbResponseAPI
from cbapi.response import CbEnterpriseResponseAPI
from cbapi.response.models import BannedHash
from customerrors.errors import *

def init():
	global banner
	global note
	banner = "Script for banning hashes v4"
	note = "Banned from API"

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
	#~ print([return_code, message])
	return [return_code, message]
