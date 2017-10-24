import json, logging, requests, shutil

from cbapi.protection import CbEnterpriseProtectionAPI
from cbapi import CbApi
from cbapi.auth import CredentialStore
from cbapi.errors import ObjectNotFoundError
from cbapi.response import CbResponseAPI
from cbapi.response.models import Binary

from datetime import datetime
from exceptions import WindowsError
from log_setup import log_event, setup_logging
#~ from logging import basicConfig, getLogger, INFO
#~ from logging.handlers import TimedRotatingFileHandler
from multiprocessing.connection import Client,Listener
from os import devnull, listdir, makedirs, remove
from os.path import exists, isdir, isfile, join
from progressbar import ProgressBar, Bar, Percentage
from Queue import Queue
from requests.exceptions import HTTPError
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from subprocess import check_call, CalledProcessError
from threading import Thread
from time import sleep
from yaml import load
from zipwrapper import Zip

class FileCollector:
	def __init__(self):
		config = load(open(r'conf.yaml', 'rb'))
		self.address = config['address']
		self.port = config['port']
		self.banner = config['banner']
		self.protection_url = config['protection']['url']
		self.protection_token = config['protection']['token']
		self.protection_headers = {'X-Auth-Token': self.protection_token}
		self.protection_path = config['protection']['path']
		self.protection_interval = config['protection']['interval']
		self.protection_counter = config['protection']['counter']
		self.response_url = config['response']['url']
		self.response_token = config['response']['token']
		self.response_path = config['response']['path']
		self.archives = config['archives']
		self.logs = config['logs']
		self.password = config['password']
		#~ self.root = getLogger("cbapi")
		self.queue = Queue()
		self.check_dirs()
		setup_logging()
		#~ basicConfig(filename=datetime.now().strftime(r'logs/FileCollector_%H_%M_%d_%m_%Y.log'), level=INFO)
		requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
		self.cb = CbApi(self.response_url, token=self.response_token, ssl_verify=False)
	
	def check_dirs(self):
		if not isdir(self.protection_path):
			log_event("[+] Creating {} directory".format(self.protection_path))
			makedirs(self.protection_path)
		if not isdir(self.response_path):
			log_event("[+] Creating {} directory".format(self.response_path))
			makedirs(self.response_path)
		if not isdir(self.archives):
			log_event("[+] Creating {} directory".format(self.archives))
			makedirs(self.archives)
		if not isdir(self.logs):
			log_event("[+] Creating {} directory".format(self.logs))
			makedirs(self.logs)
	
	def start_service(self):
		log_event(self.banner)
		log_event("[*] Connecting to {}".format(self.protection_url))
		log_event("[*] Connecting to {}".format(self.response_url))
		self.listener = Listener((self.address, self.port))
		while True:
			try:
				self.connection = self.listener.accept()
				while True:
					self.get_md5()
					log_event("[*] Processing {}.".format(self.md5))
					if self.get_fileCatalogData():
						if not self.isQueued():
							self.queue_file()
					elif self.download_binary_cbr()['code']:
						continue
					else:
						continue
			except EOFError as eof:
				log_event("[-] Lost connection to client.", True)
				self.archive_and_encrypt()
	
	def get_md5(self):
		self.md5 = self.connection.recv()
	
	def get_fileCatalogData(self):
		self.dl_req = requests.get("{}{}{}".format(self.protection_url, 'api/bit9platform/v1/fileCatalog?q=md5:', self.md5), headers = self.protection_headers, verify = False)
		if self.dl_req.ok:
			self.fc_id = self.get_id()
			if self.fc_id:
				log_event("[+] Requested file found.[id] = {}".format(self.fc_id))
				return True
			return False
		else:
			log_event("[-] Could not fetch File Catalog Data", True)
			self.connection.send("[-] Could not fetch File Catalog Data")
			return False
	
	def isQueued(self):
		log_event("[+] Checking for queued downloads.")
		self.fileName = self.md5.lower()
		isqueued = requests.get("{}{}{}".format(self.protection_url, 'api/bit9platform/v1/fileCatalog?q=uploadStatus:0&limit=0&q=fileName:', self.fileName), headers = self.protection_headers, verify = False)
		if isqueued.ok:
			log_event("[+] File is queued for uploading")
			return True
		return False
	
	def queue_file(self):
		log_event("[+] Queuing file for upload")
		compId = self.dl_req.json()[0]['computerId']
		self.data = {'computerId':compId, 'fileCatalogId':self.fc_id, 'priority':2, 'uploadStatus':0}
		self.upload_req = requests.post("{}{}".format(self.protection_url, 'api/bit9platform/v1/fileUpload'), headers = self.protection_headers, data = self.data, verify = False)
		if self.upload_req.ok:
			self.check_fileQueue()
		else:
			log_event("[-] Requested file not found.", True)
			self.connection.send("[-] Requested file not found.")
	
	def check_fileQueue(self):
		self.fileId = self.upload_req.json()['id']
		log_event("[+] File is now queued. [id] = {}".format(self.fileId))
		check_queue = requests.post("{}{}".format(self.protection_url, 'api/bit9platform/v1/fileUpload'), headers = self.protection_headers, data = self.data, verify = False)
		ctr = 1
		while check_queue.json()['uploadStatus'] is not 3:
			log_event("[+] Sleeping for {} seconds.".format(self.protection_interval))
			sleep(self.protection_interval)
			check_queue = requests.post("{}{}".format(self.protection_url, 'api/bit9platform/v1/fileUpload'), headers = self.protection_headers, data = self.data, verify= False)
			#Sleep until 5 minutes has passed
			ctr = ctr + 1
			if ctr is self.protection_counter:
				log_event("[-] File is still queued. Check the queue later.", True)
				self.connection.send("[-] File is still queued. Check the queue later.")
				break
		if check_queue.json()['uploadStatus'] is 3:
			self.download_binary_cbp()
	
	def get_id(self):
		if isinstance(self.dl_req.json(), list):
			if len(self.dl_req.json()) > 0:
				return self.dl_req.json()[0]['id']
			else:
				log_event("[-] No File Catalog data found for {}.".format(self.md5), True)
				self.connection.send("[-] No File Catalog data found for {}.".format(self.md5))
				return None
		else:
			return self.dl_req.json()['id']
			
	def archive_and_encrypt(self):
		try:
			log_event("[*] Archiving downloaded file/s.")
			prog_path = r"C:\Program Files\7-Zip\7z.exe"
			if isfile(prog_path):
				archive_name = datetime.now().strftime('%H_%M_%d_%m_%Y')
				isZipped = check_call([prog_path, 'a', '-p{}'.format(self.password), '-y', r'{}/archive-{}.zip'.format(self.archives, archive_name), './{}/*'.format(self.protection_path), './{}/*'.format(self.response_path)], stdout=open(devnull, 'w'))
				if isZipped != 0:
					raise CalledProcessError(cmd=prog_path, returncode=1, output='Failed to archive file/s')
				else:
					log_event('[+] File/s have been archived [{}.zip].'.format(archive_name))
				for file_response in listdir(self.response_path):
					tmp_path = join(self.response_path, file_response)
					remove(tmp_path)
				for file_protection in listdir(self.protection_path):
					tmp_path = join(self.protection_path, file_protection)
					remove(tmp_path)
			else:
				raise WindowsError('[-] 7zip is missing in your system.')
		except CalledProcessError as cpe:
			log_event(cpe, True)
		except WindowsError as we:
			log_event(we, True)
	
	def download_binary_cbr(self):
		temp_text = {'msg':"[+] Download successful", 'code':1}
		try:
			filename = join(self.response_path, self.md5.lower())
			if not isfile(filename):
				binary = self.cb.binary(self.md5)
				dump = open(filename, "wb")	
				dump.write(binary)
				dump.close()
			else:
				temp_text = {'msg':"[-] File exists.", 'code':1}
		except (ObjectNotFoundError, HTTPError):
			temp_text = {'msg':"[-] File was not found", 'code':0}
		log_event(temp_text['msg'], (temp_text['code'] is 0))
		return temp_text
	
	def download_binary_cbp(self):
		log_event("[+] Downloading sample")
		dl = requests.get("{}{}".format(self.protection_url, 'api/bit9platform/v1/fileUpload/{}?downloadFile=true'.format(self.fileId)), headers = self.headers, verify = False, stream = True)
		chunk_size = 1024
		size = int(dl.headers['Content-Length']) / chunk_size
		i = 0
		if dl.ok:
			pbar = ProgressBar(widgets=[Percentage(), Bar()], maxval = size).start()
			with open("{}/{}".format(self.protection_path, self.fileName), 'wb') as f:
				for chunk in dl.iter_content(chunk_size):
					f.write(chunk)
					pbar.update(i)
					i += 1
				#~ log_event("[+] Download complete")
				pbar.finish()
				f.close()
				log_event("[+] Download complete.")
				self.connection.send("[+] Download complete.")
				
		else:
			#~ print("[-] Unable to download file")
			log_event("[-] Unable to download file.", True)
			self.connection.send("[-] Unable to download file.")
