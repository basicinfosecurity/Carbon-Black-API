#Encrypt using 7zip

import os
import subprocess
from zipfile import ZipFile

class Zip:
	def __init__(self, *files):
		self.binpath = r'C:\Program Files\7-Zip\7z.exe'
		if not os.path.isfile(self.binpath):
			print '[!] 7zip is missing.'
			exit(1)
		self.files = files
	def compress(self, password=None):
		print '[*] Compressing files'
		self.zargs = list()
		self.zargs.append(self.binpath)
		self.zargs.append('a')
		if password:
			print '[*] Password protected archive'
			self.zargs.append('-p{}'.format(password))
		self.zargs.append('-y')
		self.zargs.append('{}.zip'.format(self.files[0]))
		for f in self.files:
			self.zargs.append(f)
		if subprocess.call(self.zargs) != 0:
			print '[!] Unable to encrypt files'
	def extract(self, archive, password = None):
		if not os.path.isfile(archive):
			print '[!] Archive [{}] not found'.format(archive)
		else:
			print '[*] Decompressing archive'
			ZipFile(archive).extractall(pwd = password)
