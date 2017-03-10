import argparse
import csv
import logging
import os
import shutil
import sys
from cb_ban_hash import cb_ban_hash_sa as cb
from datetime import datetime
from threading import Thread, Lock, activeCount
from time import sleep

def main():
	banner = "Feed Consumer v1"
	sleep_interval = 3
	#~ path = sys.argv[1]
	folders = ['done', 'temp', 'drop']
	max_threads = 8
	log_format = 'feed_consumer_%H_%M_%d_%m_%Y.log'
	logging.basicConfig(filename="logs\{}".format(datetime.now().strftime(log_format)), level=logging.INFO)
	parser = argparse.ArgumentParser(description=banner)
	parser.add_argument("-u", "--url", dest="server_url", help="Cb Response Server URL [e.g. \"http://cb.example.com\"]")
	parser.add_argument("-t", "--token", dest="api_token", help="Cb Response API Token")
	parser.add_argument("-p", "--path", dest="feed_path", help="Path to monitor feed drops")
	
	opts = parser.parse_args()
	
	
	try:
		if opts.server_url and opts.api_token:
			cb_obj = cb.cb_connect(opts.server_url, opts.api_token)
		else:
			raise
		path = opts.feed_path
		parent = os.path.dirname(path)
		#~ print(parent)
		for f in folders:
			if not os.path.exists(r''.join([parent, "\\", f])):
				msg = "Folder {} is missing. Creating folder".format(f)
				log_event(msg)
				os.mkdir(r''.join([parent, "\\", f]))
		while 1:
			contents = os.listdir(path)
			if(contents):
				for c in contents:
					if c.startswith("list") and os.path.splitext(c)[1] == ".csv":
						src = r''.join([path, "\\", c])
						dst = r''.join([parent, "\\done\\", c])
						msg = "Found list file [{}].".format(c)
						log_event(msg)
						with open(src, 'rb') as list_file:
							items = list(csv.DictReader(list_file))
							rows = len(items)
							msg = "Found {} items".format(rows)
							log_event(msg)
							
							for i in items:
								t = Thread(target=ban_process, args=[i['MD5'], i['enabled'], i['text']])
								while activeCount() >= max_threads:
									sleep(3)
								t.start()
						msg = "Reached EOF. Closing file and moving to {}".format(dst)
						log_event(msg)
						list_file.close()
						shutil.move(src, dst)
			else:
				msg = "No feed files to consume. Sleeping for {}".format(sleep_interval)
				log_event(msg)
			sleep(sleep_interval)
			#~ sleep(5)
	except KeyboardInterrupt as ki:
		msg = "Keyboard interrupt detected. Terminating process"
		log_event(msg, True)

def log_event(message, is_exception=False):
	print(message)
	if is_exception:
		logging.exception(message)
	else:
		logging.info(message)
		
def ban_process(md5hash, enabled, text):
	result = cb.ban_hash(md5_hash=md5hash, note=text, enable_flag=enabled)
	if result[0] > 0:
		log_event(result, True)
	else:
		log_event(result)
	
if __name__ == "__main__":
	sys.exit(main())
