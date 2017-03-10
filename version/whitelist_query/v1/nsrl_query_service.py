import nsrl_query as nsrl
import os
import sys
import yaml
from multiprocessing.connection import Listener
from mysql.connector import errors as MySQLError
from mysql.connector import errorcode as errorcode
from time import sleep

def main():
	init()
	try:
		while True:
			svc_conn = svc_listener.accept()
			#~ init()
			try:			
				if hasattr(svc_conn, 'recv'):
					print('Connected to {}'.format(svc_address))
					print('Connecting to NSRL DB')
					db_conn = nsrl.connect_mysql(host=config['hostname'], user=config['user'], password=config['password'], db=config['database'])
					while True:
						if svc_conn.poll():
							svc_msg = svc_conn.recv()
							#~ print(svc_msg)
							if svc_msg.upper() == 'CLOSE':
								svc_conn.close()
								break
							else:
								cursor = nsrl.query_db(db_conn, svc_msg)
								isFound = False
								for c in cursor:
									if svc_msg.upper() in c.values():
										isFound = True
										break
								if isFound:
									msg = "{} was found".format(svc_msg)
								else:
									msg = "{} was not found".format(svc_msg)
								svc_conn.send(msg)
								svc_conn.send(isFound)
						else:
							sleep(0.1)					
				else:
					print('Connection refused by {}'.format(svc_address))	
				
			except MySQLError.ProgrammingError as pe:
				if pe.errno == errorcode.ER_ACCESS_DENIED_ERROR:
					print("Access denied. Please provide correct credentials")
				elif pe.errno == errorcode.ER_NO_DB_ERROR:
					print("Access denied. No database provided")
				elif pe.errno == errorcode.ER_DBACCESS_DENIED_ERROR:
					print("Access denied. Access to database is denied")
				elif pe.errno == errorcode.ER_TABLEACCESS_DENIED_ERROR:
					print("Access denied. Command is not allowed for user")
			except MySQLError.Error as mysql_err:
				if mysql_err.errno == errorcode.CR_CONN_HOST_ERROR:
					print("Cannot connect to server.")
				else:
					print(mysql_err)
			except EOFError as eof:
				print("Lost connection to client {}".format(eof))
				#~ svc_listener.close()
			finally:
				print("Tearing down connection to NSRL DB")
				nsrl.close_connect_mysql(db_conn, cursor)
				#~ return isFound
				#~ svc_listener.close()
	except KeyboardInterrupt as ki:
		print("Service stopped. {}".format(ki.message))
		svc_listener.close()
		sys.exit(1)

def init():
	global config
	path = os.path.dirname(os.path.realpath(__file__))
	with open(os.path.join(path, 'config.yml'), 'rb') as cnf_file:
		config = yaml.load(cnf_file)[0]
	cnf_file.close()
	global svc_address
	global svc_listener
	global svc_conn
	svc_address = ('localhost', 6000)
	svc_listener = Listener(svc_address)
	#~ svc_conn = svc_listener.accept()
	print("Starting service {0}. Connecting to {1}".format(__file__, svc_address))

if __name__ == "__main__":
	exit(main())
