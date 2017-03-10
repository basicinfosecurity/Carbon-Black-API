import argparse
import getpass
import nsrl_query as nsrl
from mysql.connector import errors as MySQLError
from mysql.connector import errorcode as errorcode

def main():
	init()
	try:
		parser = argparse.ArgumentParser(description=banner, usage='%(prog)s -i HOSTNAME -u USER -d DATABASE -p [Password flag. User will be asked to provide a password]')
		parser.add_argument("-i", "--hostname", dest="hostname", help="Hostname/IP to database")
		parser.add_argument("-u", "--user", dest="user", help="User name")
		parser.add_argument("-p", "--password", dest="password", help="Password flag. User will be asked to provide a password", action='store_true')
		parser.add_argument("-d", "--database", dest="database", help="Database")
		parser.add_argument("-m", "--md5", dest="md5", help="MD5 hash")
		
		opts = parser.parse_args()
		
		if opts.password and opts.md5:
			password = getpass.getpass()
			conn = nsrl.connect_mysql(opts.hostname, opts.user, password, opts.database)
			cursor = nsrl.query_db(conn, opts.md5)
			#~ cursor = nsrl.delete_record(conn, md5)
			isFound = False
			for c in cursor:
				if opts.md5.upper() in c.values():
					isFound = True
					break
			
			if isFound:
				print("{} was found".format(opts.md5))
			else:
				print("{} was not found".format(opts.md5))
			print("Tearing down connection")
			nsrl.close_connect_mysql(conn, cursor)
		else:
			parser.parse_args(["-h"])
	except MySQLError.ProgrammingError as pe:
		#~ print(pe.errno)
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

def init():
	global banner
	banner = "NSRL Query Standalone script v1"	

if __name__ == "__main__":
	exit(main())
