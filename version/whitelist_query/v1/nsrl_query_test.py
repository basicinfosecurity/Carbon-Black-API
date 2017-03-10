import nsrl_query as nsrl
from mysql.connector import errors as MySQLError
from mysql.connector import errorcode as errorcode

def main():
	try:
		conn = nsrl.connect_mysql('192.168.56.5', 'user', 'pa$$w0rd', 'whitelist')
				
		#~ md5 = "12896823fb95bfb3dc9b46bcaedc9923"
		#~ md5 = "97B89125D66CCFFE8E862B1FDFDEB893"
		#~ md5 = "BF379376C124B19A7535CBA8EA179802"
		#~ md5 = "()()()("
		md5 = "NULL"
		cursor = nsrl.query_db(conn, md5)
		#~ cursor = nsrl.delete_record(conn, md5)
		isFound = False
		for c in cursor:
			if md5.upper() in c.values():
				isFound = True
				break
		
		if isFound:
			print("{} was found".format(md5))
		else:
			print("{} was not found".format(md5))
		print("Tearing down connection")
		nsrl.close_connect_mysql(conn, cursor)
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

if __name__ == "__main__":
	exit(main())
