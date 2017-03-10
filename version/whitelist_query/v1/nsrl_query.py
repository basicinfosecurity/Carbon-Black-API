import mysql.connector

def connect_mysql(host, user, password, db):
	return mysql.connector.connect(host=host, user=user, password=password, database=db)

def query_db(conn, md5_hash):
	c = conn
	cursor = c.cursor(dictionary=True)
	cursor.execute("select hex(md5) from nsrl_files where md5 = unhex(%s)",(md5_hash,))
	return cursor
	
def query_db(conn, md5_hash):
	c = conn
	cursor = c.cursor(dictionary=True)
	cursor.execute("select hex(md5) from nsrl_files where md5 = unhex(%s)",(md5_hash,))
	return cursor

def close_connect_mysql(conn, cursor):
	return {'cursorClosed': cursor.close(), 'connClosed': conn.close()}
