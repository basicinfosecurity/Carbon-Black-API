import nsrl_query as nsrl

def main():
	isFound = False
	path = r'path to sample_list.txt'
	conn = nsrl.connect_mysql('192.168.56.5', 'root', 'password', 'whitelist')
	with open(path, 'r') as hashes:
		for h in hashes:
			#~ item = h.strip('\n')
			item = h.strip()
			cursor = nsrl.query_db(conn, item)
			isFound = test_check(item, cursor)
			if isFound:
				print("{} was found".format(item))
			else:
				print("{} was not found".format(item))
	print("Tearing down connection")
	nsrl.close_connect_mysql(conn, cursor)
	
def test_check(md5_hash, cursor):
	for c in cursor:
		if md5_hash.upper() in c.values():
			return True
	return False

if __name__ == "__main__":
	exit(main())
