from multiprocessing.connection import Client
from time import sleep

def main():
	address = ('localhost', 6001)
	conn = Client(address)
	path = r'path to sample list'
	with open(path, 'r') as hashes:
		for h in hashes:
			print('Checking {}'.format(h.strip()))
			conn.send(h.strip())
			sleep(0.5)
			print(conn.recv())
			#~ print(conn.recv())
	hashes.close()
	conn.send('close')
	#~ conn.send(None)
	conn.close()

if __name__ == "__main__":
	exit(main())

