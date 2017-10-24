from multiprocessing.connection import Client

def main():
	connection = Client(('localhost', 6060))
	with open(r'PATH/TO/list.txt', 'rb') as samples:
		for sample in samples:
			print("Sending sample " + sample.rstrip())
			connection.send(sample.rstrip())
			print connection.recv()
			
if __name__ == "__main__":
	exit(main())
