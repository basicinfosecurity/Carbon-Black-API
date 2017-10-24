# Collection
File Downloading Service using Carbon Black Response and Protection

# Usage
To run, use `test_client.py` to send MD5 hashes to the service.
```
from multiprocessing.connection import Client

def main():
  connection = Client(('localhost', 6060))
  with open(r'samples.txt', 'rb') as samples: #Edit the path
    for sample in samples:
      print("Sending sample " + sample.rstrip())
      connection.send(sample.rstrip())
      print connection.recv()

if __name__ == "__main__":
  exit(main())
```

Make sure to provide your token/s in the `conf.yaml` file.
