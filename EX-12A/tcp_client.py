# udp_client.py
from socket import *

HOST = 'localhost'
PORT = 55555
BUFF_SIZE = 1024

s = socket(AF_INET, SOCK_DGRAM)

s.bind(("", 0))

ip = input('Message to send: ')
s.sendto(ip.encode(), (HOST, PORT))
print(f"Response back from server {s.recvfrom(1024)}")
