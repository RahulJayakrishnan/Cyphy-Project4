import socket
import struct
import time
from binascii import * 

HOST = '127.0.0.1'       # The remote host
PORT = 1502              # The same port as used by the server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Establish the connection
s.connect((HOST, PORT))  # Connect to the server 

# Construct the malicious packet you want to send to the server
# Please read about the structure of the modbus packets. You may need the following parameters: tid, pid, length, uid, fcode, write address
# number of registers to write, read address, number of registers to read, and content of the registers to be written (payload)
# Use struct.pack for constructing the packet



#Write your code here



################ 

# send the constructed malicious packet (i.e., m)

s.send(m)
