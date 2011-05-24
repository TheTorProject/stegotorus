import socket,struct

negot = struct.pack('BBB', 5, 1, 0)
request = struct.pack('BBBBBBB', 5, 2, 0, 1, 1, 1, 1)

PORT = 4500

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1",PORT))
s.send(negot)
s.recv(1024)
s.send(request)
data = s.recv(1024)
if (struct.unpack('BBBBih', data)[1] == 7):
    print "Works."

