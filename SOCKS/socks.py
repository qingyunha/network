import socket
import logging
import threading, select

'''
a simple SOCKS4 server

CONNECT

		+----+----+----+----+----+----+----+----+----+----+....+----+
		| VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
		+----+----+----+----+----+----+----+----+----+----+....+----+
           1    1      2              4            variable 

replay


		+----+----+----+----+----+----+----+----+
		| VN | CD | DSTPORT |      DSTIP        |
		+----+----+----+----+----+----+----+----+
    	   1    1      2              4

  CD:
	90: request granted
	91: request rejected or failed
	92: request rejected becasue SOCKS server cannot connect to
	    identd on the client
	93: request rejected because the client program and identd
	    report different user-ids
   

 '''

logging.basicConfig(level=logging.DEBUG)

VN = '\x04'
CONNECT = '\x01'

GRANT = 90
REJECT = 91


def handle_connect(client):
    conn_req = client.recv(100)

    identity = conn_req[2:8]
    dst_port = conn_req[2:4]
    dst_ip = conn_req[4:8]

    dst_port = (ord(dst_port[0]) << 8) + ord(dst_port[1])
    dst_ip = '.'.join([ str(ord(i)) for i in dst_ip])
    logging.info("connect to {}:{}".format(dst_ip, dst_port))
    target = None
    try:
        target = socket.create_connection((dst_ip, dst_port))
    except Exception as e:
        logging.info("reject connect")
        reply_client(client, REJECT, identity)
    else:
        logging.info("grant connect")
        reply_client(client, GRANT, identity)
        proxy(client, target)



def reply_client(client, cd, identity): 
    r = '\x00' + chr(cd) + identity
    client.sendall(r)


def proxy(client, target):
    logging.info("proxy starting")
    try:
        while True:
            ready, _, _ = select.select([client, target],[],[])
            if client in ready:
                s = client.recv(65535)
                if s == '':
                    raise
                else:
                    target.sendall(s)
            if target in ready:
                s = target.recv(65535)
                if s == '':
                    raise
                else:
                    client.sendall(s)
    except:
        logging.info("proxy ending")
        client.close()
        target.close()
            



def main():
    s = socket.socket()
    s.bind(('', 1080))
    s.listen(10)
    while True:
        client, _ = s.accept()
        threading.Thread(target=handle_connect, args=(client,)).start()
        #handle_connect(client)
    

if __name__ == '__main__':
    print "SOCKS server starting"
    main()
