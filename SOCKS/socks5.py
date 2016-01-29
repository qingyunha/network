import socket
import logging
import threading, select

'''
a simple SOCKS5 server


1. select authenticate method 

+----+----------+----------+
|VER | NMETHODS | METHODS  |
+----+----------+----------+
| 1  |    1     | 1 to 255 |
+----+----------+----------+

+----+--------+
|VER | METHOD |
+----+--------+
| 1  |   1    |
+----+--------+   



2. authenticate



3. request

        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

    Where:

          o  VER    protocol version: X'05'
          o  CMD
             o  CONNECT X'01'
             o  BIND X'02'
             o  UDP ASSOCIATE X'03'
          o  RSV    RESERVED
          o  ATYP   address type of following address
             o  IP V4 address: X'01'
             o  DOMAINNAME: X'03'
             o  IP V6 address: X'04'
          o  DST.ADDR       desired destination address
          o  DST.PORT desired destination port in network octet
             order




       +----+-----+-------+------+----------+----------+
       |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
       +----+-----+-------+------+----------+----------+
       | 1  |  1  | X'00' |  1   | Variable |    2     |
       +----+-----+-------+------+----------+----------+

     Where:

          o  VER    protocol version: X'05'
          o  REP    Reply field:
             o  X'00' succeeded
             o  X'01' general SOCKS server failure
             o  X'02' connection not allowed by ruleset
             o  X'03' Network unreachable
             o  X'04' Host unreachable
             o  X'05' Connection refused
             o  X'06' TTL expired
             o  X'07' Command not supported
             o  X'08' Address type not supported
             o  X'09' to X'FF' unassigned
          o  RSV    RESERVED
          o  ATYP   address type of following address


4. relay

 '''



logging.basicConfig(level=logging.ERROR)

VN = '\x05'
CONNECT = '\x01'

GRANT = '\x00' 
REJECT = '\x01'


def handle_connect(client):

    m = select_method(client)
    if not m:
        client.close()
        return

    if not authenticate(m, client):
        logging.info("authenticate failed")
        client.close()
        return
    logging.info("authenticate success")
    
    handle_request(client)


def handle_request(client):

    req = client.recv(1024)

    version = req[0]
    if version != VN:
        logging.info("not support version {}".format(ord(version)))
        client.close()
        return

    command = req[1]
    if command != '\x01':
        logging.info("Only support connect command")
        client.close()
        return

    reserved = req[2]


    addr_type = req[3]
    domain, dst_ip, dst_port = get_addr(req[3:])

    logging.info("connect to {}({}):{}".format(domain, dst_ip, dst_port))
    logging.error("connect to {}({}):{}".format(domain, dst_ip, dst_port))
    target = None
    try:
        target = socket.create_connection((dst_ip, dst_port))
    except Exception as e:
        logging.info("reject connect {}".format(domain))
        logging.error("reject connect {}".format(domain))
        reply_client(client, REJECT, target)
    else:
        logging.info("grant connect {}".format(domain))
        logging.error("grant connect {}".format(domain))
        reply_client(client, GRANT, target)
        proxy(client, target)


def select_method(client):
    SUPPORT_METHODS = ['\x00', '\x02']
    r = client.recv(1024)
    if r[0] != VN:
        logging.info("not support version {}".format(r[0]))
        return
    num = ord(r[1])
    methods = list(r[2:2+num])
    for m in methods:
        if m in SUPPORT_METHODS:
            logging.info("select method {}".format(ord(m)))
            client.sendall(VN + m)
            return m
    logging.info("not support method")
    return


def authenticate(method, client):
    if method == '\x00':
        return True
    if method == '\x02':
        return user_pass(client)

def user_pass(client):
    USER = 'tao'
    PASS = '123'
    return True



def get_addr(addrinfo):
    type = addrinfo[0]
    domain = None
    if type == '\x01':              #ipv4
        ip = addrinfo[1:5]
        port = addrinfo[5:7]
    elif type == '\x03':            #domain name
        num = ord(addrinfo[1])
        domain = addrinfo[2:2+num]
        ip = socket.gethostbyname(domain)
        port = addrinfo[2+num:4+num]
    elif type == '\04':             #ipv6
        ip = addrinfo[1:17]
        port = addrinfo[17:19]

    port = (ord(port[0]) << 8) + ord(port[1])
    return (domain, ip, port)



def reply_client(client, rep, target): 
    r = VN + rep + '\x00' + '\x01'
    if target:
        bind_ip, bind_port = target.getsockname()
        bind_ip = ''.join([chr(int(i)) for i in bind_ip.split('.')])
        bind_port = ''.join([chr(i) for i in divmod(bind_port, 256)])
    else:
        bind_ip = 4*'\x00'
        bind_port = 2*'\x00'

    client.sendall(r+bind_ip+bind_port)


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
