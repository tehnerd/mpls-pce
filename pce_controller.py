#!/usr/bin/python
import gevent
import socket
import pcep
import time
from gevent import monkey
monkey.patch_socket()


SERVADDR='0.0.0.0'
SERVPORT=4189
MAXCLIENTS=10

def send_ka(pcep_context, sock):
    while True:
        sock.send(pcep_context.generate_ka_msg())
        gevent.sleep(pcep_context._ka_timer)

def pcc_handler(clsock):
    pcep_context = pcep.PCEP()
    print(clsock[1])
    msg=clsock[0].recv(1000)
    pcep_context.parse_rcved_msg(msg)
    clsock[0].send(pcep_context.generate_open_msg(20))
    ka_greenlet = gevent.spawn(send_ka,pcep_context,clsock[0])
    while True: 
        msg=clsock[0].recv(1000)
        pcep_context.parse_rcved_msg(msg)
        #time.sleep(100)
    clsock[0].close()

def main():
    servsock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    servsock.bind((SERVADDR,SERVPORT))
    servsock.listen(MAXCLIENTS)
    while True:
        client = servsock.accept()
        gevent.spawn(pcc_handler,client)

if __name__ == '__main__':
    main()
