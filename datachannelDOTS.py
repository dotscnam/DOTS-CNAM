#!/usr/bin/env python3
import socket
import ssl
import secrets
import threading
import time

global ctime #needed to be get by functions
ctime = time.time()

HOST = "127.0.0.1"
PORT = 60000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server = ssl.wrap_socket(
    server, server_side=True, keyfile="/home/debian/Documents/cert/key.pem", certfile="/home/debian/Documents/cert/cert.pem"
)#wrapper ssl to encrypt trafic

def deliverkey(): # function to deliver key if payload match and if key and cert are corrects
    HOST = "127.0.0.1"
    PORT = 60000

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server = ssl.wrap_socket(
    server, server_side=True, keyfile="/home/debian/Documents/cert/key.pem", certfile="/home/debian/Documents/cert/cert.pem"
    )
    server.bind((HOST, PORT))
    server.listen(0)

    while True:
        connection, client_address = server.accept()
        while True:
            data = connection.recv(1024)
            if not data:
                break
            if data == 'here'.encode("utf-8"):
                print('[+] \033[37mping received\033[0m')
                clienttime()
            elif data == 'no more key, need 1 !'.encode("utf-8"):
                #print ('\033[37m[+] giving key from keys file\033[0m')
                pass
                try:
                    with open("/home/debian/Téléchargements/aiocoap/keys","r") as keyfile: #the dataserver need to access at the keys generated by the signalserver
                        listkey = []
                        for key in keyfile:  
                            key = key.rstrip()
                            listkey.append(key)
                            #print(listkey)
            
                    keyused = secrets.choice(listkey) #it select keys using secret it allow to be random
                    connection.send(keyused.encode())
                    print('[+] key sent to the client : ' + '\033[34m' + keyused + '\033[0m')
                    pass
                except:
                    connection.close() #when keys send then close the connection
                    pass
def originaltime(): #all function below are used for telemtry
    threading.Timer(30.0, originaltime).start()
    global otime
    otime = time.time()
    #print(otime)

def clienttime():
    global ctimeup
    ctimeup = time.time()

def checkclienthere():
    threading.Timer(8.0, checkclienthere).start()
    global otime
    try:
        #print('time is ', otime)
        #print('client last seen ', ctimeup)
        if otime > ctimeup + 30.0:
            print('[+] \033[31mclient lost\033[0m')
        elif otime < ctimeup + 30.0:
            print('[+] \033[32mclient is here\033[0m')
    except:
        #print('time is ', otime)
        #print('client last seen ', ctime)
        if otime > ctime + 30.0:
            print('[+] \033[31mclient lost\033[0m')
        elif otime < ctime + 30.0:
            print('[+] \033[32mclient is here\033[0m')
        
    
        
    

def main():
    
    
    originaltime()
    checkclienthere()
    deliverkey()
main()
