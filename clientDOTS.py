#!/usr/bin/env python3

import logging
import asyncio

from aiocoap import *

import secrets
import time

import socket
import ssl
import threading
import os
import sys

from os import listdir
from os.path import isfile, join

logging.basicConfig(level=logging.INFO)
#some coulours code only work if sys is imported
colours = {
	"default"    :    "\033[0m",
	# style
	"bold"       :    "\033[1m",
	"underline"  :    "\033[4m",
	"blink"      :    "\033[5m",
	"reverse"    :    "\033[7m",
	"concealed"  :    "\033[8m",
	# couleur texte
	"black"      :    "\033[30m", 
	"red"        :    "\033[31m",
	"green"      :    "\033[32m",
	"yellow"     :    "\033[33m",
	"blue"       :    "\033[34m",
	"magenta"    :    "\033[35m",
	"cyan"       :    "\033[36m",
	"white"      :    "\033[37m",
	# couleur fond
	"on_black"   :    "\033[40m", 
	"on_red"     :    "\033[41m",
	"on_green"   :    "\033[42m",
	"on_yellow"  :    "\033[43m",
	"on_blue"    :    "\033[44m",
	"on_magenta" :    "\033[45m",
	"on_cyan"    :    "\033[46m",
	"on_white"   :    "\033[47m" }

def ping(): #telemetry
    threading.Timer(30.0, ping).start()
    HOST = "127.0.0.1"
    PORT = 60002 # 60002 is the port used by the client to bind a tls connection

    SERVER_HOST = "127.0.0.1"
    SERVER_PORT = 60000 #we set 60000 as server port

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    client = ssl.wrap_socket(client, keyfile="/home/debian/Documents/cert/key.pem", certfile="/home/debian/Documents/cert/cert.pem") #using key and cert

    #print ('\033[34m[+] Client to Data Channel: asking keys...\033[0m')
    try:
        client.bind((HOST, PORT))
        client.connect((SERVER_HOST, SERVER_PORT))

        print('ping sent')
        client.send("here".encode("utf-8"))
        client.close()
    except:
        pass
    

def trigger(): #check every 5 second if snortfile is createdm in our case snort create file only if it detects attack
    threading.Timer(5.0, trigger).start()
    mypath = '/home/debian/Documents/snortfiles'
    if os.path.isdir(mypath):
        
        onlyfiles = [f for f in listdir(mypath) if isfile(join(mypath, f))]
        for fichier in onlyfiles:
            size = os.path.getsize('/home/debian/Documents/snortfiles/'+fichier)
            if size != 0:#so if there is a file in a the path above and if the file is not empty there is an attack
        #if onlyfiles:
                print('there is file' + str(onlyfiles))
                asyncio.run(askmitigation())
                os.system('cp /home/debian/Documents/snortfiles/* /home/debian/Documents/')
                os.system('rm -rf /home/debian/Documents/snortfiles/*')
            #for file in onlyfiles:
            #    with open(mypath + '/' + file, 'r') as snortfile:
            #        content = snortfile.readlines()
            #        print(content)
        else:
            print('no attack detected')
            
    else:
        print("Errors the directory is not found")

    #mypath = os.listdir('/home/debian/Documents/snortfiles')
    
        
        #time.sleep(5)
        #asyncio.get_event_loop().run_until_complete(askmitigation())
        
def checkkeys():# here the client check if there are nonce that is needed to perform mitigation and authenticate the client
        threading.Timer(1.0, checkkeys).start()
        global keysar
        keysar = []
        #filesize = os.path.getsize("/home/debian/Documents/keysclient")
        try:
            with open("/home/debian/Documents/keysclient","r") as keyfile:
                i = 0
                for line in keyfile:
                    i = i + 1
                    line = line.rstrip()
                    if line in keysar: #si l cle est deja dans la liste on passe
                        pass
                    else:
                        keysar.append(line)
                if i < 5:
                    print ('\033[33m[+] Client : -5 keys... asking keys to Data Channel.\033[0m')
                    nomorekey()
                else:
                    print ('\033[34m[+] KEY client ok!\033[0m')
        except:
            #print("\033[33m[+] file issue...test to create file.\033[0m")
            os.system('touch /home/debian/Documents/keysclient')
            
            

def nomorekey(): # if this function is tigger the client will use its tls connection to get nonce via datachannel
    HOST = "127.0.0.1"
    PORT = 60002

    SERVER_HOST = "127.0.0.1"
    SERVER_PORT = 60000

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    client = ssl.wrap_socket(client, keyfile="/home/debian/Documents/cert/key.pem", certfile="/home/debian/Documents/cert/cert.pem")

    #print ('\033[34m[+] Client to Data Channel: asking keys...\033[0m')
    try:
        client.bind((HOST, PORT))
        client.connect((SERVER_HOST, SERVER_PORT))

    
        client.send("no more key, need 1 !".encode("utf-8"))
        dataFromServer = client.recv(1024);
        print('[+] Data Channel to client: ' + '\033[34m' + dataFromServer.decode() + '\033[0m');
        client.close()
        key = dataFromServer.decode()
        addingkey(key)
    except:
        #print('\033[31mno keys..can t join data channel \033[0m')
        pass


def addingkey(key): #the function add the key to the client key file
        key = key
        if key in keysar:
                #print (key)
                #print (keysar)
                print ('\033[31m[+] already go the keys...reasking keys.\033[0m')
        else:
                with open("/home/debian/Documents/keysclient","a") as keyfileclient:
                        keyfileclient.write(key+'\r\n')
                        print ('\033[32m[+] key added !!! \033[0m' )

def removekeys(keyused): #this function remove key if it's needed
    try:
        keytoremove = keyused.decode("utf-8")
        newlist = keysar
        idx = newlist.index(keytoremove)
        newlist.pop(idx) #other method to remove an elem in list
        os.system('rm -rf /home/debian/Documents/keysclient')
        with open('/home/debian/Documents/keysclient','a') as newkey:
            for key in newlist:
                newkey.write(key+'\r\n')
            print ('\033[33m[+] keyremoved from keysclient file.\033[0m')
    except:
        pass


async def askmitigation(): #this function ask for mitigation
    
    isitok = 0
    
    while isitok != 1:
        try:
            with open("/home/debian/Documents/keysclient","r") as keyfile:
                listkey = []
                for key in keyfile:
                    key = key.rstrip()
                    listkey.append(key)
            keyused = secrets.choice(listkey)
            keyused = bytes(keyused, encoding='utf8')
            #print(listkey)
            print('[+] key used: ' + '\033[34m' + str(keyused) + '\033[0m')
            protocol = await Context.create_client_context()
            request = Message(code=GET, uri='coap://localhost/mitigation', payload=keyused)
            response = await protocol.request(request).response #the client need to ask for some ressource here its mitigation and use payload to transfer its nonce
        except Exception as e:
            #print('\033[31mFailed to fetch resource:\033[0m')
            print('\033[31m Something fail, reasons: \033[0m' + str(e))
            #print(e)
        else:
            print('[+] Response code: %s' %(response.code))
            print('[+] Remote Server: %s' %(response.remote.hostinfo))
            #print('[+] Response payload: %s '%(response.payload.decode('utf8')))
            if response.payload.decode('utf8') == '\n[+] mitigation in progress':
                #print(colours['green'] + '[+] Signal chanel to client: mitigiation ok.')
                print('\033[1m\033[32m[+] Signal chanel to client: mitigation in progress.\033[0m')
                #print('[+] Signal chanel to client: mitigiation ok. \r\n')
                removekeys(keyused)
                isitok = 1
            else:
                removekeys(keyused)
                print('\033[31m[+] Signal channel to client: Failed. Retry...\033[0m')


    

def main():#start the client
    ping()
    checkkeys()
    trigger()

if __name__ == "__main__":
    main()
