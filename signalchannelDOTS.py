#!/usr/bin/env python3

import datetime
import logging


import asyncio

import aiocoap.resource as resource
import aiocoap

import secrets #use to generate nonce
import threading #multithread
import os
import sys


def checkkeys():
        threading.Timer(1.0, checkkeys).start() #check every second
        global keysar
        keysar = []
        with open ('keys','r') as keys:
            i = 0
            for line in keys:
                i = i + 1
                line = line.rstrip()
                if line in keysar: #si l cle est deja dans la liste on passe
                    pass
                else:
                    keysar.append(line)

            if i < 7: #if there are less than 7 keys we generate nonce
                print ('[+] ',keysar)
                print('\033[33m[+] pas assez de keys...adding keys\033[0m')
                with open('keys','a') as keysadd:
                    keysadd.write(secrets.token_urlsafe(32) + '\r\n')
            else:
                print ('\033[34m[+] KEYS ok !\033[0m')
            
              


class mitigation(resource.Resource): #mitigation ressource coap

    def __init__(self):
        super().__init__()

        self.handle = None  

    async def render_get(self, request):
        print("\033[34m[+] Used protocol: %s.\033[0m" % request.remote.scheme)
        print("\033[34m[+] Request came from %s.\033[0m" % request.remote.hostinfo) #some info about client
        
        payloadclient = request.payload
        payloadclient = payloadclient.decode("utf-8")#encode payload in utf8
        #print(payloadclient)
        if payloadclient in keysar: #if client send good payload we reroute traffic
            payloadtosend = ("\n[+] mitigation in progress")
            
            print ('\033[1m\033[32m[+] mitigation ok\033[0m')
            print('\033[33m[+] removing key...\033[0m')
            
            keysar.remove(payloadclient)
            os.system('rm -rf keys')
            with open('keys','a') as newkey:
                for key in keysar:
                    newkey.write(key+'\r\n')
            os.system('''sudo /home/debian/Documents/dropddos.sh''') #here it-s simulated by using iptables
        else:
            print('\033[31m[+]------------------------    bad request        ----------------------------------\033[0m')
            print (payloadclient)
            payloadtosend = 'nope'
            pass
        return aiocoap.Message(content_format=0,payload=payloadtosend.encode('utf8'))


# logging setup

#logging.basicConfig(level=logging.INFO)
#logging.getLogger("coap-server").setLevel(logging.DEBUG)

def main():
    # Resource tree creation
    checkkeys()
    root = resource.Site()

    root.add_resource(['.well-known', 'core'],
            resource.WKCResource(root.get_resources_as_linkheader))
    
    root.add_resource(['mitigation'], mitigation())
    #listenout = ('0.0.0.0',4646)
    asyncio.Task(aiocoap.Context.create_server_context(root)) #to be rfc compliance we can change the listen port to 4646 by adding after root bind=listenout
    asyncio.get_event_loop().run_forever()
    

if __name__ == "__main__":
    main()
