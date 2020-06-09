# ssPy.py - created 9/06/20
# A python module utilizing RSA and AES to facilitate
# encrypted two way comunication between programs
# using TCP sockets.
# To Do:
# Add facility to gracefully close connection and reset keys
import socket
import threading
from Crypto import Random
import struct
from Crypto.PublicKey import RSA
import Crypto.Cipher.AES as AES
import random, string # I don't trust random for key generation but it'll have to do for the time being

class Base:
    """Base class containing methods shared  by both Client and Server"""
    def __init__(self):
        self.bs = AES.block_size
        self.seedRSA = Random.new().read
        self.RSAKey = False
        self.AESKey = False

    def addPadding(self, s):
        return s + ((16 - len(s) % 16) * '`')

    def removePadding(self, s):
        return s.replace('`','')

    def generateRSAKeys(self):
        self.RSAKey = RSA.generate(1024, self.seedRSA)


class Server(Base):
    """Server class contains methods for listening for and establish a
    connection from the server side """
    def __init__(self, local_host, local_port, verbose=False):
        Base.__init__(self)
        self.local_host = local_host
        self.local_port = local_port
        self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.soc.bind((self.local_host,self.local_port))

    def listen(self):
        print("[*] Listening on %s:%d"%(self.local_host,self.local_port))
        self.soc.listen(5)
        self.con_soc, self.addr = self.soc.accept()
        print("[*] Accepted connection from: %s:%d"%(self.addr[0],self.addr[1]))
        self.shareRSAKeys()
        self.shareAESKeys()

    def shareRSAKeys(self):
        self.generateRSAKeys()
        #try:
        self.con_soc.send(self.RSAKey.publickey().exportKey())
        self.clientRSAKey = RSA.importKey(self.con_soc.recv(4072))
        #except:
        #    print("[!] Failed to exchange keys")
        #    exit()

    def generateAESKey(self): # AES is symetric key system so only server needs this code
        self.ptAESKey = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for x in range(32))
        self.AESiv = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for x in range(16))
        self.AESKey = AES.new(self.ptAESKey, AES.MODE_CFB, self.AESiv)


    def shareAESKeys(self):
        self.generateAESKey()
        #try:
        self.con_soc.send(self.clientRSAKey.encrypt((self.ptAESKey+":"+self.AESiv).encode(), None)[0])
        response = self.con_soc.recv(4072)
        print(response)
        if not response == b'Recived':
            print("[!] Failed to share AES key")
        #except Exception,e:
        #    print(e)
    def sendEncrypted(self, msg):
        if not self.AESKey:
            #Raise exception
            print('[!] You must share an AES key before attempting encrypted transmission')
        else:
            crypto = self.AESKey.encrypt(self.addPadding(msg))
            self.con_soc.send(crypto)
            print("[*] Sent %s" % (str(crypto)))

    def reciveEncrypted(self):
        if not self.AESKey:
            #Raise exception
            print('[!] You must share an AES key before attempting encrypted transmission')
        else:
            crypto = self.con_soc.recv(4072)
            if not crypto == b'End':
                msg = self.removePadding(self.AESKey.decrypt(crypto).decode())
                print("[*] Recived %s" % (str(crypto)))
                return msg
            else:
                self.terminate()
    def terminate():
        print("[*] Peer sent end request. Terminating connection and reseting keys")
        self.con_soc.close()
        self.seedRSA = Random.new().read
        self.RSAKey = False
        self.AESKey = False
        self.AESiv = False
        self.ptAESKey = False
        self.clientRSAKey = False

    def dissconect(self):
        print("[*] Sending end request. Terminating connection and reseting keys")
        self.con_soc.send(b'End')
        self.seedRSA = Random.new().read
        self.RSAKey = False
        self.AESKey = False
        self.AESiv = False
        self.ptAESKey = False
        self.clientRSAKey = False

class Client(Base):
    """Client class contains methods for establish a connection from
    the client  side """
    def __init__(self,remote_host, remote_port, verbose=False):
        Base.__init__(self)
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self):
        self.soc.connect((self.remote_host, self.remote_port))
        self.shareRSAKeys()
        self.shareAESKeys()

    def shareRSAKeys(self):
        self.generateRSAKeys()
        try:
            self.serverRSAKey = RSA.importKey(self.soc.recv(4072))
            self.soc.send(self.RSAKey.publickey().exportKey())
        except:
            print("[!] Failed to exchange keys")

    def shareAESKeys(self):
        #try:
        ptAESKey, self.AESiv = self.RSAKey.decrypt(self.soc.recv(4072)).decode().split(':')
        self.AESKey = AES.new(ptAESKey, AES.MODE_CFB, self.AESiv)
        self.soc.send(b'Recived')
        #except Exception e:
        #    print(e)

    def sendEncrypted(self, msg):
        if not self.AESKey:
            #Raise exception
            print('[!] You must share an AES key before attempting encrypted transmission')
        else:
            crypto = self.AESKey.encrypt(self.addPadding(msg))
            self.soc.send(crypto)
            print("[*] Sent %s" % (str(crypto)))

    def reciveEncrypted(self):
        if not self.AESKey:
            #Raise exception
            print('[!] You must share an AES key before attempting encrypted transmission')
        else:
            crypto = self.soc.recv(4072)
            if not crypto == b'End':
                msg = self.removePadding(self.AESKey.decrypt(crypto).decode())
                print("[*] Recived %s" % (str(crypto)))
                return msg
            else:
                self.terminate()

    def terminate():
        print("[*] Peer sent end request. Terminating connection and reseting keys")
        self.soc.close()
        self.seedRSA = Random.new().read
        self.RSAKey = False
        self.AESKey = False
        self.AESiv = False
        self.serverRSAKey = False

    def dissconect(self):
        print("[*] Sending end request. Terminating connection and reseting keys")
        self.soc.send(b'End')
        self.seedRSA = Random.new().read
        self.RSAKey = False
        self.AESKey = False
        self.AESiv = False
        self.serverRSAKey = False
