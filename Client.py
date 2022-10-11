#! /usr/bin/env python

import json
import socket
import sys
import time
import threading
import select
import traceback
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.fernet import Fernet

print("Gerando uma chave simétrica utilizando o módulo Fernet...")
symetricKey = Fernet.generate_key()#Chave simétrica

 


############################################################# CLIENT/SERVER ###################################################################################
class Server(threading.Thread):
    def initialise(self, receive):
        self.receive = receive

    def run(self):
        lis = []
        lis.append(self.receive)
        while 1:
            read, write, err = select.select(lis, [], [])
            for item in read:
                try:
                    s = item.recv(1024)
                    if s != '':
                        chunk = s
                        f = Fernet(symetricKey)
                        decryptedMsg = f.decrypt(chunk)
                        print(decryptedMsg.decode() + '\n>>')

                        
                except:
                    traceback.print_exc(file=sys.stdout)
                    break

############################################################# CLIENT/CLIENT ###################################################################################
class Client(threading.Thread):
    def connect(self, host, port):
        self.sock.connect((host, port))

    def send(self, host, port, msg):
        sent = self.sock.send(msg)
        # print "Sent\n"

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            host = input("Enter the server IP \n>>")
            port = int(input("Enter the server Destination Port\n>>"))
        except EOFError:
            print("Error")
            return 1

        print("Connecting...\n")
        s = ''
        self.connect(host, port)
        print("Connected\n")

        print("Recebendo chave publica do servidor...")
        received_data = self.sock.recv(1024)
        received_data = received_data.decode()
        recovered = json.loads(received_data)
        digestProvider = hashlib.blake2b()
        digestProvider.update(recovered['server_public_key'].encode())
        refer_hash = digestProvider.hexdigest()
        print("Validando integridade da chave pública do servidor")
        print(refer_hash, recovered['digest'])
        if(refer_hash != recovered['digest']):
            raise Exception('Não foi possível validar a integridade da chave pública')
        print("Desserializando chave pública do servidor")
        server_public_key = load_pem_public_key(recovered['server_public_key'].encode())# Desserealizou a chave pública


        print("Criptografando chave simétrica utilizando a chave publica do servidor...")
        encryptedSymetricKey = server_public_key.encrypt(# chave simétrica criptografada
            symetricKey,
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )
        print("Enviando chave simétrica para o servidor...")
        self.send(host, port, encryptedSymetricKey)
        

        user_name = input("Enter the User Name to be Used\n>>")
        receive = self.sock
        time.sleep(1)

        srv = Server()
        srv.initialise(receive)
        srv.daemon = True
        print("Starting service...")
        
        
        srv.start()
        
        while 1:
            # print "Waiting for message\n"
            msg = input('>>')
            if msg == 'exit':
                break
            if msg == '':
                continue
            # print "Sending\n"
            msg = user_name + ': ' + msg
            f = Fernet(symetricKey)
            encodedMsg = msg.encode()
            encryptedMsg = f.encrypt(encodedMsg)
            digestProvider = hashlib.blake2b()
            digestProvider.update(encryptedMsg)
            digest = digestProvider.hexdigest()
            encryptedMsg = encryptedMsg.decode()
            data = {'msg': encryptedMsg, 'digest': digest}
            dumped = json.dumps(data).encode()
            self.send(host, port, dumped)
            
        return (1)


if __name__ == '__main__':
    print("Starting client...")
    cli = Client()
    cli.start()