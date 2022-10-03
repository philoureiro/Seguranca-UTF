#! /usr/bin/env python

import socket
import sys
import time
import threading
import select
import traceback
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key

print("Gerando chave privada RSA...")
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
#Chave privada gerada
print("Gerando chave publica RSA...")
public_key = private_key.public_key()
#Chave publica gerada
print("Gerando uma chave simétrica utilizando o Fernet...")
symetricKey = Fernet.generate_key()
#Chave simétrica gerada


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
        received_serialized_server_key = self.sock.recv(1024)
        server_public_key = load_pem_public_key(received_serialized_server_key)
        #Recebeu a chave publica do servidor
        print("Criptografando chave simétrica utilizando a chave publica do servidor...")
        encryptedSymetricKey = server_public_key.encrypt(
            symetricKey,
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )
        #Criptografou a chave simétrica
        print("Enviando chave simétrica criptograda para o servidor...")
        self.send(host, port, encryptedSymetricKey)
        # print("Enviou a chave publica")
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
            data = msg.encode()
            encryptedData = f.encrypt(data)
            self.send(host, port, encryptedData)
        return (1)


if __name__ == '__main__':
    print("Starting client...")
    cli = Client()
    cli.start()