#! /usr/bin/env python

import socket
import sys
import traceback
import threading
import select
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet

SOCKET_LIST = []
TO_BE_SENT = []
SENT_BY = {}
CONNECTEDS_CLIENTS = []#Armazenará clientes conectados juntamente com chave simétrica que será recebida e descriptografada

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

class Server(threading.Thread):

    def init(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.bind(('', 5535))
        self.sock.listen(2)
        SOCKET_LIST.append(self.sock)
        print("Server started on port 5535")

    def run(self):
        while 1:
            read, write, err = select.select(SOCKET_LIST, [], [], 0)
            for sock in read:
                if sock == self.sock:
                    sockfd, addr = self.sock.accept()
                    print("Recebendo dados do cliente...", str(addr))
                    SOCKET_LIST.append(sockfd)
                    print("Registrando cliente... ")
                    self.clientRegistry(sockfd, addr)
                    #Cliente registrado


                else:
                    try:     
                        received_client_contact = sock.recv(1024)
                        print("Recebendo mensagem")
                        recovered_client_symetric_key = b''
                        for client in CONNECTEDS_CLIENTS:
                            if sock.getpeername() == client['peer_name']:
                                recovered_client_symetric_key = client['symetric_key']
                            
                        print("Definindo chave de criptografia para respectivos clientes...")
                        f = Fernet(recovered_client_symetric_key)
                        decryptedMsg = f.decrypt(received_client_contact)
                        if decryptedMsg == '':
                            print(str(sock.getpeername()))
                            print("Mensagem vazia")
                            continue
                        else:
                            print("Enviando mensagem para a lista de transmissão...")
                            TO_BE_SENT.append(decryptedMsg)
                            SENT_BY[decryptedMsg] = (str(sock.getpeername()))
                            
                        break
                       
                    except:
                        print(str(sock.getpeername()))
                        print("Não foi possível recuperar a mensagem")
                        
    def clientRegistry(self, sockfd, addr):
        read, write, err = select.select(SOCKET_LIST, [], [], 0)
        print("Serializando chave publica...")
        PEM_serialized_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print("enviando chave publica para o cliente...")
        for item in SOCKET_LIST:
            if item == sockfd:
                item.send(PEM_serialized_public_key)
        print("Recebendo chave simétrica criptografada do cliente")
        received_symetric_key = sockfd.recv(1024)
        print("Descriptografando chave simetrica...")
        decrypted_client_symetric_key = private_key.decrypt(
            received_symetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("Armazenando chave simetrica do cliente")
        CONNECTEDS_CLIENTS.append(
                {
                "peer_name": sockfd.getpeername(),
                "addr": addr,
                "symetric_key": decrypted_client_symetric_key
                }
            )


class handle_connections(threading.Thread):
    def run(self):
        while 1:
            read, write, err = select.select([], SOCKET_LIST, [], 0)
            for items in TO_BE_SENT:
                for s in write:
                    try:
                        if (str(s.getpeername()) == SENT_BY[items]):
                            print("Impedindo o envio da mensagem para o próprio remetente que há enviou %s" % (str(s.getpeername())))
                            continue
                        
                       # Criptografar mensagens correspondentemente com a chave simétrica de cada cliente.
                        encrypted_msg_with_client_symetric_key = ""
                        for item in CONNECTEDS_CLIENTS:
                            if item['addr'] == s.getpeername():
                                client_symetric_key = item['symetric_key']
                                f = Fernet(client_symetric_key)
                                encrypted_msg_with_client_symetric_key = f.encrypt(items)
                                
                        #print("encrypted msg", encrypted_msg_with_client_symetric_key)
                        print("Enviando mensagem criptografada simetricamente com chave respectiva")
                        print("Sending to %s" % (str(s.getpeername())))
                        s.send(encrypted_msg_with_client_symetric_key)

                    except:
                        traceback.print_exc(file=sys.stdout)
                TO_BE_SENT.remove(items)
                del (SENT_BY[items])


if __name__ == '__main__':
    srv = Server()
    srv.init()
    srv.start()
    print(SOCKET_LIST) 
    print("Server started")
    handle = handle_connections()
    handle.start()
   