#! /usr/bin/env python

import setuptools 
import json
import socket
import sys
import traceback
import threading
import select
import hashlib
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

print("Gerando chave privada...")
private_key = rsa.generate_private_key(#Chave privada 
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

print("Gerando chave publica RSA...")
public_key = private_key.public_key()#Chave publica 


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
                        print("Recebendo mensagem")
                        received_client_contact = sock.recv(1024)
                        print('desserializando dados')
                        loaded_contact = json.loads(received_client_contact.decode())
                        digestProvider = hashlib.blake2b()
                        digestProvider.update(b'%s'%(loaded_contact['msg'].encode()))
                        refer_digest = digestProvider.hexdigest()
                        print('Verificando integridade')
                        if(loaded_contact['digest'] != refer_digest):
                            raise Exception('Não foi possível validar a integridade da mensagem')
                        print("Integridade Validada com sucesso")
                        recovered_client_symetric_key = b''# Conterá a chave simétrica do cliente que será recuperada de CONNECTEDS_CLIENTS
                        print("Definindo chave de criptografia para respectivo cliente...")
                        for client in CONNECTEDS_CLIENTS:
                            if sock.getpeername() == client['peer_name']:
                                recovered_client_symetric_key = client['symetric_key']
                        f = Fernet(recovered_client_symetric_key)
                        print("Descriptografando mensagem...")
                        decryptedMsg = f.decrypt((loaded_contact['msg'].encode()))# Mensagem descriptografada

                        if decryptedMsg.decode() == '':
                            print(str(sock.getpeername()))
                            print("Mensagem vazia")
                            continue
                        else:
                            print("Enviando mensagem para a lista de transmissão...")
                            TO_BE_SENT.append(decryptedMsg)
                            SENT_BY[decryptedMsg] = (str(sock.getpeername()))
                            
                        
                       
                    except:
                        print(str(sock.getpeername()))
                        print("Não foi possível recuperar a mensagem, fechando socket...")
                        SOCKET_LIST.remove(sockfd)
                        break
                        
    def clientRegistry(self, sockfd, addr):
        read, write, err = select.select(SOCKET_LIST, [], [], 0)

        print("Serializando dados para envio da chave publica...")

        PEM_serialized_public_key = public_key.public_bytes(
             encoding=serialization.Encoding.PEM,
             format=serialization.PublicFormat.SubjectPublicKeyInfo
         )
        digestProvider = hashlib.blake2b()
        digestProvider.update(PEM_serialized_public_key)
        digest = digestProvider.hexdigest()
        data = {'server_public_key': PEM_serialized_public_key.decode(), 'digest': digest}
        dumped = json.dumps(data).encode()
        print("enviando chave publica para o cliente...")
        for item in SOCKET_LIST:
            if item == sockfd:
                item.send(dumped)

        print("Recebendo chave simétrica criptografada do cliente")
        try:
            received_symetric_key = sockfd.recv(2048)
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
        except:
            print('Não foi possível receber a chave simétrica')



class handle_connections(threading.Thread):
    def run(self):
        while 1:
            read, write, err = select.select([], SOCKET_LIST, [], 0)
            for items in TO_BE_SENT:
                for s in write:
                    try:
                        if (str(s.getpeername()) == SENT_BY[items]):
                            print("Impedindo a transmissão da mensagem para o próprio remetente que a enviou %s" % (str(s.getpeername())))
                            continue
                        
                       # Criptografar mensagens correspondentemente com a chave simétrica de cada cliente.
                        encrypted_msg_with_client_symetric_key = ""
                        for item in CONNECTEDS_CLIENTS:
                            if item['addr'] == s.getpeername():
                                client_symetric_key = item['symetric_key']
                                f = Fernet(client_symetric_key)
                                encrypted_msg_with_client_symetric_key = f.encrypt(items) # Mensagem criptografada
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
   