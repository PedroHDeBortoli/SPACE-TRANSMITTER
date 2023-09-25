import socket
import threading
import os
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

def receive_messages(client_socket):
    while True:
        data = client_socket.recv(1024)
        if not data:
            break
        try:
            message = data.decode('utf-8')
            print("Recebido:", message)
        except UnicodeDecodeError:
            print("Recebido (dados binários):", data)

def validate_data_and_signature(data, signature, sonda_public_key):
    h = SHA256.new(data)
    try:
        pkcs1_15.new(sonda_public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
    
HOST_A = '127.0.0.1'
PORT_A = 443

server_socket_a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket_a.bind((HOST_A, PORT_A))
server_socket_a.listen()

print('Aguardando conexões no Computador A...')
client_socket_a, client_address_a = server_socket_a.accept()
print('Conexão estabelecida com:', client_address_a)

receive_thread = threading.Thread(target=receive_messages, args=(client_socket_a,))
receive_thread.start()

while True:
    data = client_socket_a.recv(1024)
    if not data:
        break

    signature = client_socket_a.recv(1024)

    sonda_public_key = RSA.import_key(client_socket_a.recv(1024))

    if validate_data_and_signature(data, signature, sonda_public_key):
        print("Dados recebidos com sucesso.")
    else:
        print("Arquivo ou assinatura inválidos.")

server_socket_a.close()    