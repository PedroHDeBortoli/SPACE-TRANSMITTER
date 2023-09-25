import socket
import threading
import os
import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

data_filename = ""
sonda_nome = ""

# Funções para Gerar e Enviar chaves RSA
def generate_rsa_key_pair(sonda_nome):
    key = RSA.generate(1024)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(f'{sonda_nome}.private.pem', 'wb') as private_key_file:
        private_key_file.write(private_key)

    with open(f'{sonda_nome}.public.pem', 'wb') as public_key_file:
        public_key_file.write(public_key)

def send_public_key(sonda_nome, server_socket):
    with open(f'{sonda_nome}.public.pem', 'rb') as public_key_file:
        public_key = public_key_file.read()
    
    server_socket.send(public_key)

# Funções para coletar dados da sonda, criptografá-los e salvar em um arquivo
def collect_and_encrypt_data(sonda_nome):
    global data_filename

    local = input("Local: ")
    data_atual = datetime.datetime.now().strftime("%d.%m")
    temperatura = input("Temperatura: ")
    radiacao_alfa = input("Radiação Alfa: ")
    radiacao_beta = input("Radiação Beta: ")
    radiacao_gama = input("Radiação Gama: ")

    data = f"Local: {local}\nData: {data_atual}\nTemperatura: {temperatura}\nRadiação Alfa: {radiacao_alfa}\nRadiação Beta: {radiacao_beta}\nRadiação Gama: {radiacao_gama}"
    data_filename = f'{local.replace(" ", "_")}{sonda_nome}{data_atual}.txt'  

    key = os.urandom(16)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())

    with open(data_filename, 'wb') as data_file:
        data_file.write(cipher.nonce)
        data_file.write(tag)
        data_file.write(ciphertext)

# Funções para Assinatura de Dados e Envio com Verificação
def generate_signature(sonda_nome, data_filename):
    with open(f'{sonda_nome}.private.pem', 'rb') as private_key_file:
        private_key = RSA.import_key(private_key_file.read())
    
    with open(data_filename, 'rb') as data_file:
        data = data_file.read()

    h = SHA256.new(data)
    signature = pkcs1_15.new(private_key).sign(h)

    with open(f'{data_filename}.assinatura', 'wb') as signature_file:
        signature_file.write(signature)

def send_data_and_signature(sonda_nome, server_socket):
    global data_filename

    if not os.path.exists(data_filename):
        print(f"Arquivo {data_filename} não encontrado. Certifique-se de que o arquivo existe.")
        return
    
    signature_filename = f'{data_filename}.assinatura'

    if not os.path.exists(signature_filename):
        print(f"Arquivo {signature_filename} não encontrado. Certifique-se de que o arquivo existe.")
        return
    
    with open(data_filename, 'rb') as data_file:
        data = data_file.read()
    
    with open(signature_filename, 'rb') as signature_file:
        signature = signature_file.read()
    
    server_socket.send(b'DADOS')

    server_socket.send(data)
    server_socket.send(signature)

    print("Recebido com sucesso!")

    continuar = input("Aperte Enter para continuar ou digite '6' para sair...")
    if continuar == '6':
        print("Programa Encerrado!")
        return

def receive_confirmation(server_socket):
    confirmation = server_socket.recv(1024)
    print(confirmation.decode())

# Funções do Menu
def main():
    HOST_B = '127.0.0.1'
    PORT_B = 443

    client_socket_b = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket_b.connect((HOST_B, PORT_B))

    while True:
        print("\nMenu de Opções:")
        print("1 - Cadastrar Sonda e Gerar Par de Chaves")
        print("2 - Enviar Chave da Sonda")
        print("3 - Coletar Dados da Sonda")
        print("4 - Gerar Assiantura dos Dados Coletados")
        print("5 - Enviar Dados para a Terra")
        print("6 - Sair")

        opcao = input("Escolha uma opção: ")

        if opcao == '1':
            global sonda_nome
            sonda_nome = input ("Digite o nome da Sonda: ")
            generate_rsa_key_pair(sonda_nome)
            print("Acesso criado!")
        elif opcao == '2':
            send_public_key(sonda_nome, client_socket_b)
            print("Acesso criado!")
        elif opcao == '3':
            collect_and_encrypt_data(sonda_nome)
            print("Acesso criado!")
        elif opcao == '4':
            generate_signature(sonda_nome, data_filename)
            print("Acesso criado!")
        elif opcao == '5':
            send_data_and_signature(sonda_nome, client_socket_b)
            receive_confirmation(client_socket_b)
            print("Acesso criado!")
        elif opcao == '6':
            print("Programa Encerrado!")
            break
        else:
            print("Opção inválida. Tente novamente.")

        continuar = input("Aperte Enter para continuar ou digite '6' para sair...")
        if continuar == '6':
            print("Programa Encerrado!")
            return       

if __name__ == "__main__":
    main()
