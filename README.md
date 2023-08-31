# About This Keylogger
• Every 10 seconds you get **Keyboard**, **Mouse**, **ScreenShot**, **Microphone** and **SystemInfo** inputs from target computer and send to your mail.

• If the target finds the code and opens the file, the program **Deletes** itself.

***• The aim of the project is to test the security of Operating Systems.***

# Warning

• You need to run the script as administrator because the file copies itself to `C:\Windows\System32`

• Also, remember that **even the higher-level** file copying functions like `shutil.copy() and shutil.copy2()` can't copy all file metadata.

• On Windows, file owners, ACLs and alternate data streams are not copied.


# INSTALLATION
**• pip install -r requirements.txt**
# USAGE

• Create an account on https://mailtrap.io/ to use a temp mail.

• Click on ***Show Credentials*** to see your **Username** and **Password.**

![image](https://github.com/isPique/Keylogger/assets/139041426/840ab983-424b-4407-a6ba-697abf2f3dfb)

• After clicking on ***Show Credentials*** set your own **SMTP Username** and **SMTP Password** on `keylogger.py`

![image](https://github.com/isPique/Keylogger/assets/139041426/2c0a42b0-477e-4bb0-86ae-352e446bdc3d)

• Then create an account on https://ipinfo.io/ to get your **Access Token.**

![image](https://github.com/isPique/Keylogger/assets/139041426/45c987b1-4781-4468-9672-672e43b58672)
