import tkinter

from cryptography.fernet import Fernet
import os
import hashlib
import binascii
import tkinter as tk
master_key = b'Cp1hH7cSCOO1hpp5yQx3kPDh7rQ_4VdFjoTp1GuyH_c='


class passwordApp(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self.title("Password Manager")
        self.greeting = tk.Label(self, text="Welcome to our Password Storage service.\nPlease enter you name and password",
                         font=("ariel", 16, "bold")).grid(row=0, column=1)
        self.name_label = tk.Label(self, text="Name:").grid(row=1, column=0)
        self.websiteEntry = tk.Entry(self)
        self.nameEntry = tk.Entry(self)
        self.nameEntry.grid(row=1, column=1)
        self.password_label = tk.Label(self, text="Password:").grid(row=2, column=0)
        self.passwordEntry = tk.Entry(self)
        self.passwordEntry.grid(row=2, column=1)
        self.confirm = tk.Button(self, text='Login', bd='5',command=self.submit).grid(row=3, column=1)

    def on_button(self):
        print(self.nameEntry.get())

    def submit(self):
        name = self.nameEntry.get()
        password = self.passwordEntry.get()
        if self.login_user(name, password):
            for child in self.winfo_children():
                child.destroy()
            self.title("Password Manager")
            self.website = tk.Label(self, text="Website:", font="bold").grid(row=0, column=0)
            self.name = tk.Label(self, text="UserName:", font="bold").grid(row=0, column=1)
            listOfSites = self.get_websites_names()
            i = 1
            for site in listOfSites:
                tk.Label(self, text=site[0]).grid(row=i, column=0)
                tk.Label(self, text=site[1]).grid(row=i, column=1)
                t = i - 1
                #tk.Button(self, text='View Password', bd='5', command=lambda t=t: show_password(t)).grid(row=i, column=2)
                i += 1
            #tk.Button(self, text='Add Password', bd='5', command=add_password).grid(row=i, column=2)
            self.mainloop()
        else:
            view2 = tk.Tk()
            view2.title("Password Manager")
            tk.Label(view2, text="wrong name or password").grid(row=0, column=0)
            view2.mainloop()

    def login_user(self, name, password):
        f1 = open("user.txt", "r")
        lines = f1.readlines()
        for line in lines:
            info = line.split(",")
            if info[0] == name:
                end = len(info[1]) - 1
                salt = info[1][2:66]
                key = info[1][66:end]
                new_key = hashlib.pbkdf2_hmac(
                    'sha256',
                    password.encode('utf-8'),
                    salt.encode('ascii'),
                    100000
                )
                new_key = binascii.hexlify(new_key).decode('ascii')
                if new_key == key:
                    return True
                else:
                    return False
            else:
                return False

    def get_websites_names(self):
        f1 = open("passwords.txt", "r")
        listOfSites = []
        lines = f1.readlines()
        for line in lines:
            info = line.split(",")
            webName = [info[0], info[1]]
            listOfSites.append(webName)
        return listOfSites


app = passwordApp()
app.mainloop()


"""
def create_user(name, password):
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    hashedPassword = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000,
    )
    hashedPassword = binascii.hexlify(hashedPassword)
    storage = salt + hashedPassword
    f1 = open("user.txt", "w")
    f1.write(name + f",{storage}")
    f1.close()

def encrypt_password(website, name, password):
    key = Fernet.generate_key()
    passwordEncryptor = Fernet(key)
    encryptedPassword = passwordEncryptor.encrypt(password.encode())
    keyEncryptor = Fernet(master_key)
    encryptedKey = keyEncryptor.encrypt(key)
    f1 = open("passwords.txt", "a")
    f1.write(website+","+name+f",{encryptedPassword}\n")
    f1.close()
    f2 = open("keys.txt", "a")
    f2.write(f"{encryptedKey}\n")
    f2.close()
    return True


def decrypt_password(number):
    encryptedPassword = ""
    encryptedKey = ""
    f1 = open("passwords.txt", "r")
    f2 = open("keys.txt", "r")
    lines = f1.readlines()
    i = 0
    for line in lines:
        if i == number:
            parts = line.split(",")
            end = len(parts[2]) - 2
            encryptedPassword = parts[2][2:end]
        i += 1
    lines = f2.readlines()
    i = 0
    for line in lines:
        if i == number:
            end = line.__len__() - 2
            encryptedKey = line[2:end]
        i += 1
    keyDecryptor = Fernet(master_key)
    key = keyDecryptor.decrypt(encryptedKey.encode())
    passwordDecryptor = Fernet(key)
    password = passwordDecryptor.decrypt(encryptedPassword.encode()).decode()
    return password


def show_password(number):
    password = decrypt_password(number)
    view3 = Tk()
    view3.title("Password")
    Label(view3, text=password).grid(row=0, column=0)
    view3.mainloop()


def password_confirmation(websiteEntry, nameEntry, passwordEntry):
    website = websiteEntry.get()
    name = nameEntry.get()
    password = passwordEntry.get()
    if encrypt_password(website, name, password):
        view4 = Tk()
        view4.title("Success")
        Label(view4, text="You have successfully added a new password", font="bold").grid(row=0, column=0)
        view4.mainloop()
        submit()


def add_password():
    view3 = Tk()
    view3.title("Add Password")
    Label(view3, text="Website:").grid(row=0, column=0)
    Label(view3, text="UserName:").grid(row=1, column=0)
    Label(view3, text="Password:").grid(row=2, column=0)
    tkinter.Entry(view3, textvariable=websiteEntry).grid(row=0, column=1)
    tkinter.Entry(view3, textvariable=nameEntry).grid(row=1, column=1)
    tkinter.Entry(view3, textvariable=passwordEntry).grid(row=2, column=1)
    Button(view3, text='confirm', bd='5', command=lambda: password_confirmation(websiteEntry, nameEntry, passwordEntry)).grid(row=3, column=1)
    view3.mainloop()
"""


