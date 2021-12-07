import sys
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
        self.user = ""
        self.title("Password Manager")
        self.frame = tkinter.Frame(self, highlightbackground="blue", highlightthickness=10, width=600, height=290, bd=0)
        self.frame.place(relx=0)
        self.greeting = tk.Label(self,
                                 text="\n\nWelcome to our Password Storage service.                \nPlease enter you name and password\n\n",
                                 font=("ariel", 16, "bold")).grid(row=0, column=1)
        self.name_label = tk.Label(self, text="Name:").grid(row=1, column=0)
        self.websiteEntry = tk.Entry(self)
        self.nameEntry = tk.Entry(self)
        self.nameEntry.grid(row=1, column=1)
        self.password_label = tk.Label(self, text="Password:").grid(row=2, column=0)
        self.passwordEntry = tk.Entry(self, show="*")
        self.passwordEntry.grid(row=2, column=1)
        self.confirm = tk.Button(self, text='Login', bd='5', command=self.submit).grid(row=3, column=1)

        self.addUser = tk.Button(self, text='Create Account', bd='5', command=self.create_user_screen).grid(row=4,
                                                                                                            column=1)

        button_quit = tk.Button(self, text='Exit Application', bd='5', command=self.quit).grid(row=5,
                                                                                               column=1)

    def create_user_screen(self):
        for child in self.winfo_children():
            child.destroy()
        self.title("New User")
        tk.Label(self, text="Please enter your name and password").grid(row=0, column=1)
        tk.Label(self, text="Name:").grid(row=1, column=0)
        tk.Label(self, text="Password:").grid(row=2, column=0)
        self.nameEntry = tk.Entry(self)
        self.nameEntry.grid(row=1, column=1)
        self.passwordEntry = tk.Entry(self, show="*")
        self.passwordEntry.grid(row=2, column=1)
        self.confirm = tk.Button(self, text='Login', bd='5', command=self.create_user).grid(row=3, column=1)

        button_quit = tk.Button(self, text='Exit Application', bd='5', command=self.quit).grid(row=5,
                                                                                               column=1)
        self.mainloop()

    def submit(self):
        name = self.nameEntry.get()
        password = self.passwordEntry.get()
        if self.login_user(name, password):
            self.write_main_window()
        else:
            view2 = tk.Tk()
            view2.title("Password Manager")
            tk.Label(view2, text="wrong name or password").grid(row=0, column=0)
            view2.mainloop()

    def write_main_window(self):
        for child in self.winfo_children():
            child.destroy()
        self.title("Password Manager")
        self.website = tk.Label(self, text="Password list:", font="bold").grid(row=0, column=0)
        self.name = tk.Label(self, text="", font="bold").grid(row=0, column=1)
        listOfSites = self.get_websites_names()
        i = 1
        for site in listOfSites:
            tk.Label(self, text=site[0]).grid(row=i, column=0)
            tk.Label(self, text=site[1]).grid(row=i, column=1)
            t = i - 1
            tk.Button(self, text='View Password', bd='5', command=lambda t=t: self.show_password(t)).grid(row=i,
                                                                                                          column=2)
            tk.Button(self, text='Edit Password', bd='5',
                      command=lambda t=t, site=site: self.edit_password(site[0], site[1], t)). \
                grid(row=i, column=3)
            tk.Button(self, text='Delete Password', bd='5', command=lambda t=t: self.delete_password(t)).grid(row=i,
                                                                                                              column=4)
            i += 1
        tk.Button(self, text='Add Password', bd='5', command=self.add_password).grid(row=i, column=2)
        button_quit = tk.Button(self, text='Exit Application', bd='5', command=self.quit).grid(row=i + 1,
                                                                                               column=1)

        button_restart = tk.Button(self, text='Logout', bd='5', command=lambda: self.restart()).grid(row=i + 2,
                                                                                                     column=1)
        self.mainloop()

    def restart(self):
        self.destroy()
        os.startfile("main.py")

    def random_password(self):
        self.write_main_window()

    def login_user(self, name, password):
        self.user = name
        f1 = open("user.txt", "r")
        lines = f1.readlines()
        for line in lines:
            info = line.split(",")
            if info[0] == name:
                end = len(info[1]) - 2
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

        return False

    def get_websites_names(self):
        f1 = open(self.user + "passwords.txt", "r")
        listOfSites = []
        lines = f1.readlines()
        for line in lines:
            info = line.split(",")
            webName = [info[0], info[1]]
            listOfSites.append(webName)
        return listOfSites

    def show_password(self, number):
        password = self.decrypt_password(number)
        view3 = tk.Tk()
        view3.title("Password")
        tk.Label(view3, text=password).grid(row=0, column=0)
        view3.mainloop()

    def decrypt_password(self, number):
        encryptedPassword = ""
        encryptedKey = ""
        f1 = open(self.user + "passwords.txt", "r")
        f2 = open(self.user + "keys.txt", "r")
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

    def add_password(self):
        for child in self.winfo_children():
            child.destroy()
        self.title("Add Password")
        tk.Label(self, text="Website:").grid(row=0, column=0)
        tk.Label(self, text="UserName:").grid(row=1, column=0)
        tk.Label(self, text="Password:").grid(row=2, column=0)
        self.websiteEntry = tk.Entry(self)
        self.websiteEntry.grid(row=0, column=1)
        self.nameEntry = tk.Entry(self)
        self.nameEntry.grid(row=1, column=1)
        self.passwordEntry = tk.Entry(self, show="*")
        self.passwordEntry.grid(row=2, column=1)
        tk.Button(self, text='confirm', bd='5',
                  command=self.password_confirmation).grid(row=3, column=1)
        button_quit = tk.Button(self, text='Return to password list', bd='5', command=self.write_main_window).grid(
            row=5,
            column=1)
        button_quit = tk.Button(self, text='Exit Application', bd='5', command=self.quit).grid(row=6,
                                                                                               column=1)
        self.mainloop()

    def password_confirmation(self):
        website = self.websiteEntry.get()
        name = self.nameEntry.get()
        password = self.passwordEntry.get()
        if self.encrypt_password(website, name, password):
            view4 = tk.Tk()
            view4.title("Success")
            tk.Label(view4, text="You have successfully added a new password", font="bold").grid(row=0, column=0)
            self.write_main_window()
            view4.mainloop()

    def encrypt_password(self, website, name, password):
        key = Fernet.generate_key()
        passwordEncryptor = Fernet(key)
        encryptedPassword = passwordEncryptor.encrypt(password.encode())
        keyEncryptor = Fernet(master_key)
        encryptedKey = keyEncryptor.encrypt(key)
        f1 = open(self.user + "passwords.txt", "a")
        f1.write(website + "," + name + f",{encryptedPassword}\n")
        f1.close()
        f2 = open(self.user + "keys.txt", "a")
        f2.write(f"{encryptedKey}\n")
        f2.close()
        return True

    def create_user(self):
        name = self.nameEntry.get()
        self.user = name
        password = self.passwordEntry.get()
        salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
        hashedPassword = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000,
        )
        hashedPassword = binascii.hexlify(hashedPassword)
        storage = salt + hashedPassword
        f1 = open("user.txt", "a")
        f1.write(name + f",{storage}\n")
        f1.close()
        f1 = open(self.user + "passwords.txt", "w")
        f1.write("")
        f1.close()
        f1 = open(self.user + "keys.txt", "w")
        f1.write("")
        f1.close()
        view4 = tk.Tk()
        view4.title("Success")
        tk.Label(view4, text="You have successfully created a new user", font="bold").grid(row=0, column=0)
        self.write_main_window()
        view4.mainloop()

    def edit_password(self, website, name, number):
        password = self.decrypt_password(number)
        for child in self.winfo_children():
            child.destroy()
        self.title("Add Password")
        tk.Label(self, text="Website:").grid(row=0, column=0)
        tk.Label(self, text="UserName:").grid(row=1, column=0)
        tk.Label(self, text="Password:").grid(row=2, column=0)
        self.websiteEntry = tk.Entry(self)
        self.websiteEntry.insert(0, website)
        self.websiteEntry.grid(row=0, column=1)
        self.nameEntry = tk.Entry(self)
        self.nameEntry.insert(0, name)
        self.nameEntry.grid(row=1, column=1)
        self.passwordEntry = tk.Entry(self, show="*")
        self.passwordEntry.insert(0, password)
        self.passwordEntry.grid(row=2, column=1)
        tk.Button(self, text='confirm', bd='5', command=lambda: self.edit_password_manager(number)).grid(row=3,
                                                                                                         column=1)

    def edit_password_manager(self, number):
        website = self.websiteEntry.get()
        name = self.nameEntry.get()
        password = self.passwordEntry.get()
        self.encrypt_password(website, name, password)
        self.delete_password(number)

    def delete_password(self, number):
        f1 = open(self.user + "passwords.txt", "r")
        f2 = open(self.user + "keys.txt", "r")
        lines = f1.readlines()
        i = 0
        newLines1 = []
        for line in lines:
            if i != number:
                newLines1.append(line)
            i += 1
        f1.close()
        f1 = open(self.user + "passwords.txt", "w")
        f1.writelines(newLines1)
        f1.close()
        lines = f2.readlines()
        i = 0
        newLines2 = []
        for line in lines:
            if i != number:
                newLines2.append(line)
            i += 1
        f2.close()
        f2 = open(self.user + "keys.txt", "w")
        f2.writelines(newLines2)
        f2.close()
        self.write_main_window()


app = passwordApp()
app.mainloop()
