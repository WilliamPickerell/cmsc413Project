import sys
import tkinter

from cryptography.fernet import Fernet
import os
import hashlib
import binascii
import tkinter as tk

# Master key for encryption
master_key = b'Cp1hH7cSCOO1hpp5yQx3kPDh7rQ_4VdFjoTp1GuyH_c='


class passwordApp(tk.Tk):

    # main menu
    def __init__(self):
        tk.Tk.__init__(self)
        self.user = ""
        # Window Title
        self.title("Password Manager")
        # Frame size
        self.frame = tkinter.Frame(self, highlightbackground="blue", highlightthickness=10, width=600, height=290, bd=0)
        self.frame.place(relx=0)
        # Greeting
        self.greeting = tk.Label(self,
                                 text="\n\nWelcome to our Password Storage service.                \nPlease enter you name and password\n\n",
                                 font=("ariel", 16, "bold")).grid(row=0, column=1)
        # username entry
        self.name_label = tk.Label(self, text="Name:").grid(row=1, column=0)
        self.websiteEntry = tk.Entry(self)
        self.nameEntry = tk.Entry(self)
        self.nameEntry.grid(row=1, column=1)
        # password entry
        self.password_label = tk.Label(self, text="Password:").grid(row=2, column=0)
        self.passwordEntry = tk.Entry(self, show="*")
        self.passwordEntry.grid(row=2, column=1)
        # button to enter
        self.confirm = tk.Button(self, text='Login', bd='5', command=self.submit).grid(row=3, column=1)
        #
        self.addUser = tk.Button(self, text='Create Account', bd='5', command=self.create_user_screen).grid(row=4,
                                                                                                            column=1)
        # button to quit app
        button_quit = tk.Button(self, text='Exit Application', bd='5', command=self.quit).grid(row=5,
                                                                                               column=1)

    # screen to make a user
    def create_user_screen(self):
        for child in self.winfo_children():
            child.destroy()
        # title
        self.title("New User")
        tk.Label(self, text="Please enter your name and password").grid(row=0, column=1)

        tk.Label(self, text="Name:").grid(row=1, column=0)
        tk.Label(self, text="Password:").grid(row=2, column=0)
        # username for new user
        self.nameEntry = tk.Entry(self)
        self.nameEntry.grid(row=1, column=1)
        # password for new user
        self.passwordEntry = tk.Entry(self, show="*")
        self.passwordEntry.grid(row=2, column=1)
        # button to make new user.
        self.confirm = tk.Button(self, text='Login', bd='5', command=self.create_user).grid(row=3, column=1)
        self.mainloop()

    def submit(self):
        name = self.nameEntry.get()
        password = self.passwordEntry.get()
        # create user if input works out
        if self.login_user(name, password):
            self.write_main_window()
        # create error message for incorrect input
        else:
            view2 = tk.Tk()
            view2.title("Password Manager")
            tk.Label(view2, text="wrong name or password").grid(row=0, column=0)
            view2.mainloop()

    #password management window
    def write_main_window(self):
        # stop repeat windows
        for child in self.winfo_children():
            child.destroy()
        # Title and formatting
        self.title("Password Manager")
        self.website = tk.Label(self, text="Password list:", font="bold").grid(row=0, column=0)
        self.name = tk.Label(self, text="", font="bold").grid(row=0, column=1)
        # get list of all websites with passwords
        listOfSites = self.get_websites_names()
        i = 1
        for site in listOfSites:
            tk.Label(self, text=site[0]).grid(row=i, column=0)
            tk.Label(self, text=site[1]).grid(row=i, column=1)
            t = i - 1
            # button to view password
            tk.Button(self, text='View Password', bd='5', command=lambda t=t: self.show_password(t)).grid(row=i,
                                                                                                          column=2)
            # button to edit password
            tk.Button(self, text='Edit Password', bd='5',
                      command=lambda t=t, site=site: self.edit_password(site[0], site[1], t)). \
                grid(row=i, column=3)
            # button to delete password
            tk.Button(self, text='Delete Password', bd='5', command=lambda t=t: self.delete_password(t)).grid(row=i,
                                                                                                              column=4)
            i += 1
        # button to add password
        tk.Button(self, text='Add Password', bd='5', command=self.add_password).grid(row=i, column=2)
        button_quit = tk.Button(self, text='Exit Application', bd='5', command=self.destroy).grid(row=i + 1,
                                                                                                  column=1)
        # button to restart
        button_restart = tk.Button(self, text='Logout', bd='5', command=lambda: self.restart()).grid(row=i + 2,
                                                                                                     column=1)
        self.mainloop()

    # restart function
    def restart(self):
        self.destroy()
        self.__init__()

    # creates a random password
    def random_password(self):
        self.write_main_window()

    # check for user login
    def login_user(self, name, password):
        self.user = name
        f1 = open("user.txt", "r")
        lines = f1.readlines()
        # read each line
        for line in lines:
            info = line.split(",")
            # process account info
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

    # get website names and passwords
    def get_websites_names(self):
        f1 = open(self.user + "passwords.txt", "r")
        listOfSites = []
        encryptedPassword = []
        encryptedKey = []
        f1 = open(self.user + "passwords.txt", "r")
        f2 = open(self.user + "keys.txt", "r")
        lines = f1.readlines()
        i = 0
        # process passwords
        for line in lines:
            end = len(line) - 2
            encryptedPassword.append(line[2:end])
        lines = f2.readlines()
        # process keys
        for line in lines:
            end = line.__len__() - 2
            encryptedKey.append(line[2:end])
        i = 0
        # decrypt information
        for encrypted in encryptedPassword:
            keyDecryptor = Fernet(master_key)
            key = keyDecryptor.decrypt(encryptedKey[i].encode())
            passwordDecryptor = Fernet(key)
            webNamepassword = passwordDecryptor.decrypt(encrypted.encode()).decode()
            info = webNamepassword.split(",")
            listOfSites.append(info)
            i += 1
        return listOfSites

    # decrypts passwords and shows password
    def show_password(self, number):
        password = self.decrypt_password(number)
        view3 = tk.Tk()
        view3.title("Password")
        tk.Label(view3, text=password).grid(row=0, column=0)
        view3.mainloop()

    # process password decryption
    def decrypt_password(self, number):
        encryptedPassword = ""
        encryptedKey = ""
        f1 = open(self.user + "passwords.txt", "r")
        f2 = open(self.user + "keys.txt", "r")
        lines = f1.readlines()
        i = 0
        # decrypt passwords
        for line in lines:
            if i == number:
                end = len(line) - 2
                encryptedPassword = line[2:end]
            i += 1
        lines = f2.readlines()
        i = 0
        # decrypt keys
        for line in lines:
            if i == number:
                end = line.__len__() - 2
                encryptedKey = line[2:end]
            i += 1
        keyDecryptor = Fernet(master_key)
        key = keyDecryptor.decrypt(encryptedKey.encode())
        passwordDecryptor = Fernet(key)
        webNamepassword = passwordDecryptor.decrypt(encryptedPassword.encode()).decode()
        info = webNamepassword.split(",")
        password = info[2]
        return password

    # add password menu
    def add_password(self):
        #
        for child in self.winfo_children():
            child.destroy()
        self.title("Add Password")
        tk.Label(self, text="Website:").grid(row=0, column=0)
        tk.Label(self, text="UserName:").grid(row=1, column=0)
        tk.Label(self, text="Password:").grid(row=2, column=0)
        # field for website entry
        self.websiteEntry = tk.Entry(self)
        self.websiteEntry.grid(row=0, column=1)
        # field for username entry
        self.nameEntry = tk.Entry(self)
        self.nameEntry.grid(row=1, column=1)
        # field for password entry
        self.passwordEntry = tk.Entry(self, show="*")
        self.passwordEntry.grid(row=2, column=1)
        # button to return to the password list menu
        tk.Button(self, text='confirm', bd='5',
                  command=self.password_confirmation).grid(row=3, column=1)
        button_quit = tk.Button(self, text='Return to password list', bd='5', command=self.write_main_window).grid(
            row=5,
            column=1)
        # button to return to exit application
        button_quit = tk.Button(self, text='Exit Application', bd='5', command=self.quit).grid(row=6,
                                                                                               column=1)
        self.mainloop()

    # banner to let the user know the they added a password
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

    # encrypt password and add password to passwords.txt and key to keys.txt
    def encrypt_password(self, website, name, password):
        key = Fernet.generate_key()
        webNamePass = website + "," + name + "," + password
        passwordEncryptor = Fernet(key)
        encryptedPassword = passwordEncryptor.encrypt(webNamePass.encode())
        keyEncryptor = Fernet(master_key)
        encryptedKey = keyEncryptor.encrypt(key)
        f1 = open(self.user + "passwords.txt", "a")
        f1.write(f"{encryptedPassword}\n")
        f1.close()
        f2 = open(self.user + "keys.txt", "a")
        f2.write(f"{encryptedKey}\n")
        f2.close()
        return True

    # function to create user
    def create_user(self):
        name = self.nameEntry.get()
        self.user = name
        f1 = open("user.txt", "r")
        userDoesNotExist = True
        lines = f1.readlines()

        # check if user exists
        for line in lines:
            info = line.split(",")
            if info[0] == name:
                userDoesNotExist = False

        # create user if user does not exist
        if userDoesNotExist:
            password = self.passwordEntry.get()
            # create salt
            salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
            # create hashed password including salt
            hashedPassword = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt,
                100000,
            )
            hashedPassword = binascii.hexlify(hashedPassword)
            storage = salt + hashedPassword
            # add username to list of users
            f1 = open("user.txt", "a")
            f1.write(name + f",{storage}\n")
            f1.close()
            # create list of passwords
            f1 = open(self.user + "passwords.txt", "w")
            f1.write("")
            f1.close()
            # create list of keys for passwords
            f1 = open(self.user + "keys.txt", "w")
            f1.write("")
            f1.close()
            view4 = tk.Tk()
            view4.title("Success")
            # banner for creating new user
            tk.Label(view4, text="You have successfully created a new user", font="bold").grid(row=0, column=0)
            self.write_main_window()
            view4.mainloop()
        else:
            view4 = tk.Tk()
            view4.title("Failure")
            # error banner stating that user already exists.
            tk.Label(view4, text="That user already exists", font="bold").grid(row=0, column=0)
            view4.mainloop()

    # edit password menu
    def edit_password(self, website, name, number):
        password = self.decrypt_password(number)
        # ensure no duplicates
        for child in self.winfo_children():
            child.destroy()
        self.title("Add Password")
        tk.Label(self, text="Website:").grid(row=0, column=0)
        tk.Label(self, text="UserName:").grid(row=1, column=0)
        tk.Label(self, text="Password:").grid(row=2, column=0)
        # website field with previous website
        self.websiteEntry = tk.Entry(self)
        self.websiteEntry.insert(0, website)
        self.websiteEntry.grid(row=0, column=1)
        # username field with previous username
        self.nameEntry = tk.Entry(self)
        self.nameEntry.insert(0, name)
        self.nameEntry.grid(row=1, column=1)
        # password field with previous password
        self.passwordEntry = tk.Entry(self, show="*")
        self.passwordEntry.insert(0, password)
        self.passwordEntry.grid(row=2, column=1)
        tk.Button(self, text='confirm', bd='5', command=lambda: self.edit_password_manager(number)).grid(row=3,
                                                                                                         column=1)
    # commit changes from the edit password menu
    def edit_password_manager(self, number):
        website = self.websiteEntry.get()
        name = self.nameEntry.get()
        password = self.passwordEntry.get()
        self.encrypt_password(website, name, password)
        self.delete_password(number)

    # deletes password from list of passwords
    def delete_password(self, number):
        f1 = open(self.user + "passwords.txt", "r")
        f2 = open(self.user + "keys.txt", "r")
        lines = f1.readlines()
        i = 0
        newLines1 = []
        # deletes password, website, and username from passwords file
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
        # deletes key from keys file
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
