from cryptography.fernet import Fernet
import os
import hashlib
import binascii
master_key = b'Cp1hH7cSCOO1hpp5yQx3kPDh7rQ_4VdFjoTp1GuyH_c='


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


def login_user(name, password):
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


def encrypt_password(name, password):
    key = Fernet.generate_key()
    passwordEncryptor = Fernet(key)
    encryptedPassword = passwordEncryptor.encrypt(password.encode())
    keyEncryptor = Fernet(master_key)
    encryptedKey = keyEncryptor.encrypt(key)
    f1 = open("passwords.txt", "a")
    f1.write(name+f",{encryptedPassword}\n")
    f1.close()
    f2 = open("keys.txt", "a")
    f2.write(f"{encryptedKey}\n")
    f2.close()


def decrypt_password(number):
    name = ""
    encryptedPassword = ""
    encryptedKey = ""
    f1 = open("passwords.txt", "r")
    f2 = open("keys.txt", "r")
    lines = f1.readlines()
    i = 0
    for line in lines:
        if i == number:
            parts = line.split(",")
            name = parts[0]
            end = len(parts[1]) - 2
            encryptedPassword = parts[1][2:end]
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


if __name__ == '__main__':
    #encrypt_password("test", "test1")
    #pword = decrypt_password(1)
    #create_user("William", "password123")
    print(login_user("William", "password123"))
    #print(pword)

