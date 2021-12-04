from cryptography.fernet import Fernet
master_key = b'Cp1hH7cSCOO1hpp5yQx3kPDh7rQ_4VdFjoTp1GuyH_c='


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
    encrypt_password("test", "test1")
    pword = decrypt_password(1)
    print(pword)

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
