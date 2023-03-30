from cryptography.fernet import Fernet
def encrypt(plain_password):
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    pwd=bytes(plain_password,'utf-8')
    encrypted_text = (cipher_suite.encrypt(pwd))
    print(str(key))
    print(str(encrypted_text))
    return(encrypted_text,key)

def decrypt(encrypt_password,key):
    cipher_suite = Fernet(key)
    ciphered_text = encrypt_password
    uncipher_text = (cipher_suite.decrypt(ciphered_text))
    plain_text_encryptedpassword = bytes(uncipher_text).decode("utf-8") #convert to string
    return(plain_text_encryptedpassword)