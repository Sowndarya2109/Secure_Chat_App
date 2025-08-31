from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def derive_key(code_word, salt):
    key = PBKDF2(code_word, salt, dkLen=32, count=1000000)
    return key

def encrypt(plain_text, code_word):
    salt = get_random_bytes(16)
    key = derive_key(code_word.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    encrypted = base64.b64encode(salt + cipher.iv + ct_bytes).decode('utf-8')
    return encrypted

def decrypt(encrypted, code_word):
    try:
        data = base64.b64decode(encrypted)
        salt = data[:16]
        iv  = data[16:32]
        ct = data[32:]
        key = derive_key(code_word.encode(), salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except (ValueError, KeyError):
        return "Incorrect code word or corrupted message"
    
if __name__ == "__main__":
    message = input("Enter message to encrypt: ")
    code_word = input("Enter code word: ")
    encrypted_msg = encrypt(message, code_word)
    print(f"\nEncrypted message:\n{encrypted_msg}")

    print("\n-----Receiver side-----")
    rec_code = input("Enter code word to decrypt: ") 
    decrypted_msg = decrypt(encrypted_msg, rec_code)
    print(f"\nDecrypted message:\n{decrypted_msg}")
        