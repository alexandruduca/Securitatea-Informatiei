import secrets
import string

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY_LENGTH = 128


def generate_key(bytes):
    return ''.join(
        secrets.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(bytes // 8))


def encrypt_ECB(msg, key):
    return AES.new(key.encode(), AES.MODE_ECB).encrypt(pad(msg.encode(), KEY_LENGTH // 8))


def decrypt_ECB(enc, key):
    return unpad(AES.new(key.encode(), AES.MODE_ECB).decrypt(enc), KEY_LENGTH // 8).decode()


def encrypt_ECB_file(key):
    cipher_blocks = []
    with open('file.txt') as f:
        while f:
            plain_text = f.read(16)
            encryption = encrypt_ECB(plain_text, key)
            cipher_blocks.append(encryption)
            if plain_text == '':
                break
    cipher_blocks.pop()
    return cipher_blocks


def decrypt_ECB_file(key, cipher_blocks):
    plain_text_blocks = []
    for i in cipher_blocks:
        plain_text = decrypt_ECB(i, key)
        plain_text_blocks.append(plain_text)
    return plain_text_blocks


def encrypt_CTR_file(key):
    cipher_blocks = []
    counter = []
    nonce = generate_key(KEY_LENGTH // 2)
    i = 0
    with open('file.txt') as f:
        while f:
            plain_text = f.read(16)
            counter.append(nonce + f'{i:08}')
            encryption = encrypt_ECB(counter[i], key)
            cipher_text = bytes(A ^ B for A, B in zip(plain_text.encode(), encryption))
            cipher_blocks.append(cipher_text)
            i += 1
            if plain_text == '':
                break
    cipher_blocks.pop(), counter.pop()
    return cipher_blocks, counter


def decrypt_CTR_file(key, cipher_blocks, counter):
    plain_text_blocks = []
    for i in counter:
        encryption = encrypt_ECB(i, key)
        plain_text = bytes(A ^ B for A, B in zip(encryption, cipher_blocks[counter.index(i)]))
        plain_text_blocks.append(plain_text)
    return plain_text_blocks


MC = []
k1 = generate_key(KEY_LENGTH)  # ECB
k2 = generate_key(KEY_LENGTH)  # CTR
K = generate_key(KEY_LENGTH)  # K
MC.append(k1)
MC.append(k2)
MC.append(K)


def ECB_communication(MC):
    key = MC[0]
    K = MC[2]
    print("Cheia K: ", K)
    print("Cheia k1, inainte de criptare: ", key)

    enc = encrypt_ECB(key, K)
    print("Cheia k1, criptata: ", enc)

    k1 = decrypt_ECB(enc, K)
    print("Cheia k1, dupa decriptare: ", k1)

    print("\nNodul B: Putem incepe comunicarea\n")

    cipher_blocks = encrypt_ECB_file(k1)
    print("Blocurile de cipher text: ")
    print(cipher_blocks)
    print("Textul decriptat: ")
    plain_text_blocks = decrypt_ECB_file(k1, cipher_blocks)
    print(''.join(plain_text_blocks))


def CTR_communication(MC):
    key = MC[1]
    K = MC[2]
    print("Cheia K: ", K)
    print("Cheia k2, inainte de criptare: ", key)

    enc = encrypt_ECB(key, K)
    print("Cheia k2, criptata: ", enc)

    k2 = decrypt_ECB(enc, K)
    print("Cheia k2, dupa decriptare: ", k2)

    print("\nNodul B: Putem incepe comunicarea\n")

    cipher_blocks, counter = encrypt_CTR_file(k2)
    print("Blocurile de cipher text: ")
    print(cipher_blocks)
    print("Blocurile de nonce+counter: ")
    print(counter)
    print("Textul decriptat: ")
    plain_text_blocks = decrypt_CTR_file(k2, cipher_blocks, counter)
    print(''.join([a.decode() for a in plain_text_blocks]))


while 1:
    mode = input("Nodul A: modul de operare va fi: ")
    if mode.upper() == 'ECB':
        ECB_communication(MC)
        break
    elif mode.upper() == 'CTR':
        CTR_communication(MC)
        break
    print("Modul de operare ales nu este valid, alegeti fie ECB, fie CTR")
