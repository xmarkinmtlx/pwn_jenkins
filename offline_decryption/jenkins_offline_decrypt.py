### Updated 2025 to remove crypto and pycrypto
import sys
import re
import base64
import os
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Configure this to your liking
secret_title_list = ['apiToken', 'password', 'privateKey', 'passphrase', 'secret', 'secretId', 'value', 'defaultValue', 'apiToken']

decryption_magic = b'::::MAGIC::::'


def usage():
    print(f'Usage:\n\t{os.path.basename(sys.argv[0])} <jenkins_base_path>')
    print(f'or:\n\t{os.path.basename(sys.argv[0])} <master.key> <hudson.util.Secret> [credentials.xml]')
    print(f'or:\n\t{os.path.basename(sys.argv[0])} -i <path> (interactive mode)')
    sys.exit(1)


def get_confidentiality_key(master_key_path, hudson_secret_path):
    with open(master_key_path, 'r') as f:
        master_key = f.read().encode('utf-8')

    with open(hudson_secret_path, 'rb') as f:
        hudson_secret = f.read()

    # Remove trailing newlines if present
    master_key = master_key.rstrip(b'\n')
    hudson_secret = hudson_secret.rstrip(b'\n')

    return decrypt_confidentiality_key(master_key, hudson_secret)


def decrypt_confidentiality_key(master_key, hudson_secret):
    derived_master_key = sha256(master_key).digest()[:16]

    cipher = Cipher(algorithms.AES(derived_master_key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_hudson_secret = decryptor.update(hudson_secret) + decryptor.finalize()

    if decryption_magic not in decrypted_hudson_secret:
        return None

    return decrypted_hudson_secret[:16]


def decrypt_secret_old_format(encrypted_secret, confidentiality_key):
    cipher = Cipher(algorithms.AES(confidentiality_key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_secret = decryptor.update(encrypted_secret) + decryptor.finalize()

    if decryption_magic not in decrypted_secret:
        return None

    return decrypted_secret.split(decryption_magic)[0]


def decrypt_secret_new_format(encrypted_secret, confidentiality_key):
    iv = encrypted_secret[9:9+16]
    cipher = Cipher(algorithms.AES(confidentiality_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_secret = decryptor.update(encrypted_secret[9+16:]) + decryptor.finalize()

    padding_value = decrypted_secret[-1]
    if padding_value > 16:
        return decrypted_secret
    
    return decrypted_secret[:-padding_value]


def decrypt_secret(encoded_secret, confidentiality_key):
    if encoded_secret is None:
        return None
    
    try:
        encrypted_secret = base64.b64decode(encoded_secret)
    except base64.binascii.Error as error:
        print(f'Failed base64 decoding: {error}')
        return None

    if encrypted_secret[0] == 1:
        return decrypt_secret_new_format(encrypted_secret, confidentiality_key)
    else:
        return decrypt_secret_old_format(encrypted_secret, confidentiality_key)


def decrypt_credentials_file(credentials_file, confidentiality_key):
    with open(credentials_file, 'r') as f:
        data = f.read()

    secrets = []
    for secret_title in secret_title_list:
        secrets += re.findall(secret_title + r'>\{?(.*?)\}?<\/' + secret_title, data)
    secrets += re.findall(r'>{([a-zA-Z0-9=+/]*)}</', data)
    secrets = list(set(secrets))

    for secret in secrets:
        try:
            decrypted_secret = decrypt_secret(secret, confidentiality_key)
            if decrypted_secret:
                print(decrypted_secret.decode('utf-8'))
        except Exception as e:
            print(e)


def run_interactive_mode(confidentiality_key):
    while True:
        secret = input('Encrypted secret: ')
        if not secret:
            continue
        try:
            decrypted_secret = decrypt_secret(secret, confidentiality_key)
            print(decrypted_secret.decode('utf-8'))
        except Exception as e:
            print(e)


if __name__ == '__main__':
    if len(sys.argv) > 4 or len(sys.argv) < 2:
        usage()
    
    credentials_file = ''
    
    if sys.argv[1] == '-i':
        base_path = sys.argv[2]
        if not os.path.isdir(base_path):
            usage()
        master_key_file = os.path.join(base_path, 'secrets', 'master.key')
        hudson_secret_file = os.path.join(base_path, 'secrets', 'hudson.util.Secret')
    elif len(sys.argv) == 2:
        base_path = sys.argv[1]
        credentials_file = os.path.join(base_path, 'credentials.xml')
        master_key_file = os.path.join(base_path, 'secrets', 'master.key')
        hudson_secret_file = os.path.join(base_path, 'secrets', 'hudson.util.Secret')
    else:
        master_key_file = sys.argv[1]
        hudson_secret_file = sys.argv[2]
        if len(sys.argv) == 4:
            credentials_file = sys.argv[3]

    if not os.path.exists(master_key_file) or not os.path.exists(hudson_secret_file):
        print('Required files not found')
        exit(1)
    
    confidentiality_key = get_confidentiality_key(master_key_file, hudson_secret_file)
    if not confidentiality_key:
        print('Failed decrypting confidentiality key')
        exit(1)

    if credentials_file:
        decrypt_credentials_file(credentials_file, confidentiality_key)
    else:
        run_interactive_mode(confidentiality_key)
