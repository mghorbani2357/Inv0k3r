import argparse
import getpass
import hashlib
import importlib.util
import os
import subprocess
import sys
import traceback
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Constants
SALT_SIZE = 16
NONCE_SIZE = 12  # GCM standard
KEY_SIZE = 32  # 256-bit AES
PBKDF2_ITERATIONS = 200_000

KEY_FORGE_HOME_DIR = f'{os.path.expanduser("~")}/.key_forge'
KEY_FORGE_KEY_RING_DIR = f'{KEY_FORGE_HOME_DIR}/keyring'


def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derive a secure 256-bit key from the password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password)


def encrypt_file(input_path: str, password: str):
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password.encode(), salt)
    nonce = os.urandom(NONCE_SIZE)

    aesgcm = AESGCM(key)

    with open(input_path, 'rb') as f:
        plaintext = f.read()

    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return salt + nonce + ciphertext


def decrypt_file(encrypted_path: str, password: str):
    with open(encrypted_path, 'rb') as f:
        data = f.read()

    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = data[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password.encode(), salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        print(f"Decryption failed: incorrect password or corrupted file.", file=sys.stderr)
        exit(1)

    return plaintext


def sha256sum(filename):
    with open(filename, 'rb', buffering=0) as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def find_key(key_id):
    path = Path(KEY_FORGE_KEY_RING_DIR)
    for index, key_path in enumerate(path.glob('*.enc')):
        name, ext = os.path.splitext(os.path.basename(key_path))
        key_hash = sha256sum(key_path)
        if name == key_id or key_hash.startswith(key_id):
            return key_path
    return None


parser = argparse.ArgumentParser(description='KeyForge CLI')
subparsers = parser.add_subparsers(help='sub-command help')

add_subparsers = subparsers.add_parser('add', help='add key to keyring')
add_subparsers.set_defaults(which='add')
add_subparsers.add_argument('path', metavar='', type=str, help='path to key smith file')

list_subparsers = subparsers.add_parser('list', help='list key smiths')
list_subparsers.set_defaults(which='list')

delete_subparsers = subparsers.add_parser('delete', help='add key from keyring')
delete_subparsers.set_defaults(which='delete')
delete_subparsers.add_argument('id', metavar='', type=str, help='key hash or key name')

invoke_subparsers = subparsers.add_parser('invoke', help='add key from keyring')
invoke_subparsers.set_defaults(which='invoke')
invoke_subparsers.add_argument('id', metavar='', type=str, help='key hash or key name or path')


def main():
    args = parser.parse_args()

    os.makedirs(KEY_FORGE_HOME_DIR, exist_ok=True)
    os.makedirs(KEY_FORGE_KEY_RING_DIR, exist_ok=True)

    if hasattr(args, 'which'):
        match args.which:
            case 'add':
                if not os.path.exists(args.path):
                    spec = importlib.util.spec_from_file_location('key', args.path)
                    module = importlib.util.module_from_spec(spec)
                    if spec.loader:
                        spec.loader.exec_module(module)
                        if hasattr(module, 'invoke'):
                            plugin_name = os.path.splitext(os.path.basename(args.path))[0]
                            password = getpass.getpass('Enter passphrase to encrypt the module:\n', stream=None)

                            with open(f'{KEY_FORGE_KEY_RING_DIR}/{plugin_name}.enc', 'wb') as f:
                                f.write(encrypt_file(args.path, password))
                        else:
                            print(f"Operation aborted: module does not have `invoke` method", file=sys.stderr)
                    else:
                        print(f"No loader found for {args.path}")
                else:
                    print(f"Operation aborted: file '{args.output}' does not exists", file=sys.stderr)

            case 'list':
                path = Path(KEY_FORGE_KEY_RING_DIR)

                print("Key Hash    Key Name")
                print("--------    --------")
                print()

                for index, key_path in enumerate(path.glob('*.enc')):
                    name, ext = os.path.splitext(os.path.basename(key_path))
                    key_hash = sha256sum(key_path)

                    print(f'{key_hash[:8]}    {name[:8]}')
            case 'delete':
                if (key_path := find_key(args.id)) is not None:
                    os.remove(key_path)
                    print(f"Key with id `{args.id}` deleted")
                else:
                    print(f"Unable to find `{args.id}`")

            case 'invoke':
                subprocess.run('tput smcup', shell=True)
                try:
                    if (key_path := find_key(args.id)) is not None:
                        password = getpass.getpass('Enter passphrase to decrypt the module:\n', stream=None)
                        namespace = {}
                        exec(decrypt_file(str(key_path), password), namespace)
                        namespace['invoke']()
                    else:
                        print(f"Unable to find `{args.id}`")
                except KeyboardInterrupt:
                    subprocess.run('tput rmcup', shell=True)
                    return
                except:
                    print(traceback.print_exc())
                finally:
                    try:
                        getpass.getpass('Press `Enter` to wipe out', stream=None)
                    except KeyboardInterrupt:
                        subprocess.run('tput rmcup', shell=True)
                    except:
                        pass
                    subprocess.run('tput rmcup', shell=True)

            case _:
                parser.print_help()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()

# Todo:
#   - import and export key 
#   - invoke external file
#   - implement setup.py 
#   - implement build.py to export singleton executable file for all platforms
#   - setup automatic publish pipeline and acquire badges
#   - implement unittests
#   - check for security enchantments
#   - make the tool available for all platforms
#   - get version
