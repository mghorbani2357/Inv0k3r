import argparse
import getpass
import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
import traceback
import ctypes

from importlib.metadata import version, PackageNotFoundError
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Constants
SALT_SIZE = 16
NONCE_SIZE = 12  # GCM standard
KEY_SIZE = 32  # 256-bit AES
PBKDF2_ITERATIONS = 200_000

KEY_FORGE_HOME_DIR = f'{os.path.expanduser("~")}/.key_forge'
KEY_FORGE_KEY_RING_DIR = f'{KEY_FORGE_HOME_DIR}/keyring'

if os.name == 'nt':
    kernel32 = ctypes.windll.kernel32
    kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

def clear_cli():
    if os.name == 'nt':
        sys.stdout.write('\x1b[?1049h')
        sys.stdout.flush()
    else:
        subprocess.run('tput smcup', shell=True)

def wipe_out():
    if os.name == 'nt':
        sys.stdout.write('\x1b[?1049l')
        sys.stdout.flush()
    else:
        subprocess.run('tput rmcup', shell=True)

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
parser.add_argument('-v', '--version', action='version', help='print tools version')

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
invoke_subparsers.add_argument('id', metavar='', type=str, help='key hash or key name')
invoke_subparsers.add_argument('-f', '--path', metavar='', type=str, help='key path')

export_subparsers = subparsers.add_parser('export', help='export key from keyring')
export_subparsers.set_defaults(which='export')
export_subparsers.add_argument('id', metavar='', type=str, help='key hash or key name')
export_subparsers.add_argument('path', metavar='', type=str, help='path to where key should be exported')

import_subparsers = subparsers.add_parser('import', help='export key from keyring')
import_subparsers.set_defaults(which='import')
import_subparsers.add_argument('path', metavar='', type=str, help='path to key')


def get_version():
    try:
        return version("my_package")
    except PackageNotFoundError:
        return "unknown"


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
                            password = getpass.getpass('Enter passphrase to encrypt the module(leave it blank if you don\'t want to encrypt it):\n', stream=None)

                            with open(f'{KEY_FORGE_KEY_RING_DIR}/{plugin_name}.enc', 'wb') as f:
                                f.write(encrypt_file(args.path, password) if password != '' else open(args.path).read())
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
                clear_cli()
                try:
                    if (hasattr(args, 'id') and (key_path := find_key(args.id))) or hasattr(args, 'path'):
                        password = getpass.getpass('Enter passphrase to decrypt the module(leave it blank if it isn\'t encrypted):\n', stream=None)
                        namespace = {}
                        key_file_path = str(key_path) if (hasattr(args, 'id') and (key_path := find_key(args.id))) else hasattr(args, 'path')
                        exec(decrypt_file(key_file_path, password) if password != '' else open(key_file_path).read(), namespace)
                        namespace['invoke']()

                    else:
                        print("Unable to find the key", file=sys.stderr)

                except KeyboardInterrupt:
                    wipe_out()
                    return
                except:
                    print(traceback.print_exc())
                finally:
                    try:
                        getpass.getpass('Press `Enter` to wipe out', stream=None)
                    except KeyboardInterrupt:
                        wipe_out()
                    except:
                        pass
                    wipe_out()
            case 'export':
                if (key_path := find_key(args.id)) is not None:
                    shutil.copy(key_path, args.path)
                else:
                    print("Unable to find the key", file=sys.stderr)
            case _:
                parser.print_help()
    else:

        if args.version:
            print(f'keyforge version {get_version()}')
        else:
            parser.print_help()


if __name__ == '__main__':
    main()

# Todo:
#   - setup automatic publish pipeline and acquire badges
#   - implement unittests
#   - check for security enchantments
