import argparse
import ctypes
import getpass
import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
import traceback
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

INVOKER_HOME_DIR = f'{os.path.expanduser("~")}/.invoker'
INVOKER_SLOTS_DIR = f'{INVOKER_HOME_DIR}/slots'

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



def find_slot(slot_identifier):
    path = Path(INVOKER_SLOTS_DIR)
    results = list()
    for index, key_path in enumerate(path.glob('*')):
        name, ext = os.path.splitext(os.path.basename(key_path))
        key_hash = sha256sum(key_path)
        if name == slot_identifier or key_hash.startswith(slot_identifier):
            results.append(key_path)
    if len(results) == 1:
        return results[0]
    elif len(results) > 1:
        print(f"Error: Multiple identifiers found with provided prefix:{slot_identifier}")
    else:
        print(f"Error: No such slot:{slot_identifier}")
    return None

def create_parser():
    parser = argparse.ArgumentParser(description='Invoker CLI')
    parser.add_argument('-v', '--version', action='store_true', default=False, help='print tools version')

    subparsers = parser.add_subparsers(help='sub-command help')

    add_subparsers = subparsers.add_parser('add', help='add executable context into slots')
    add_subparsers.set_defaults(which='add')
    add_subparsers.add_argument('path', metavar='', type=str, help='path to python executable file')
    add_subparsers.add_argument('-e', '--encrypt', action='store_true', default=False, help='encrypt context')


    list_subparsers = subparsers.add_parser('list', help='list key smiths')
    list_subparsers.set_defaults(which='list')

    delete_subparsers = subparsers.add_parser('delete', help='add key from keyring')
    delete_subparsers.set_defaults(which='delete')
    delete_subparsers.add_argument('id', metavar='', type=str, help='key hash or key name')

    invoke_subparsers = subparsers.add_parser('invoke', help='invoke key from a file')
    invoke_subparsers.set_defaults(which='invoke')
    invoke_subparsers.add_argument('id', metavar='', type=str, help='key hash or key name')
    invoke_subparsers.add_argument('-f', '--path', metavar='', type=str, help='key path')

    save_subparsers = subparsers.add_parser('save', help='save key from keyring')
    save_subparsers.set_defaults(which='save')
    save_subparsers.add_argument('id', metavar='', type=str, help='key hash or key name')
    save_subparsers.add_argument('path', metavar='', type=str, help='path to where key should be saved')
    save_subparsers.add_argument('-d', '--decrypt', action='store_true', default=False, help='decrypt context')

    return parser


def get_version():
    try:
        return version("my_package")
    except PackageNotFoundError:
        return "unknown"


def main(args, parser):
    os.makedirs(INVOKER_HOME_DIR, exist_ok=True)
    os.makedirs(INVOKER_SLOTS_DIR, exist_ok=True)

    if hasattr(args, 'which'):
        match args.which:
            case 'add':
                if os.path.exists(args.path):
                    spec = importlib.util.spec_from_file_location('key', args.path)
                    module = importlib.util.module_from_spec(spec)
                    if spec.loader:
                        try:
                            spec.loader.exec_module(module)
                        except SyntaxError as e:
                            print(f"Operation aborted: invalid input", file=sys.stderr)
                            exit(1)
                        if hasattr(module, 'invoke'):
                            if args.encrypt:
                                name, extension = os.path.splitext(os.path.basename(args.path))

                                password = getpass.getpass('Enter passphrase to encrypt the module(leave it blank if you don\'t want to encrypt it):\n', stream=None)
                                password_confirm = getpass.getpass('Please enter passphrase to confirm:\n', stream=None)
                                if password != password_confirm:
                                    print(f"Operation aborted: passphrase confirmation failed", file=sys.stderr)
                                    exit(1)
                                buffer = encrypt_file(args.path, password)
                                out_put_slot_path = f'{INVOKER_SLOTS_DIR}/{name}.enc{extension}'
                            else:
                                out_put_slot_path = f'{INVOKER_SLOTS_DIR}/{os.path.basename(args.path)}'

                                with open(args.path, 'rb') as f_in:
                                    buffer = f_in.read()

                            with open(out_put_slot_path, 'wb') as f_out:
                                f_out.write(buffer)
                        else:
                            print(f"Operation aborted: module does not have `invoke` method", file=sys.stderr)
                    else:
                        print(f"Operation aborted: No loader found for {args.path}", file=sys.stderr)
                else:
                    print(f"Operation aborted: file '{args.path}' does not exists", file=sys.stderr)

            case 'list':
                path = Path(INVOKER_SLOTS_DIR)

                print("Key Hash    Key Name")
                print("--------    --------")
                print()

                for index, key_path in enumerate(path.glob('*.enc')):
                    name, ext = os.path.splitext(os.path.basename(key_path))
                    key_hash = sha256sum(key_path)

                    print(f'{key_hash[:8]}    {name[:8]}')
            case 'delete':
                if (key_path := find_slot(args.id)) is not None:
                    os.remove(key_path)
                    print(f"Key with id `{args.id}` deleted")

            case 'invoke':
                clear_cli()
                try:
                    if (hasattr(args, 'id') and (key_path := find_slot(args.id))) or hasattr(args, 'path'):
                        password = getpass.getpass('Enter passphrase to decrypt the module(leave it blank if it isn\'t encrypted):\n', stream=None)
                        namespace = {}
                        key_file_path = str(key_path) if (hasattr(args, 'id') and (key_path := find_slot(args.id))) else hasattr(args, 'path')
                        exec(decrypt_file(key_file_path, password) if password != '' else open(key_file_path).read(), namespace)
                        namespace['invoke']()

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

                wipe_out()
            case 'save':
                if (key_path := find_slot(args.id)) is not None:
                    shutil.copy(key_path, args.path)
                else:
                    print("Unable to find the key", file=sys.stderr)

            # case 'import':
            #     if find_key(args.id) is not None:
            #         print(f"Operation aborted: '{args.id}' already exists", file=sys.stderr)
            #
            #     if os.path.exists(args.path):
            #         shutil.copy(args.path,f'{KEY_FORGE_KEY_RING_DIR}/{args.id}.enc')
            #     else:
            #         print(f"Operation aborted: file '{args.path}' does not exists", file=sys.stderr)
            case _:
                parser.print_help()
    else:

        if args.version:
            print(f'keyforge version {get_version()}')
        else:
            parser.print_help()


if __name__ == '__main__':
    parser = create_parser()
    main(parser.parse_args(), parser)

# Todo:
#   - setup automatic publish pipeline and acquire badges
#   - implement unittests
#   - check for security enchantments
