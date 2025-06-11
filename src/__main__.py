import argparse
import getpass
import hashlib
import importlib.util
import os
import subprocess
import sys
import traceback
from pathlib import Path

from black_smith import encrypt_file, decrypt_file


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


KEY_FORGE_HOME_DIR = f'{os.path.expanduser('~')}/.key_forge'
KEY_FORGE_KEY_RING_DIR = f'{KEY_FORGE_HOME_DIR}/keyring'
KEY_FORGE_TMP_DIR = f'{KEY_FORGE_HOME_DIR}/tmp'

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

    match args.which:
        case 'add':
            if not os.path.exists(args.path):
                print(f"Operation aborted: file '{args.output}' does not exists", file=sys.stderr)
                exit(1)
            spec = importlib.util.spec_from_file_location('key', args.path)
            module = importlib.util.module_from_spec(spec)

            if spec.loader:
                spec.loader.exec_module(module)
            else:
                print(f"No loader found for {args.path}")
                exit(1)

            if not hasattr(module, 'invoke'):
                print(f"Operation aborted: module does not have `invoke` method", file=sys.stderr)
                exit(1)

            plugin_name = os.path.splitext(os.path.basename(args.path))[0]
            password = getpass.getpass('Enter passphrase to encrypt the module:\n', stream=None)

            with open(f'{KEY_FORGE_KEY_RING_DIR}/{plugin_name}.enc', 'wb') as f:
                f.write(encrypt_file(args.path, password))
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
            if (key_path := find_key(args.id))is not None:
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
                exit(0)
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
