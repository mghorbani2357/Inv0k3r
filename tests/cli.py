import io
import os.path
import shutil
from contextlib import redirect_stdout, redirect_stderr, suppress
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

import src.KeyForge.__main__ as invoker_module
from src.KeyForge.__main__ import create_parser, main

SCRIPTS_PATH = '_helper/scripts'


def initialize_test_environment():
    if os.path.exists(invoker_module.INVOKER_HOME_DIR):
        os.rename(
            invoker_module.INVOKER_HOME_DIR,
            f"{invoker_module.INVOKER_HOME_DIR}.backup"
        )
    os.mkdir(invoker_module.INVOKER_HOME_DIR)
    os.mkdir(invoker_module.INVOKER_SLOTS_DIR)


def wipe_out_test_environment():
    shutil.rmtree(invoker_module.INVOKER_HOME_DIR, )
    if os.path.exists(f"{invoker_module.INVOKER_HOME_DIR}.backup"):
        os.rename(
            f"{invoker_module.INVOKER_HOME_DIR}.backup",
            invoker_module.INVOKER_HOME_DIR
        )


class BaseInvokerCLITestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        initialize_test_environment()

    @classmethod
    def tearDownClass(cls):
        wipe_out_test_environment()


class TestMainModuleOfInvokerCLI(BaseInvokerCLITestCase):
    def test_bare_input(self):
        parser = create_parser()
        args = parser.parse_args([])
        f = io.StringIO()
        with redirect_stdout(f):
            main(args, parser)
        output = f.getvalue().strip()

    def test_version(self):
        parser = create_parser()
        args = parser.parse_args(['-v'])
        main(args, parser)


def execute_and_get_output(arguments: list, raise_system_exit_suppression=True):
    parser = create_parser()
    args = parser.parse_args(arguments)
    f = io.StringIO()
    e = io.StringIO()
    suppressed = True
    with suppress(SystemExit) as cm:
        with redirect_stdout(f):
            with redirect_stderr(e):
                main(args, parser)
                suppressed = False

    if suppressed and raise_system_exit_suppression:
        raise Exception('Invalid SystemExit occurred')

    return f,e


class TestAddModuleOfInvokerCLI(BaseInvokerCLITestCase):
    @patch('getpass.getpass', side_effect=[''])
    def test_add_bare_slot(self, mock_getpass):
        execute_and_get_output(['add', f'{SCRIPTS_PATH}/bare_invoke.py'])
        bare_invoker_path = Path(f"{invoker_module.INVOKER_SLOTS_DIR}/bare_invoke.py")
        self.assertTrue(bare_invoker_path.exists(), f"File does not exist: {bare_invoker_path.absolute()}")

    @patch('getpass.getpass', side_effect=['VerySecurePassPhrase', 'VerySecurePassPhrase'])
    def test_add_slot_with_encryption(self, mock_getpass):
        execute_and_get_output(['add', f'{SCRIPTS_PATH}/bare_invoke.py', '--encrypt'])
        bare_invoker_path = Path(f"{invoker_module.INVOKER_SLOTS_DIR}/bare_invoke.enc.py")
        self.assertTrue(bare_invoker_path.exists(), f"File does not exist: {bare_invoker_path.absolute()}")
        self.assertNotEqual(
            invoker_module.sha256sum(bare_invoker_path.absolute()),
            invoker_module.sha256sum(f'{SCRIPTS_PATH}/bare_invoke.py'),
            "Hash of file after encryption doesn't changed"
        )

    def test_add_empty_file(self):
        f,e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/empty_file.py'])
        output = e.getvalue().strip()
        self.assertEqual("Operation aborted: module does not have `invoke` method", output)

    def test_add_incorrect_file(self):
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/incorrect.py'], False)
        output = e.getvalue().strip()
        self.assertEqual("Operation aborted: invalid input", output)

    def test_add_py_file_without_invoke_method(self):
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/without_invoke.py'])
        output = e.getvalue().strip()
        self.assertEqual("Operation aborted: module does not have `invoke` method", output)

    def test_add_so_file_without_invoke_method(self):
        pass

    def test_add_correct_py_file(self):
        execute_and_get_output(['add', f'{SCRIPTS_PATH}/correct.py'])
        bare_invoker_path = Path(f"{invoker_module.INVOKER_SLOTS_DIR}/correct.py")
        self.assertTrue(bare_invoker_path.exists(), f"File does not exist: {bare_invoker_path.absolute()}")

    def test_add_correct_so_file(self):
        pass

    def test_add_use_encrypt_mode_for_py_file(self):
        pass

    def test_add_use_encrypt_mode_for_so_file(self):
        pass

    def test_import_already_encrypted_file(self):
        pass

    def test_invalid_path(self):
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/invalid_path.py'], False)
        output = e.getvalue().strip()
        self.assertEqual(f"Operation aborted: file '{SCRIPTS_PATH}/invalid_path.py' does not exists", output)

    @patch('getpass.getpass', side_effect=['SomePassPhrase', 'DifferentPassPhrase'])
    def test_password_confirmation(self, mock_getpass):
        f, e = execute_and_get_output(['add', f'{SCRIPTS_PATH}/bare_invoke.py', '--encrypt'], False)
        output = e.getvalue().strip()
        self.assertEqual("Operation aborted: passphrase confirmation failed", output)

class TestListModuleOfInvokerCLI(BaseInvokerCLITestCase):
    def test_list_before_any_addition(self):
        pass

    def test_list_after_addition(self):
        pass

    def test_list_while_manual_file_copied(self):
        pass

    def test_list_after_import(self):
        pass

    def test_list_while_irrelevant_file_exists_on_slot_dir(self):
        pass


class TestDeleteModuleOfInvokerCLI(BaseInvokerCLITestCase):
    def test_delete_slot_by_name(self):
        pass

    def test_delete_slot_by_id(self):
        pass

    def test_delete_duplicate_slots_by_name(self):
        pass

    def test_delete_duplicate_slots_by_id(self):
        pass

    def test_delete_none_existing_slot(self):
        pass

    def test_delete_duplicate_slots_by_partial_name(self):
        pass

    def test_delete_duplicate_slots_by_partial_id(self):
        pass


class TestSaveModuleOfInvokerCLI(BaseInvokerCLITestCase):
    def test_save_slot_by_name(self):
        pass

    def test_save_slot_by_id(self):
        pass

    def test_save_duplicate_slots_by_name(self):
        pass

    def test_save_duplicate_slots_by_id(self):
        pass

    def test_save_none_existing_slot(self):
        pass

    def test_save_duplicate_slots_by_partial_name(self):
        pass

    def test_save_duplicate_slots_by_partial_id(self):
        pass


class TestInvokerModuleOfInvokerCLI(BaseInvokerCLITestCase):
    def test_invoker_from_external_file(self):
        pass

    def test_invoker_from_external_encrypted_file(self):
        pass

    def test_invoker_by_id(self):
        pass

    def test_invoker_by_name(self):
        pass

    def test_invoker_by_id_encrypted_mode(self):
        pass

    def test_invoker_by_name_encrypted_mode(self):
        pass


class TestSlotDiscovery(BaseInvokerCLITestCase):
    def test_search_by_name(self):
        Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot1.py").touch()
        Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot2.py").touch()
        Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot3.py").touch()
        self.assertIsNotNone(invoker_module.find_slot('slot1'))
        shutil.rmtree(invoker_module.INVOKER_HOME_DIR)
        os.mkdir(invoker_module.INVOKER_HOME_DIR)

    def test_unable_to_find_slot(self):
        Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot1.py").touch()
        Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot2.py").touch()
        Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot3.py").touch()
        self.assertIsNone(invoker_module.find_slot('unsearchable_slot'))
        shutil.rmtree(invoker_module.INVOKER_HOME_DIR)
        os.mkdir(invoker_module.INVOKER_HOME_DIR)

    def test_search_by_name_enc(self):
        Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot1.enc").touch()
        Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot2.enc").touch()
        Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot3.enc").touch()
        self.assertIsNotNone(invoker_module.find_slot('slot2'))
        shutil.rmtree(invoker_module.INVOKER_HOME_DIR)
        os.mkdir(invoker_module.INVOKER_HOME_DIR)

    def test_search_by_id(self):
        with open(f"{invoker_module.INVOKER_SLOTS_DIR}/slot1.py", 'w') as file:
            file.write("# Some comment to change the sha256sum")
        Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot2.enc").touch()
        Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot3.py").touch()

        sum_id = invoker_module.sha256sum(f"{invoker_module.INVOKER_SLOTS_DIR}/slot1.py")
        self.assertIsNotNone(invoker_module.find_slot(sum_id))
        shutil.rmtree(invoker_module.INVOKER_HOME_DIR)
        os.mkdir(invoker_module.INVOKER_HOME_DIR)

    def test_duplicate_id(self):
        Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot1.py").touch()
        Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot2.enc").touch()
        Path(f"{invoker_module.INVOKER_SLOTS_DIR}/slot3.py").touch()
        sum_id = invoker_module.sha256sum(f"{invoker_module.INVOKER_SLOTS_DIR}/slot2.enc")
        self.assertIsNone(invoker_module.find_slot(sum_id))
        shutil.rmtree(invoker_module.INVOKER_HOME_DIR)
        os.mkdir(invoker_module.INVOKER_HOME_DIR)
