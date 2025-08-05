==============================
Invoker CLI: Secure Script Execution
==============================
0. Publisher Notes

1. Introduction
---------------

Invoker is a powerful command-line utility designed for the secure storage, management, and execution of local Python scripts. It addresses the common challenge of managing a growing collection of utility and automation scripts, especially those containing sensitive information like API keys, credentials, or proprietary logic.

The core purpose of Invoker is to provide a secure, centralized "keyring" for your executable Python code. By adding scripts to Invoker's managed "slots," you can run them on demand from anywhere in your terminal, with the assurance that their source code is protected by a robust, password-based encryption layer.

2. Core Concepts Explained
--------------------------

### Slots: Your Script Library

A "slot" is the fundamental unit within Invoker. Think of it as a library entry for a single Python script. When you ``add`` a script, its contents are copied to a dedicated file within the Invoker home directory (``~/.invoker/slots/``). This isolates the script from its original location, meaning you can delete the original file while retaining its functionality within Invoker.

### Identifiers: How to Reference a Slot

Every slot can be referenced in two distinct ways. It's crucial to understand both.

1. **Name:** This is simply the original filename of the script when it was added (e.g., ``my_script.py``). While convenient, names are not guaranteed to be unique. If you add two different scripts both named ``deploy.py`` from different directories, Invoker will treat them as distinct slots.

2. **Hash Prefix:** When a slot is created, Invoker calculates a unique SHA256 hash of its file content. This hash acts as a perfect fingerprint for the script's code. You can use the first few characters of this hash (e.g., ``a1b2c3d4``) to reference the slot. This is the most reliable method because it's virtually impossible for two different scripts to have the same hash. If you provide a prefix that matches more than one slot (a rare "ambiguous identifier" event), Invoker will return an error and ask you to provide a longer, more specific prefix.

### Encryption: Securing Your Code

Invoker employs a multi-layered, state-of-the-art encryption strategy to protect your slots. When you choose the ``--encrypt`` option, the following process occurs:

* **Password-Based Key Derivation (PBKDF2):** Your provided passphrase is not used directly as the encryption key. Instead, it's fed into the PBKDF2 algorithm.

  * **Salt:** A random 16-byte salt is generated. This ensures that even if two slots are encrypted with the same password, their resulting encryption keys will be completely different. This protects against "rainbow table" attacks.

  * **Iterations (200,000):** The derivation algorithm is repeated 200,000 times. This makes it computationally very expensive and slow for an attacker to try and guess your password, even if they have access to the encrypted file.

* **AES-256 GCM (Galois/Counter Mode):** The derived 32-byte (256-bit) key is used to encrypt your script's content with AES, a military-grade encryption standard.

  * **Authenticated Encryption:** GCM is a mode of operation that not only provides confidentiality (encrypts the data) but also authenticity. This means it can detect if the encrypted file has been tampered with or corrupted. If decryption is attempted on a modified file, the process will fail, preventing the execution of potentially malicious code.

3. Getting Started
------------------

### Initial Setup

The first time you run any Invoker command, it automatically creates the necessary directory structure:

* ``~/.invoker/``: The main home directory.
* ``~/.invoker/slots/``: The directory where all script slots are stored.

### Script Requirements: The `invoke()` Function

For a Python script to be compatible with Invoker, it **must** contain a function named ``invoke()``. This function serves as the sole entry point that Invoker calls when executing a slot. The script can be as simple or as complex as you need, importing any other libraries and defining any number of helper functions, as long as the ``invoke()`` function exists.

**Example `api_data_fetcher.py`:**

.. code-block:: python

    import os
    import requests # This script has external dependencies

    # Ensure you have installed dependencies: pip install requests

    API_KEY = os.environ.get("MY_SECRET_API_KEY", "default_key_if_not_set")

    def _fetch_from_endpoint(endpoint_url):
        """A helper function to handle the API call."""
        try:
            headers = {"Authorization": f"Bearer {API_KEY}"}
            response = requests.get(endpoint_url, headers=headers)
            response.raise_for_status() # Raises an exception for bad status codes
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching data: {e}")
            return None

    def invoke():
        """The main entry point for the Invoker tool."""
        print("--- Starting API Data Fetcher ---")
        user_data = _fetch_from_endpoint("https://api.example.com/users/1")
        if user_data:
            print(f"Successfully fetched user: {user_data.get('name')}")
        print("--- Script Finished ---")


4. Command Reference: In-Depth Examples
---------------------------------------

### `add`

Adds a new script to the Invoker slots, creating a secure copy inside ``~/.invoker/slots/``.

**Scenario:** You have written the ``api_data_fetcher.py`` script from the example above and want to add it to Invoker with encryption because it handles an API key.

1. **Run the ``add`` command with the ``--encrypt`` flag:**

   .. code-block:: bash

      invoker add ./api_data_fetcher.py --encrypt

2. **Enter your passphrase when prompted:**

   .. code-block:: text

      Enter passphrase to encrypt the module(leave it blank if you don't want to encrypt it):
      # (Your typing will be hidden)
      Please enter passphrase to confirm:
      # (Your typing will be hidden)

3. **Get the confirmation hash:**

   .. code-block:: text

      # Output:
      f9e8d7c6b5a4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8 added to slot-ring

4. **Verify the result (optional):**
   You can now see the encrypted file in the slots directory.

   .. code-block:: bash

      ls ~/.invoker/slots
      # Output:
      # api_data_fetcher.enc.py

   The ``.enc`` suffix is automatically added to signify that the slot is encrypted.

----

### `list`

Provides a quick overview of all available slots.

**Scenario:** After adding a few scripts, you want to see what's available.

1. **Run the ``list`` command:**

   .. code-block:: bash

      invoker list

2. **Review the output:**
   The output shows the first 8 characters of the unique hash (for easy reference) and the slot's name.

   .. code-block:: text

      # Output:
      # Key Hash    Key Name
      # --------    --------
      #
      # a1b2c3d4    backup_script
      # f9e8d7c6    api_data_fetcher.enc

   Notice that for encrypted files, the name in the list omits the final extension (``.py``) for clarity.

----

### `delete`

Permanently removes a slot from the Invoker keyring.

**Scenario:** The ``backup_script`` is outdated and you want to remove it.

1. **Run the ``delete`` command using its name:**

   .. code-block:: bash

      invoker delete backup_script

2. **Get the confirmation:**

   .. code-block:: text

      # Output:
      # Slot `backup_script` deleted

   Alternatively, you could have used its hash prefix: ``invoker delete a1b2c3d4``.

----

### `invoke`

Executes a slot in a clean, isolated environment.

**Functionality:** The ``invoke`` command first clears your current terminal view. This is done to prevent any sensitive output from the script (like tokens or private data) from accidentally remaining visible in your scrollback history after the script finishes. When the script is done, Invoker waits for you to press ``Enter`` before restoring your original terminal view, giving you time to review the output.

**Scenario:** You need to run the encrypted ``api_data_fetcher``.

1. **Run the ``invoke`` command using its hash:**

   .. code-block:: bash

      invoker invoke f9e8d7c6

2. **The screen clears, and you are prompted for the password:**

   .. code-block:: text

      Enter passphrase to decrypt the module:
      # (Your typing is hidden)

3. **The script executes:**
   If the password is correct, the script is decrypted in memory and executed.

   .. code-block:: text

      --- Starting API Data Fetcher ---
      Successfully fetched user: John Doe
      --- Script Finished ---

4. **Wipe out:**
   After execution, the program waits for your confirmation to clean up the screen.

   .. code-block:: text

      Press `Enter` to wipe out

   Pressing ``Enter`` restores your terminal to its previous state, leaving no trace of the script's output.

----

### `save`

Exports a slot from the keyring to an external file. This is perfect for backups or for sharing a script with a colleague.

**Scenario 1: Backing up an encrypted script.**
You want to save the encrypted ``api_data_fetcher`` to an external drive without decrypting it.

1. **Run the ``save`` command:**

   .. code-block:: bash

      invoker save f9e8d7c6 /mnt/backups/api_fetcher_encrypted.py

2. **Get confirmation:**

   .. code-block:: text

      # Output:
      # Slot `f9e8d7c6` saved to `/mnt/backups/api_fetcher_encrypted.py`

   The resulting file is an exact, encrypted copy of the slot.

**Scenario 2: Exporting a decrypted version for review.**
You need to view the source code of the ``api_data_fetcher``.

1. **Run the ``save`` command with the ``--decrypt`` flag:**

   .. code-block:: bash

      invoker save f9e8d7c6 /tmp/decrypted_source.py --decrypt

2. **Enter the passphrase when prompted:**

   .. code-block:: text

      Enter passphrase to decrypt the module:
      # (Your typing is hidden)

3. **Get confirmation:**

   .. code-block:: text

      # Output:
      # Slot `f9e8d7c6` saved to `/tmp/decrypted_source.py`

   The file ``/tmp/decrypted_source.py`` now contains the plain-text source code of the script.

----

### `version`

Prints the current version of the Invoker tool.

**Usage:**

.. code-block:: bash

   invoker --version
   # or
   invoker -v
