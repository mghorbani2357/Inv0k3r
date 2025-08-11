# Invoker CLI: Secure Script Execution

![GitHub License](https://img.shields.io/github/license/mghorbani2357/invoker-cli)
[![Test](https://github.com/mghorbani2357/invoker-cli/actions/workflows/test.yml/badge.svg)](https://github.com/mghorbani2357/invoker-cli/actions/workflows/test.yml)
[![Build Binaries](https://github.com/mghorbani2357/invoker-cli/actions/workflows/build.yml/badge.svg?event=release)](https://github.com/mghorbani2357/invoker-cli/actions/workflows/build.yml)
[![Publish to PyPI](https://github.com/mghorbani2357/invoker-cli/actions/workflows/publish.yml/badge.svg?event=release)](https://github.com/mghorbani2357/invoker-cli/actions/workflows/publish.yml)
[![Codacy Badge](https://app.codacy.com/project/badge/Coverage/f8aee29bfd084444b2bfc1c3354c181d)](https://app.codacy.com/gh/mghorbani2357/invoker-cli/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_coverage)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/f8aee29bfd084444b2bfc1c3354c181d)](https://app.codacy.com/gh/mghorbani2357/invoker-cli/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
![PyPI - Downloads](https://img.shields.io/pypi/dd/invoker-cli?label=HPD)
[![PyPI Downloads](https://static.pepy.tech/badge/invoker-cli)](https://pepy.tech/projects/invoker-cli)
![PyPI - Format](https://img.shields.io/pypi/format/invoker-cli)
![GitHub last commit](https://img.shields.io/github/last-commit/mghorbani2357/invoker-cli)
![GitHub Release](https://img.shields.io/github/v/release/mghorbani2357/invoker-cli)

Invoker CLI is a command-line utility designed for the secure management and execution of local Python scripts. It addresses the critical challenge of handling sensitive data—such as API keys and credentials—by providing a secure, centralized "keyring" for your executable code.

Instead of storing secrets directly, Invoker stores and encrypts the scripts themselves. By adding scripts to Invoker's managed "slots," you can execute them on demand from anywhere in your terminal, with the assurance that their source code is protected by a robust, password-based encryption layer. This approach ensures that your most sensitive logic is never exposed, offering a powerful and elegant solution for digital security and privacy.

---

## 0. Publisher's Note
The genesis of this project, Invoker CLI, is rooted in a sobering reality of our digital age. It began not as a technical exercise, but as a personal mission. When one of close friend's company suffered a devastating data breach—a stark example of a threat many assume is distant—the consequences of compromised credentials became intensely real. This event was followed by the chilling revelation of a 16-billion-record password leak from major platforms like Google, Facebook, and Apple. It became clear that the traditional model of storing sensitive information was fundamentally broken and that the problem was far larger than any single individual or company.

The core idea for this tool emerged from a simple yet profound question: What if sensitive credentials, such as API keys and passwords, were never stored in the first place? What if they could be securely regenerated or recovered on-demand? The goal was to find a way to create a strong, cryptographically secure key which is hard to brute-force but simple for a human to recall.

This led to the concept of empowering each user to have their own unique method for generating these credentials. Rather than relying on a centralized, vulnerable database, a developer could write their own "recipe" as a small, executable script. The challenge then became: how do we store and manage these personalized scripts securely, and how do we ensure they can be executed on demand without exposing their contents?

This line of thought evolved into the Invoker CLI. It's a secure "keyring" for your executable code, a centralized system for managing and running your personal security scripts. It ensures that your unique methods for generating credentials remain private, protected by state-of-the-art encryption. This project is a direct response to a widespread problem, offering a practical, developer-centric solution that prioritizes security and privacy in a world where it's becoming an increasingly rare commodity.

## 1. Quick Start
This guide will walk you through the essential steps to begin using Invoker CLI.

### Step 1: Installation
Use pip to install the package directly.

```bash
pip install invoker-cli
```

### Step 2: Confirm Installation
After the first time you run any Invoker command, it automatically creates the necessary directory structure for you. You can confirm your installation by checking the tool's version.

```bash
invoker --version
# or
invoker -v
```

### Step 3: Create a Compatible Script
For a Python script to be compatible with Invoker, it must contain a function named invoke(). This function serves as the sole entry point that Invoker calls when executing a slot. Here is an example script you can use, saved as `hello.py`:

```python
def invoke():
    print("Hello from Invoker CLI!")
```


### Step 4: Add and Run the Script
Use the `add` command to store your script in slot-ring.

```bash
invoker add hello.py
```

Use the invoke command to run it.

```bash
invoker invoke hello

# Output ->

Hello from Invoker CLI!
```

## 2. Core Concepts Explained

### Slots: Your Script Library

A "slot" is the fundamental unit within Invoker. Think of it as a library entry for a single Python script. When you ``add`` a script, its contents are copied to a dedicated file within the Invoker home directory (``~/.invoker/slots/``). This isolates the script from its original location, meaning you can delete the original file while retaining its functionality within Invoker.

### Identifiers: How to Reference a Slot

Every slot can be referenced in two distinct ways. It's crucial to understand both.

1. **Name:** This is simply the original filename of the script when it was added (e.g., ``my_script.py``). While convenient, names are not guaranteed to be unique. If you add two different scripts both named ``deploy.py`` from different directories, Invoker will treat them as distinct slots.

2. **Hash Prefix:** When a slot is created, Invoker calculates a unique **SHA256** hash of its file content. This hash acts as a perfect fingerprint for the script's code. You can use the first few characters of this hash (e.g., ``a1b2c3d4``) to reference the slot. This is the most reliable method because it's virtually impossible for two different scripts to have the same hash. If you provide a prefix that matches more than one slot (a rare "ambiguous identifier" event), Invoker will return an error and ask you to provide a longer, more specific prefix.

### Encryption: Securing Your Code

Invoker employs a multi-layered, state-of-the-art encryption strategy to protect your slots. When you choose the ``--encrypt`` option, the following process occurs:

* **Password-Based Key Derivation (PBKDF2):** Your provided passphrase is not used directly as the encryption key. Instead, it's fed into the PBKDF2 algorithm.

  * **Salt:** A random 16-byte salt is generated. This ensures that even if two slots are encrypted with the same password, their resulting encryption keys will be completely different. This protects against "rainbow table" attacks.

  * **Iterations (200,000):** The derivation algorithm is repeated 200,000 times. This makes it computationally very expensive and slow for an attacker to try and guess your password, even if they have access to the encrypted file.

* **AES-256 GCM (Galois/Counter Mode):** The derived 32-byte (256-bit) key is used to encrypt your script's content with AES, a military-grade encryption standard.

  * **Authenticated Encryption:** GCM is a mode of operation that not only provides confidentiality (encrypts the data) but also authenticity. This means it can detect if the encrypted file has been tampered with or corrupted. If decryption is attempted on a modified file, the process will fail, preventing the execution of potentially malicious code.

## 3. Installation

You can install Invoker CLI using several methods, from a simple pip install to compiling the source code yourself.

### 1. From PyPI (Recommended)

This is the easiest way to get started. Use pip to install the package directly from the Python Package Index.

```bash
pip install invoker-cli
```

Or you can just clone and install directly from github.


```bash
pip install git+https://github.com/mghorbani2357/invoker-cli.git
```

### 2. From GitHub

If you prefer to work with the latest development version or want to contribute, you can clone the repository and install it directly.

First, clone the repository:
```bash 
git+https://github.com/your-username/invoker-cli.git

git clone https://github.com/your-username/invoker-cli.git
cd invoker-cli
```
Then, install the package in "editable" mode:
```bash
pip install -e .
```

### 3. Using a Pre-compiled Executable

For users who want to run the tool without a Python environment, you can download a pre-compiled executable from the GitHub Releases page. Navigate to the GitHub Releases page for the project. Find the latest release and download the executable file for your operating system (e.g., invoker.exe for Windows, or invoker for macOS/Linux). Place the executable file in a directory that is included in your system's PATH to run it from any terminal.

### 4. Compiling from Source (Advanced)

For users who want to build a self-contained executable for improved performance, you can compile the source code using advanced tools. This is a great option for creating a single binary file that runs without a Python environment.

Nuitka is a powerful compiler that translates your Python code into C++ and then compiles it into a standalone executable. This can result in a significant performance boost over standard Python and is the best choice if you are concerned about execution speed.

Clone the repository as shown in the "From GitHub" section.Install Nuitka and its required compiler dependencies:
```bash
git clone https://github.com/your-username/invoker-cli.git
cd invoker-cli
pip install nuitka
```
**Note**: Nuitka requires a C++ compiler. On Windows, you can use Visual Studio. On Linux, GCC is typically available by default.

Run Nuitka from the root directory of the project:
```bash
nuitka --standalone --onefile invoker_cli/__main__.py
```
The compiled executable will be created in the current directory. Place the executable file in a directory that is included in your system's PATH to run it from any terminal.

## 4. Getting Started
In this section we will walk you through the essential steps to begin using Invoker CLI. You'll learn how to create a compatible script, manage your slots, and run them securely. Lets begin by confirming your installation. You can do this by checking its version.

### version
Prints the current version of the Invoker tool.
**Usage:**
```bash
invoker --version
# or
invoker -v
```
After the first time you run any Invoker command, it automatically creates the necessary directory structure:

* ``~/.invoker/``: The main home directory.
* ``~/.invoker/slots/``: The directory where all script slots are stored.
### Script Requirements
For a Python script to be compatible with Invoker, it **must** contain a function named ``invoke()``. This function serves as the sole entry point that Invoker calls when executing a slot. The script can be as simple or as complex as you need, importing any other libraries and defining any number of helper functions, as long as the ``invoke()`` function exists.

Here is a Python script you can use as an example. It's designed to be compatible with Invoker, and it generates a unique and strong password based on a site name, username, and a master passphrase. This approach ensures the password is consistently generated but never stored, aligning perfectly with the core principles of your project.

**Example `my_pass.py`:**
```python

import hashlib
import getpass
import base64
import sys

def invoke():
    """
    The main entry point for the Invoker tool.
    This script generates a unique password based on user inputs.
    """
    print("--- Secure Password Generator ---")

    # Get a master passphrase securely. This acts as the unique "key"
    # for all your generated passwords. It is never stored.
    try:
        master_passphrase = getpass.getpass("Enter your master passphrase: ")
        if not master_passphrase:
            print("Operation aborted: A passphrase is required.", file=sys.stderr)
            return
    except (EOFError, KeyboardInterrupt):
        print("\nOperation aborted.", file=sys.stderr)
        return

    # Get inputs for the specific password you need.
    site_name = input("Enter the website or service name (e.g., 'google.com'): ")
    username = input("Enter your username for this site: ")
    
    if not site_name or not username:
        print("Operation aborted: Both a site name and username are required.", file=sys.stderr)
        return

    # Combine the inputs into a single string. Using the master passphrase
    # as a salt ensures the output is unique to you.
    combined_string = f"{master_passphrase}:{site_name}:{username}"

    # Hash the combined string using a strong cryptographic algorithm (SHA256).
    # This ensures the output is one-way and cannot be reversed.
    hashed_bytes = hashlib.sha256(combined_string.encode('utf-8')).digest()

    # Encode the hash to a URL-safe base64 string.
    # This creates a password that is safe for most services and includes
    # a mix of uppercase, lowercase, numbers, and symbols.
    generated_password = base64.urlsafe_b64encode(hashed_bytes).decode('utf-8')

    # Trim the password to a reasonable length.
    final_password = generated_password[:16]

    print(f"\nYour generated password for '{site_name}' is:")
    print(f"-> {final_password}")
    print("\n--- Script Finished ---")
```

## 5. Command Reference: In-Depth Examples

### 1. `add`

The add switch copies a script into your Invoker slots, creating a secure copy inside ~/.invoker/slots/. This isolates the script, so you can safely delete the original file while keeping it available through Invoker.

You have the option to add your script with or without encryption.

**Adding an Encrypted Script**

Scenario: Your script, my_pass.py, contains the method you use to generate your passwords. You want to store it securely with strong encryption. Run the add command with the --encrypt flag:

```bash
invoker add api_data_fetcher.py --encrypt
```

Enter and confirm your passphrase when prompted. Your typing will be hidden for security. Confirm the script was added. Invoker will output a unique hash, confirming the script has been added to the secure slots.

Verify the result (optional). The script is now stored in the slots directory with an .enc extension, indicating it is encrypted.
```bash
ls ~/.invoker/slots
# Output:
# my_pass.enc.py
```
**Adding an Unencrypted Script**

Scenario: Your script, helper_utility.py, does not contain sensitive information. You want to add it to your Invoker slots for convenience, but without a password. Run the add command without the --encrypt flag:
```bash
invoker add ./helper_utility.py
```

Confirm the script was added. Invoker will output a unique hash, and the file will be stored without the .enc suffix.

---

### 2. `list`

Provides a quick overview of all available slots.

**Scenario:** After adding a few scripts, you want to see what's available.

1. **Run the ``list`` command:**

```bash
invoker list
```

2. **Review the output:**
The output shows the first 8 characters of the unique hash (for easy reference) and the slot's name.

```text

# Output:
Key Hash    Key Name
--------    --------

a1b2c3d4    helper_utility
f9e8d7c6    my_pass.enc
```
Notice that for encrypted files, the name in the list omits the final extension (``.py``) for clarity.

---

### 3. `delete`

Permanently removes a slot from the Invoker keyring.

**Scenario:** The ```` is outdated and you want to remove it.

1. **Run the ``delete`` command using its name:**

```bash
invoker delete helper_utility
```
2. **Get the confirmation:**
```text
# Output:
Slot `helper_utility` deleted
```
 Alternatively, you could have used its hash prefix.
```bash
invoker delete a1b2c3d4
```

---

### 4. `invoke`

Executes a slot in a clean, isolated environment.

**Functionality:** The ``invoke`` command first clears your current terminal view. This is done to prevent any sensitive output from the script (like tokens or private data) from accidentally remaining visible in your scrollback history after the script finishes. When the script is done, Invoker waits for you to press ``Enter`` before restoring your original terminal view, giving you time to review the output.

**Scenario:** You need to run the encrypted ``my_pass``.

1. **Run the ``invoke`` command using its hash:**

```bash
invoker invoke f9e8d7c6
```

2. **The screen clears, and you are prompted for the password:**
```text
Enter passphrase to decrypt the module:
# (Your typing is hidden)
```

3. **The script executes:**
   If the password is correct, the script is decrypted in memory and executed.

```text
Enter your master passphrase: 
# (Your typing is hidden)
Enter the website or service name (e.g., 'google.com'): `someplace.com`
Enter your username for this site: `some_username`
--- Your generated password for 'someplace.com' is:
-> 47DEQpj8HBSa-_TI'
--- Script Finished ---
```

4. **Wipe out:**
   After execution, the program waits for your confirmation to clean up the screen.

```text
Press `Enter` to wipe out
```

Pressing ``Enter`` restores your terminal to its previous state, leaving no trace of the script's output.

---

### 5. `save`

Exports a slot from the keyring to an external file. This is perfect for backups or for sharing a script with a colleague.

**Scenario 1: Backing up an encrypted script.**
You want to save the encrypted ``my_pass`` to an external drive without decrypting it.

1. **Run the ``save`` command:**

```bash
invoker save f9e8d7c6 /mnt/backups/saved_pass.py
```

2. **Get confirmation:**

```text
# Output:
# Slot `f9e8d7c6` saved to `/mnt/backups/saved.py`
```
The resulting file is an exact, encrypted copy of the slot. you could use this method also for unencrypted slots.

**Scenario 2: Exporting a decrypted version for review.**
You need to view the source code of the ``my_pass``.

1. **Run the ``save`` command with the ``--decrypt`` flag:**

```bash
invoker save f9e8d7c6 /tmp/decrypted_source.py --decrypt
```
2. **Enter the passphrase when prompted:**
```text
Enter passphrase to decrypt the module:
# (Your typing is hidden)
```

3. **Get confirmation:**

```text
# Output:
Slot `f9e8d7c6` saved to `/tmp/decrypted_source.py`
```
The file ``/tmp/decrypted_source.py`` now contains the plain-text source code of the script.

## Conclusion

**Invoker CLI** represents a significant step in the ongoing effort to build a more secure digital world. This project is not presented as a definitive, all-encompassing solution to the massive problem of data breaches and credential management. Instead, it is a focused tool designed to offer a practical, and effective way for developers to mitigate a common and critical security risk.

The path to true digital privacy is a long and complex one, and this is by no means the end of that journey or the final effort. **Invoker CLI** is built on the belief that a fundamental shift is needed—away from vulnerable storage and towards secure, on-demand generation. By helping to secure the individual scripts that are the lifeblood of our digital workflows, we hope to contribute to a larger, more resilient ecosystem. We encourage the community to use this tool, provide feedback, and join us in this ongoing mission to make digital security a proactive practice, not just a reactive measure.
