"""setup.py for Invoker-CLI"""

__author__ = "Mohsen Ghorbani"
__email__ = "m.ghorbani2357@gmail.com"
__copyright__ = "Copyright 2025, Mohsen Ghorbani"

from setuptools import setup

setup(
    install_requires=filter(None, open('requirements.txt').read().splitlines())
)
