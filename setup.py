"""setup.py for KeyForge"""

__author__ = "Mohsen Ghorbani"
__email__ = "m.ghorbani2357@gmail.com"
__copyright__ = "Copyright 2025, Mohsen Ghorbani"

from setuptools import setup, find_packages

REQUIREMENTS = filter(None, open('requirements.txt').read().splitlines())

setup(
    name='KeyForge',
    packages=find_packages(),
    install_requires=list(REQUIREMENTS),
)
