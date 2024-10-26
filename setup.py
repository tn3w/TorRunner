"""
setup.py

Setup TorRunner.

License: Made available under the GPL-3.0 license.
Source: https://github.com/tn3w/TorRunner
"""

from setuptools import setup, find_packages

with open('README.md', 'r', encoding='utf-8') as readable_file:
    long_description = readable_file.read()

setup(
    name = "tor_runner",
    version = "1.4.9.8.1",
    description = "TorRunner is designed to facilitate the deployment of Tor hidden services.",
    long_description = long_description,
    long_description_content_type = 'text/markdown',
    author = 'TN3W',
    author_email = 'tn3w@protonmail.com',
    url = 'https://github.com/tn3w/TorRunner',
    packages = find_packages(),
    include_package_data=True,
    package_data={
        'tor_runner': ['libraries/*', 'libraries/vanguards/*']
    },
    install_requires = [],
    entry_points = {
        'console_scripts': [
            'tor_runner=tor_runner.tor_runner:main',
        ],
    },
    classifiers = [
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Internet :: Proxy Servers",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Server",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries",
        "Topic :: Software Development :: Libraries :: Application Frameworks",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
    ],
    license = 'GPL-3.0',
    keywords = 'tor, flask, sanic, hidden-service, security, privacy',
    python_requires = '>=3.6',
)
