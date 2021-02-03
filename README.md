# Command-line Shibboleth
*A command line interface for using the University of Michigan's
Shibboleth/Weblogin authentication system*

**WARNING: This repository is not thoroughly tested and does not
handle errors well. It may break at any time. Use at your own risk!**

## Requirements
This repository requires:
 - Python >= 3.x
 - Python Requests module
 - Python Beautiful Soup module >= 4.x

## Quick Start
```sh
$ git clone https://github.com/thomasebsmith/command-line-shibboleth.git
$ cd command-line-shibboleth/
$ pip3 install requests beautifulsoup4
$ ./login
  uniqname: <your uniqname here>
  password: <your password here>
  ...
$ curl -L -c .cookies.tmp -b .cookies.tmp 'https://url-that-requires-shibboleth'
```

## Features
 - Support for 2FA via Duo Push, phone calls, and passcodes.
 - Ability to send passcodes via SMS.
 - Python library for advanced usage.

## Installation Notes
By default, `beautifulsoup4` cannot be installed without `sudo` permission.
If you are installing this in CAEN or a similar environment without this
permission, try using the following commands to install `beautifulsoup4`:
```sh
$ mkdir -p ~/some/folder/for/pip/packages
$ pip3 install -t ~/some/folder/for/pip/packages beautifulsoup4
$ echo 'PYTHONPATH="~/some/folder/for/pip/packages:$PYTHONPATH"' >> ~/.profile
$ source ~/.profile
```
