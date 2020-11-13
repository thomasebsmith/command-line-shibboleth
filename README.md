# Command-line Shibboleth
*A command line interface for using the University of Michigan's
Shibboleth authentication system*

**WARNING: This repository is not thoroughly tested and does not
handle errors well.  It may break at any time. Use at your own risk!**

## Requirements
This repository requires:
 - Python >= 3.x
 - Requests
 - Beautiful Soup

## Quick Start
```sh
$ git clone https://github.com/thomasebsmith/command-line-shibboleth.git
$ cd command-line-shibboleth/
$ pip3 install requests BeautifulSoup
$ python3 ./src/__main__.py
  uniqname: <your uniqname here>
  password: <your password here>
  ...
$ curl -L -c cookies.tmp -b cookies.tmp 'https://url-that-requires-shibboleth'
```

## Features
 - Support for 2FA via Duo Push, phone calls, and passcodes.
 - Ability to send passcodes via SMS.
