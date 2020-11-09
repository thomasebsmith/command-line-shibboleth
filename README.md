# Command-line Shibboleth
*A command line interface for using the University of Michigan's
Shibboleth authentication system*

**WARNING: This script is not tested and does not handle errors well.
It may break at any time. Use at your own risk!**

## Quick Start
```sh
$ git clone https://github.com/thomasebsmith/command-line-shibboleth.git
$ cd command-line-shibboleth/
$ ./weblogin.sh
  uniqname: <your uniqname here>
  password: <your password here>
$ curl -L -c cookies.tmp -b cookies.tmp 'https://url-that-requires-shibboleth'
