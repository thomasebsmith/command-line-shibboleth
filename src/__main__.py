#!/usr/bin/env python3

import argparse
import requests
import sys

from .cli import CLI
from .library import ShibbolethError

def run():
    """Authenticate via U-M Shibboleth from the command line."""
    parser = argparse.ArgumentParser(
        description="Authenticate to U-M Shibboleth from the command line."
    )
    parser.add_argument(
        "cookie_file",
        default="cookies.tmp",
        nargs="?",
        help="a Netscape-style cookie file (e.g. one generated by cURL)"
    )
    args = parser.parse_args()
    cookie_file = args.cookie_file

    try:
        cli = CLI(cookie_file)
        request = requests.Request("GET", "https://weblogin.umich.edu/")
        result = cli.perform(request)
        #print(result.text)
        return 0
    except requests.exceptions.ConnectionError as e:
        print("Error connecting to Shibboleth server(s):", file=sys.stderr)
        return 1
    except requests.exceptions.Timeout:
        print("A request timed out.", file=sys.stderr)
        return 1
    except requests.exceptions.TooManyRedirects:
        print("Too many redirects.", file=sys.stderr)
        return 1
    except ShibbolethError as e:
        print(e, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 1

if __name__ == "__main__":
    sys.exit(run())
