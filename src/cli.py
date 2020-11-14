from getpass import getpass

from .library import ShibbolethSession


class CLI:
    def __init__(self, cookie_file):
        self._session = ShibbolethSession(cookie_file)

    def perform(self, request):
        result = self._session.perform(request, self)
        self._session.save_cookies()
        return result

    def get_credentials(self):
        uniqname = input("uniqname: ")
        password = getpass("password: ")
        return {
            "uniqname": uniqname,
            "password": password,
        }

    def show_credentials_error(self, error):
        print(error)

    def on_two_factor_start(self, credentials):
        print(f"Duo two-factor login for {credentials['uniqname']}")

    def on_two_factor_fail(self):
        print()

    def choose_duo(self, duo_choices):
        print("Select one of the following options:")
        for index, choice in enumerate(duo_choices):
            print(f" {index + 1}. {choice['description']}")
        print()

        choice = None
        while choice is None:
            choice = input(f"option: ")
            try:
                choice = int(choice)
                if choice < 1 or choice > len(duo_choices):
                    choice = None
            except ValueError:
                choice = None

        choice = duo_choices[choice - 1]
        passcode = None
        if choice["factor"] == "Passcode":
            passcode = input(f"passcode: ")

        return {
            "choice": choice,
            "passcode": passcode,
        }
