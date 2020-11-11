import ast
from http.cookiejar import MozillaCookieJar, LoadError
import json
import re
from time import sleep
from urllib.parse import parse_qs, urlencode, urlparse

from bs4 import BeautifulSoup, element as bs4_element
import requests

class ShibbolethError(Exception):
    def init(self, message):
        super().__init__(self, message)


class ShibbolethSession:
    def __init__(self, cookie_file_name):
        """Create an authentication session using the given cookie file."""
        self._session = requests.Session()
        self._session.cookies = MozillaCookieJar(cookie_file_name)
        try:
            self._session.cookies.load(ignore_discard=True)
        except (LoadError, OSError):
            pass
        self._session.headers.update({
            "User-Agent": "Mozilla/5.0",
            "Accept-Language": "en-US,en;q=0.5",
        })

        self._authenticated = False
        self._two_factor_authenticated = False
        self._duo_config = None
        self._duo_choices = None
        self._duo_sid = None
        self._duo_txid = None

        self._weblogin_host = "https://weblogin.umich.edu"
        self._weblogin_url = f"{self._weblogin_host}/"
        self._js_regex = re.compile(
            r"[;\s](var|const|let)\s+error\s*=\s*(['\"])(.*?)\2\s*;",
            re.MULTILINE
        )
        # TODO: This could be improved
        self._duo_config_regex = re.compile(
            r"[;\s](var|const|let)\s+duo_config\s*=\s*({[^}]*})\s*;",
            re.MULTILINE
        )

    def authenticated(self):
        """Return whether Shibboleth authentication is complete."""
        return self._authenticated

    def two_factor_authenticated(self):
        """Return whether two-factor authentication is complete."""
        return self._two_factor_authenticated
    
    def authenticate(self, uniqname, password):
        """
        Attempt to authenticate the user to Shibboleth.

        Does not perform 2FA, but determines what 2FA methods are available.
        Returns these choices, or None if authentication was not successful.
        """
        self._session.get(self._weblogin_url, allow_redirects=False)

        post_headers = {}
        post_data = {
            "ref": "",
            "service": "",
            "required": "",
            "login": uniqname,
            "loginX": uniqname,
            "password": password,
        }
        post_res = self._session.post(
            self._weblogin_url,
            headers=post_headers,
            data=post_data,
            allow_redirects=False,
        )
        post_response_html = BeautifulSoup(post_res.text, "html.parser")
        script = post_response_html.find("script", string=self._js_regex)
        error = re.search(self._js_regex, script.string).group(3)
        if error != "Additional authentication is required.":
            raise ShibbolethError(error)

        self._duo_config = ast.literal_eval(
            re.search(self._duo_config_regex, script.string).group(2)
        )

        self._duo_choices = self.get_duo_choices()

        self._authenticated = True

        return self._duo_choices

    def get_duo_choices(self):
        """Attempt to get possible choices for a Duo 2FA request."""
        assert(self._duo_config is not None)
        self._post_duo_auth()
        prompt_url = f"https://{self._duo_config['host']}/frame/prompt"
        params = {
            "sid": self._duo_sid,
        }
        headers = {}
        res = self._session.get(
            prompt_url,
            headers=headers,
            params=params,
            allow_redirects=False,
        )
        res_html = BeautifulSoup(res.text, "html.parser")
        options = res_html.select("select[name=device] > option")

        return list(map(lambda option: ({
            "id": option["value"],
            "description": option.get_text(),
        }), options))

    def _post_duo_auth(self):
        assert(self._duo_config is not None)
        auth_url = f"https://{self._duo_config['host']}/frame/web/v1/auth"
        post_headers = {
            "Origin": f"https://{self._duo_config['host']}"
        }
        post_data = {
            "tx": self._duo_sig(),
            "parent": self._weblogin_url,
            "java_version": "",
            "flash_version": "",
            "screen_resolution_width": "500",
            "screen_resolution_height": "1000",
            "color_depth": "24",
            "is_cef_browser": "false",
            "is_ipad_os": "false",
        }
        post_params = {
            "tx": self._duo_sig(),
            "parent": self._weblogin_url,
            "v": "2.6"
        }
        post_res = self._session.post(
            auth_url,
            params=post_params,
            headers=post_headers,
            data=post_data,
            allow_redirects=False,
        )
        query_params = parse_qs(urlparse(post_res.headers["Location"]).query)
        self._duo_sid = query_params["sid"][0]

    def _duo_sig(self):
        return self._duo_config["sig_request"].split(":APP")[0]
    
    def _duo_sig_suffix(self):
        return self._duo_config["sig_request"].split(":APP")[1]

    def two_factor_authenticate(self, device):
        """
        Attempt to perform 2FA using the given method.

        Requires that the session is authenticated().
        """
        if not self.authenticated():
            raise ShibbolethError(
                "User must be authenticated to Shibboleth before attempting "
                "two-factor authentication."
            )

        assert(self._duo_config is not None)

        prompt_url = f"https://{self._duo_config['host']}/frame/prompt"
        prompt_headers = {
            "Accept": "text/plain, */*; q=0.01",
            "Origin": f"https://{self._duo_config['host']}",
            "X-Requested-With": "XMLHttpRequest",
        }
        prompt_data = {
            "sid": self._duo_sid,
            "device": device,
            "factor": "Duo Push",
            "out_of_date": "",
            "days_out_of_date": "",
            "days_to_block": "None",
        }

        self._duo_txid = self._session.post(
            prompt_url,
            headers=prompt_headers,
            data=prompt_data,
            allow_redirects=False
        ).json()["response"]["txid"]

        status_url = f"https://{self._duo_config['host']}/frame/status"
        status_headers = {
            "Accept": "text/plain, */*; q=0.01",
            "Origin": f"https://{self._duo_config['host']}",
            "X-Requested-With": "XMLHttpRequest",
        }
        status_data = {
            "sid": self._duo_sid,
            "txid": self._duo_txid,
        }
        while True:
            sleep(2)
            status_dict = self._session.post(
                status_url,
                headers=status_headers,
                data=status_data
            ).json()
            if status_dict["response"]["status_code"] == "allow":
                break

        cookie_url = f"{status_url}/{self._duo_txid}"
        cookie_headers = status_headers
        cookie_data = {
            "sid": self._duo_sid,
        }
        duo_cookie = self._session.post(
            cookie_url,
            headers=cookie_headers,
            data=cookie_data,
            allow_redirects=False,
        ).json()["response"]["cookie"]
        full_duo_cookie = f"{duo_cookie}:APP{self._duo_sig_suffix()}"

        weblogin_headers = {
            "Origin": self._weblogin_host,
        }
        weblogin_data = {
            "ref": "",
            "service": "",
            "required": "mtoken",
        }
        weblogin_data[self._duo_config["post_argument"]] = full_duo_cookie
        weblogin_url=f"{self._weblogin_host}{self._duo_config['post_action']}"
        response = self._session.post(
            weblogin_url,
            headers=weblogin_headers,
            data=weblogin_data,
            allow_redirects=False
        )

    def save_cookies(self):
        """Save the cookies to the cookie file."""
        self._session.cookies.save(ignore_discard=True)
