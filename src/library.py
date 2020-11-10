import ast
from http.cookiejar import FileCookieJar
import json
import re
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
        self._session.cookies = FileCookieJar(cookie_file_name)
        self._session.headers.update({
            "User-Agent": "Mozilla/5.0",
            "Accept-Language": "en-US,en;q=0.5",
        })

        self._authenticated = False
        self._two_factor_authenticated = False
        self._duo_config = None
        self._duo_choices = None
        self._duo_sid = None

        self._weblogin_url = "https://weblogin.umich.edu/"
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

    def two_factor_authenticate(self, method):
        """
        Attempt to perform 2FA using the given method.

        Requires that the session is authenticated().
        """
        if not self.authenticated():
            raise ShibbolethError(
                "User must be authenticated to Shibboleth before attempting "
                "two-factor authentication."
            )
        # TODO
