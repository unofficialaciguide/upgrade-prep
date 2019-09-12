"""
    ACI session handler

    This heavily leverages the acitoolkit Session module with changes pulled from StateChecker and
    EnhancedEndpointTracker and websocket/certificate dependencies removed.
    https://github.com/datacenter/acitoolkit
    https://github.com/datacenter/statechecker
    https://github.com/agccie/ACI-EnhancedEndpointTracker
"""

from requests.exceptions import ConnectionError
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.cookies import create_cookie

import json
import logging
import re
import requests
import threading
import time
import traceback
import urllib3

# module level logging
logger = logging.getLogger(__name__)

# disable urllib warnings
urllib3.disable_warnings()

class Session(object):
    """ Session class responsible for all communication with the APIC """

    LIFETIME_MIN = 900              # minimum lifetime for session (15 minutes)
    LIFETIME_MAX = 86400            # maximum lifetime for session (1 day)
    LIFETIME_REFRESH = 0.95         # percentage of lifetime before refresh is started
    DEFAULT_SUBSCRIPTION_REFRESH = 60   # default subscription refresh time
    MIN_SUBSCRIPTION_REFRESH = 30       # min refresh to 30 seconds
    MAX_SUBSCRIPTION_REFRESH = 36000    # limit to refresh time to 10 hours

    def __init__(self, url, uid, pwd=None, cert_name=None, key=None, verify_ssl=False,
                 appcenter_user=False, proxies=None, resubscribe=True, graceful=True, lifetime=0,
                 subscription_refresh_time=60, cached_token=None, token_refresh_callback=None):
        """
            url (str)               apic url such as https://1.2.3.4
            uid (str)               apic username or certificate name 
            pwd (str)               apic password
            cert_name (str)         certificate name for certificate-based authentication
            key (str)               path to certificate file used for certificate-based 
                                    authentication if a password is provided then it will be 
                                    prefered over certficate
            verify_ssl (bool)       verify ssl certificate for ssl connections
            appcenter_user (bool)   set to true when using certificate authentication from ACI app
            proxies (dict)          optional dict containing the proxies passed to request library
            resubscribe (bool)      auto resubscribe on if subscription or login fails
                                    if false then subscription thread is closed on refresh failure
            graceful(bool)          trigger graceful_resubscribe at 95% of maximum lifetime which
                                    acquires new login token and gracefully restarts subscriptions.
                                    During this time, there may be duplicate data on subscription 
                                    but no data should be lost.
            lifetime (int)          maximum lifetime of the session before triggering a new login
                                    or graceful resubscribe (if graceful is enabled). If set to 0,
                                    then lifetime is set based on maximumLifetimeSeconds at login.
                                    Else the minimum value of lifetime or maximumLifetimeSeconds is
                                    used.
            subscription_refresh_time (int) Seconds for each subscription before it needs to be 
                                    refreshed. If the value is greater than default 
                                    SUBSCRITION_REFRESH, then it is provided as an http parameter
                                    in the initial subscription setup. Note, this is only supported
                                    in 4.0 and above. Caller should verify APIC/nodes are running
                                    a supported version of code before extended the subscription
                                    refresh time to custom value.
            cached_token            (bool) valid token to use for API requests. If provided, then
                                    that token is used for every API request and refresh/subscription
                                    is disabled.
            token_refresh_callback  (func) function triggered on each token refresh. Must accept
                                    single argument which is this session object.
        """
        url = str(url)
        uid = str(uid)
        if pwd is not None:
            pwd = str(pwd)
        if key is not None:
            key = str(key)
        if pwd is None and (key is None or cert_name is None):
            raise Exception("A password or cert_name and key are required")

        r1 = re.search("^(?P<protocol>https?://)?(?P<hostname>.+$)", url.lower())
        if r1 is not None:
            self.hostname = r1.group("hostname")
            if r1.group("protocol") is None: 
                self.api = "https://%s" % self.hostname
            else:
                self.api = "%s%s" % (r1.group("protocol"), self.hostname)
        else:
            raise Exception("invalid APIC url: %s" % url)

        self.uid = uid
        self.pwd = pwd
        self.cert_name = cert_name
        self.key = key
        self.appcenter_user = appcenter_user
        self.default_timeout = 120
        self.resubscribe = resubscribe
        self.graceful = graceful
        self.lifetime = lifetime
        self.subscription_refresh_time = subscription_refresh_time
        # limit subscription_refresh to min/max
        if self.subscription_refresh_time > Session.MAX_SUBSCRIPTION_REFRESH:
            self.subscription_refresh_time = Session.MAX_SUBSCRIPTION_REFRESH
        elif self.subscription_refresh_time < Session.MIN_SUBSCRIPTION_REFRESH:
            self.subscription_refresh_time = Session.MIN_SUBSCRIPTION_REFRESH

        if self.pwd is not None:
            self.cert_auth = False
        else:
            self.cert_auth = True
            try:
                with open(self.key, 'r') as f:
                    self._x509Key = load_privatekey(FILETYPE_PEM, f.read())
            except Exception as e:
                logger.debug("Traceback:\n%s", traceback.format_exc())
                raise TypeError("Could not load private key(%s): %s" % (self.key, e))

        self.verify_ssl = verify_ssl
        self.session = None
        self.token = None
        self.login_timeout = 0
        self.login_lifetime = 0
        self.login_thread = None
        self.subscription_thread = None
        self._logged_in = False
        self._proxies = proxies
        # Disable the warnings for SSL
        if not self.verify_ssl:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        # cached mode when user provides a valid cached token
        self._cached_mode = False
        if cached_token is not None:
            self._cached_mode = True
            self.token = cached_token
            self.session = requests.Session()
            self.session.cookies.set_cookie(create_cookie(name="APIC-cookie", value=cached_token))
        # support token refresh callbacks
        self.token_refresh_callback = token_refresh_callback

    def _send_login(self, timeout=None):
        """ send the actual login request to the APIC and open the web socket interface. """

        self._logged_in = False
        self.session = requests.Session()

        if self.appcenter_user:
            login_url = '/api/requestAppToken.json'
            data = {'aaaAppToken':{'attributes':{'appName': self.cert_name}}}
        elif self.cert_auth:
            # skip login for non appcenter_user cert auth
            resp = requests.Response()
            resp.status_code = 200
            return resp
        else:
            login_url = '/api/aaaLogin.json'
            data = {'aaaUser': {'attributes': {'name': self.uid, 'pwd': self.pwd}}}
        ret = self.push_to_apic(login_url, data=data, timeout=timeout, retry=False)
        if not ret.ok:
            logger.warn("could not login to apic, closing session")
            self.close()
            return ret
        self._logged_in = True
        ret_data = json.loads(ret.text)['imdata'][0]
        self.token = str(ret_data['aaaLogin']['attributes']['token'])
        self.login_timeout = int(ret_data['aaaLogin']['attributes']['refreshTimeoutSeconds'])/2
        lifetime = float(ret_data['aaaLogin']['attributes']['maximumLifetimeSeconds'])
        if self.lifetime > 0:
            lifetime = min(self.lifetime, lifetime)
        lifetime = lifetime * Session.LIFETIME_REFRESH
        if lifetime < Session.LIFETIME_MIN:
            lifetime = Session.LIFETIME_MIN
        elif lifetime > Session.LIFETIME_MAX:
            lifetime = Session.LIFETIME_MAX
        self.login_lifetime = time.time() + lifetime
        logger.debug("lifetime set to %.3f (%.3f seconds)", self.login_lifetime, lifetime)

        # trigger token refresh callback on initial token acqusition
        if callable(self.token_refresh_callback):
            self.token_refresh_callback(self)
        return ret

    def push_to_apic(self, url, data={}, timeout=None, method="POST", retry=True):
        """ POST/DELETE the object data to the APIC

            url (str)       relative url to post/delete
            data (dict)     data to send to the APIC
            timeout (int)   timeout in seconds to complete the request
            method (str)    method (POST or DELETE)
            retry (bool)    retry post/delete on failure

            returns requests response object
        """
        return self._send(method, url, data=data, timeout=timeout, retry=retry)

    def get(self, url, timeout=None, retry=True):
        """ perform REST GET request to apic

            url (str)       relative url to get
            timeout (int)   timeout in seconds to complete the request
            retry (bool)    retry get on failure

            returns requests response object
        """
        return self._send("GET", url, timeout=timeout, retry=retry)

    def login(self, timeout=30):
        """ login to APIC, return bool success """
        if self._cached_mode:
            logger.error("login method not supported when running in cached mode")
            return False
        try:
            resp = self._send_login(timeout)
            if resp.status_code == 200:
                if self.login_thread is None:
                    self.login_thread = Login(self)
                    self.login_thread.daemon = True
                    self.login_thread.start()
                return True
        except ConnectionError as e:
            logger.warn('Could not login to APIC due to ConnectionError: %s', e)
        return False

    def refresh_login(self, timeout=None):
        """ Refresh the login to the APIC, return bool success """
        if self._cached_mode:
            logger.error("login refresh method not supported when running in cached mode")
            return False
        logger.debug("refreshing apic login")
        refresh_url = '/api/aaaRefresh.json'
        resp = self.get(refresh_url, timeout=timeout, retry=False)
        if resp.status_code == 200:
            ret_data = json.loads(resp.text)['imdata'][0]
            self.token = str(ret_data['aaaLogin']['attributes']['token'])
            # trigger token refresh callback
            if callable(self.token_refresh_callback):
                self.token_refresh_callback(self)
            return True
        else:
            logger.debug("failed to refresh apic login")
            return False

    def close(self):
        """ Close the session """
        if self.login_thread is not None:
            self.login_thread.exit()
        if self.subscription_thread is not None:
            self.subscription_thread.exit()
        if self.session is not None:
            self.session.close()

    def _send(self, method, url, data=None, timeout=None, retry=True):
        """ perform GET/POST/DELETE request to apic
            returns requests response object
        """
        if method == "GET":
            session_method = self.session.get
        elif method == "POST":
            session_method = self.session.post
        elif method == "DELETE":
            session_method = self.session.delete
        else:
            raise Exception("unsupported http method %s (expect GET, POST, or DELETE)" % method)

        # if timeout is not set then use default
        if timeout is None:
            timeout = self.default_timeout

        # prep data and certificate before request
        if data is not None:
            data = json.dumps(data, sort_keys=True)
        #cookies = self._prep_x509_header(method, url, data=data)
        cookies = {}
        # if this is a request to /appcenter we need to ensure that DevCookie is set in headers
        # due to extra security (CSCvo11989)
        headers = {}
        if re.search("^/appcenter/", url) and self.token is not None:
            headers["DevCookie"] = self.token

        url = "%s%s" % (self.api, url)
        #logger.debug("%s %s", method, url)
        # perform request method with optional retry
        resp = session_method(url, data=data, verify=self.verify_ssl, timeout=timeout, 
                    proxies=self._proxies, cookies=cookies, headers=headers)
        if resp.status_code == 403 and retry and not self._cached_mode:
            # no retry in cached mode, API call will simply fail
            logger.warn('%s, refreshing login and will try again', resp.text)
            resp = self._send_login()
            if resp.ok:
                logger.debug('retry login successful')
                # need new session_method ptr with fresh session object
                if method == "GET":
                    session_method = self.session.get
                elif method == "POST":
                    session_method = self.session.post
                elif method == "DELETE":
                    session_method = self.session.delete
                if "DevCookie" in headers:
                    headers["DevCookie"] = self.token
                resp = session_method(url, data=data, verify=self.verify_ssl, timeout=timeout, 
                        proxies=self._proxies, cookies=cookies, headers=headers)
                logger.debug('returning resp: %s', resp)
            else:
                logger.warn('retry login failed')
        return resp

class Login(threading.Thread):
    """ Login thread responsible for refreshing the APIC login before timeout """
    def __init__(self, session):
        threading.Thread.__init__(self)
        self.failure_reason = None
        self._session = session
        self._exit = False

    def exit(self):
        """ Indicate that the thread should exit """
        logger.debug("exiting login thread")
        self._exit = True
        if self._session.subscription_thread is not None:
            self._session.subscription_thread.exit()

    def wait_until_next_cycle(self):
        """ determine sleep period based on login_timeout and login_lifetime and wait required
            amount of time.
        """
        override = False
        sleep_time = self._session.login_timeout
        if self._session.graceful:
            ts = time.time()
            if ts + sleep_time > self._session.login_lifetime:
                sleep_time = self._session.login_lifetime - ts
                override = True
        if sleep_time > 0:
            logger.debug("login-thread next cycle %0.3f (graceful: %r)", sleep_time, override)
            time.sleep(sleep_time)

    def refresh(self):
        """ trigger a token refresh with login triggered on error. 
            Return boolean success.
        """
        logger.debug("login thread token refresh")
        refreshed = False
        try:
            refreshed = self._session.refresh_login(timeout=30)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            logger.warn('connection error or timeout on login refresh, triggering new login')
            self._session.login_timeout = 30
        if not refreshed:
            if self._session._send_login().ok:
                return True
            else:
                logger.warn("login attempt failed")
                self.failure_reason = "login refresh connection error or timeout"
                return False
        else:
            return True

    def restart(self):
        """ if graceful restart is enabled and subscription thread is running, then trigger the 
            graceful_resubscribe function.  Else, trigger a new login (fresh token).
            Return boolean success
        """
        logger.debug("login thread graceful restart")
        if self._session.subscription_thread is not None:
            if self._session.graceful_resubscribe():
                return True
            else:
                self.failure_reason = "graceful restart failure"
                return False
        else:
            if self._session._send_login().ok:
                return True
            else:
                self.failure_reason = "login refresh connection error or timeout"
                return False

    def run(self):
        threading.currentThread().name = "session-login"
        logger.debug("starting new login thread")
        self.failure_reason = None
        while not self._exit:
            self.wait_until_next_cycle()
            try:
                # trigger either token refresh or graceful_resubscribe
                if self._session.graceful and time.time() > self._session.login_lifetime:
                    success = self.restart()
                else:
                    success = self.refresh()
                if not success:
                    logger.warn("failed to refresh/restart login thread")
                    return self.exit()
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                logger.warn('connection error or timeout on login refresh/restart')
                return self.exit()
            except Exception as e:
                logger.debug("Traceback:\n%s", traceback.format_exc())
                logger.warn("exception occurred on login thread login: %s", e)
                return self.exit()

        return self.exit()

