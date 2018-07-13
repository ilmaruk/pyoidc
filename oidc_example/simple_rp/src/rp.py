import argparse
import os

import cherrypy
import yaml

import jwkest.jwk

from oic.oauth2 import rndstr
from oic.oic import Client
from oic.oic.message import AuthorizationResponse, RegistrationResponse

__author__ = 'regu0004'

_MAGIK_BASE = 'http://localhost:7301/sso'


class OIDCExampleRP(object):
    def __init__(self, client_metadata, behaviour, client_id):
        self.client_metadata = client_metadata
        self.behaviour = behaviour

        self.redirect_uri = self.client_metadata["redirect_uris"][0]
        self.response_type = self.client_metadata["response_types"][0]
        self.behaviour = self.behaviour

        self.client_id = client_id

    def register_with_dynamic_provider(self, session, uid):
        issuer_url = session["client"].wf.discovery_query(uid)
        provider_info = session["client"].provider_config(issuer_url)
        session["client"].register(provider_info["registration_endpoint"],
                                   **self.client_metadata)

    def register_statically(self, session):
        info = {"client_id": self.client_id, "client_secret": "abcdefghijklmnop"}
        client_reg = RegistrationResponse(**info)
        session["client"].store_registration_info(client_reg)

        session["client"].issuer = _MAGIK_BASE
        session["client"].authorization_endpoint = "%s/authorize" % _MAGIK_BASE
        session["client"].token_endpoint = "%s/token" % _MAGIK_BASE
        session["client"].end_session_endpoint = "%s/logout" % _MAGIK_BASE

    def make_authentication_request(self, session):
        session["state"] = rndstr()
        session["nonce"] = rndstr()
        request_args = {
            "response_type": self.response_type,
            "state": session["state"],
            "nonce": session["nonce"],
            "redirect_uri": self.redirect_uri,
            "prompt": "login",
        }

        request_args.update(self.behaviour)

        auth_req = session["client"].construct_AuthorizationRequest(
            request_args=request_args)
        login_url = auth_req.request(session["client"].authorization_endpoint)

        raise cherrypy.HTTPRedirect(login_url, 303)

    def parse_authentication_response(self, session, query_string):
        auth_response = session["client"].parse_response(AuthorizationResponse,
                                                         info=query_string,
                                                         sformat="urlencoded")

        if auth_response["state"] != session["state"]:
            raise "The OIDC state does not match."

        if "id_token" in auth_response and \
                        auth_response["id_token"]["nonce"] != session["nonce"]:
            raise "The OIDC nonce does not match."

        return auth_response

    def make_token_request(self, session, auth_code):
        args = {
            "code": auth_code,
            "redirect_uri": self.redirect_uri,
            "client_id": session["client"].client_id,
            "client_secret": session["client"].client_secret
        }

        key = jwkest.jwk.rsa_load('../magik.key.pub')
        rsa_key = jwkest.jwk.RSAKey(use='dec', alg='RS256', key=key)

        token_response = session["client"].do_access_token_request(
            scope="openid",
            state=session["state"],
            request_args=args,
            key=[rsa_key]
        )

        return token_response

    def make_userinfo_request(self, session, access_token):
        userinfo_response = session["client"].do_user_info_request(
            access_token=access_token)
        return userinfo_response

    def make_logout_request(self, session):
        response = session["client"].do_end_session_request(scope='openid', state=rndstr())
        pass


class RPServer(object):
    def __init__(self, client_metadata, behaviour, verify_ssl, client_id):
        self.rp = OIDCExampleRP(client_metadata, behaviour, client_id)
        self.verify_ssl = verify_ssl
        self.client_id = client_id

    @cherrypy.expose
    def index(self):
        html = self._load_HTML_page_from_file("htdocs/index.html")
        return html.format(self.client_id, self.client_id)

    @cherrypy.expose
    def authenticate(self):
        cherrypy.session["client"] = Client(verify_ssl=self.verify_ssl)

        # static registration
        self.rp.register_statically(cherrypy.session)

        # auth req
        redirect_url = self.rp.make_authentication_request(cherrypy.session)
        raise cherrypy.HTTPRedirect(redirect_url, 303)

    @cherrypy.expose
    def repost_fragment(self, **kwargs):
        response = self.rp.parse_authentication_response(cherrypy.session,
                                                         kwargs["url_fragment"])

        html_page = self._load_HTML_page_from_file("htdocs/success_page.html")

        # Support for hybrid flow
        authz_code = None
        try:
            authz_code = response["code"]
        except KeyError:
            pass

        access_token = None
        try:
            access_token = response["access_token"]
            userinfo = self.rp.make_userinfo_request(cherrypy.session,
                                                     access_token)
        except KeyError:
            pass
        return html_page.format(authz_code, access_token,
                                response["id_token"], userinfo)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def code_flow(self, **kwargs):
        if "error" in kwargs:
            raise cherrypy.HTTPError(500, "{}: {}".format(kwargs["error"],
                                                          kwargs[
                                                              "error_description"]))

        qs = cherrypy.request.query_string
        auth_response = self.rp.parse_authentication_response(cherrypy.session,
                                                              qs)
        auth_code = auth_response["code"]
        token_response = self.rp.make_token_request(cherrypy.session, auth_code)

        return token_response["id_token"].to_dict()

    @cherrypy.expose
    def implicit_hybrid_flow(self, **kwargs):
        return self._load_HTML_page_from_file("htdocs/repost_fragment.html")

    def _load_HTML_page_from_file(self, path):
        if not path.startswith("/"): # relative path
            # prepend the root package dir
            path = os.path.join(os.path.dirname(__file__), path)

        with open(path, "r") as f:
            return f.read()

    @cherrypy.expose
    def logout(self):
        self.rp.make_logout_request(cherrypy.session)
        raise cherrypy.HTTPRedirect('/')


def main():
    parser = argparse.ArgumentParser(description='Example OIDC Client.')
    parser.add_argument("-p", "--port", default=80, type=int)
    parser.add_argument("-b", "--base", default="https://localhost", type=str)
    parser.add_argument("-c", "--client_id", type=str, required=True)
    parser.add_argument("settings")
    args = parser.parse_args()

    with open(args.settings, "r") as f:
        settings = yaml.load(f)

    baseurl = args.base.rstrip("/")  # strip trailing slash if it exists
    registration_info = settings["registration_info"]
    # patch redirect_uris with proper base url
    registration_info["redirect_uris"] = [url.format(base=baseurl) for url in
                                          registration_info["redirect_uris"]]

    rp_server = RPServer(registration_info, settings["behaviour"],
                         settings["server"]["verify_ssl"], args.client_id)

    # Mount the WSGI callable object (app) on the root directory
    cherrypy.tree.mount(rp_server, "/")

    # Set the configuration of the web server
    cherrypy.config.update({
        'tools.sessions.on': True,
        'server.socket_port': args.port,
        'server.socket_host': '0.0.0.0',
        'tools.sessions.name': "%s-session" % args.client_id,
    })

    if baseurl.startswith("https://"):
        cherrypy.config.update({
            'server.ssl_module': 'builtin',
            'server.ssl_certificate': settings["server"]["cert"],
            'server.ssl_private_key': settings["server"]["key"],
            'server.ssl_certificate_chain': settings["server"]["cert_chain"],
        })

    # Start the CherryPy WSGI web server
    cherrypy.engine.start()
    cherrypy.engine.block()


if __name__ == "__main__":
    main()
