"""Python Flask WebApp Auth0 integration example
"""
from functools import wraps
import json
from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
#from authlib.flask.client import OAuth
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

import constants
#from auth0.v3.authentication import GetToken

#from auth0.v3.management import Auth0

import json
from six.moves.urllib.request import urlopen
from functools import wraps

from flask import Flask, request, jsonify, _request_ctx_stack
from flask_cors import cross_origin
from jose import jwt

from flask import Response
import pdb
import requests

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

#AUTH0_CALLBACK_URL = env.get(constants.AUTH0_CALLBACK_URL)
#request.
#AUTH0_CALLBACK_URL = ''
AUTH0_CLIENT_ID = env.get(constants.AUTH0_CLIENT_ID)
AUTH0_CLIENT_SECRET = env.get(constants.AUTH0_CLIENT_SECRET)
AUTH0_DOMAIN = env.get(constants.AUTH0_DOMAIN)
AUTH0_BASE_URL = 'https://' + AUTH0_DOMAIN
AUTH0_AUDIENCE = env.get(constants.AUTH0_AUDIENCE)

ALGORITHMS = ["RS256"]
print("aud: "+AUTH0_AUDIENCE)

ACCESS_TOKEN = ""
ID_TOKEN = ""

guser_perms=[]

app = Flask(__name__, static_url_path='/public', static_folder='./public')
app.secret_key = constants.SECRET_KEY
app.debug = True


@app.errorhandler(Exception)
def handle_auth_error(ex):
    response = jsonify(message=str(ex))
    response.status_code = (ex.code if isinstance(ex, HTTPException) else 500)
    return response


oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    api_base_url=AUTH0_BASE_URL,
    access_token_url=AUTH0_BASE_URL + '/oauth/token',
    authorize_url=AUTH0_BASE_URL + '/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    },
)
#conn = http.client.HTTPSConnection("")

#conn.request("POST", "/django-app1.auth0.com/dbconnections/signup", payload, headers)
'''
get_token = GetToken(AUTH0_DOMAIN)
token = get_token.client_credentials(AUTH0_CLIENT_ID,
AUTH0_CLIENT_SECRET, 'https://{}/api/v2/'.format(AUTH0_DOMAIN))
'''

#_auth0 = Auth0(AUTH0_DOMAIN, mgmt_api_token)
#print(_auth0.connections.all())

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if constants.PROFILE_KEY not in session:
            return redirect('/login')
        return f(*args, **kwargs)

    return decorated


# Controllers API
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

def get_token_auth_header():
    headers = {'content-type': 'Authorization'}
    #headers = {"Access-Control-Allow-Origin", "*"}

    auth = request.headers.get('Authorization', None)
    #auth = request.headers.get("Authorization", None)
    if not auth:
        raise AuthError({"code": "authorization_header_missing",
                        "description":
                            "Authorization header is expected"}, 401)

    parts = auth.split()

    if parts[0].lower() != "bearer":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Authorization header must start with"
                            " Bearer"}, 401)
    elif len(parts) == 1:
        raise AuthError({"code": "invalid_header",
                        "description": "Token not found"}, 401)
    elif len(parts) > 2:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Authorization header must be"
                            " Bearer token"}, 401)

    token = parts[1]
    #print(token)
    return token

def requires_authorize(f):
    """Determines if the Access Token is valid
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        print("under authorize")
        token = get_token_auth_header()
        jsonurl = urlopen("https://"+AUTH0_DOMAIN+"/.well-known/jwks.json")
        jwks = json.loads(jsonurl.read())
        unverified_header = jwt.get_unverified_header(token)
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        if rsa_key:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=AUTH0_AUDIENCE,
                    issuer="https://"+AUTH0_DOMAIN+"/"
                )
            except jwt.ExpiredSignatureError:
                raise AuthError({"code": "token_expired",
                                "description": "token is expired"}, 401)
            except jwt.JWTClaimsError:
                raise AuthError({"code": "invalid_claims",
                                "description":
                                    "incorrect claims,"
                                    "please check the audience and issuer"}, 401)
            except Exception:
                raise AuthError({"code": "invalid_header",
                                "description":
                                    "Unable to parse authentication"
                                    " token."}, 401)

            _request_ctx_stack.top.current_user = payload
            return f(*args, **kwargs)
        raise AuthError({"code": "invalid_header",
                        "description": "Unable to find appropriate key"}, 401)
        print("ALL DONEE")
    return decorated

def requires_scope(required_scope):
    token = get_token_auth_header()
    unverified_claims = jwt.get_unverified_claims(token)
    guser_perms = unverified_claims.get("permissions")
    for u in guser_perms:
        print("permisions "+u)
    return Response(json.dumps(guser_perms), mimetype='application/json')

@app.route('/login/callback')
def callback_handling():
    token = auth0.authorize_access_token()
    global ACCESS_TOKEN
    global ID_TOKEN
    ACCESS_TOKEN = token.get('access_token')
    ID_TOKEN = token.get('id_token')
    host_str = request.host_url
    URL_PATH = host_str+'login/sample/home'
    header = 'Bearer '+ACCESS_TOKEN
    HEADERS = {
        'Authorization': header
    }
    R = requests.get(URL_PATH, headers=HEADERS)
    resp = auth0.get('userinfo')
    userinfo = resp.json()

    session[constants.JWT_PAYLOAD] = userinfo
    session[constants.PROFILE_KEY] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }
    host_str = request.host
    return redirect('https://'+host_str+'/login/dashboard')

@app.route('/login')
def login():
    host_str = request.host
    red_uri = "https://"+host_str+"/login/callback"
    print(red_uri)
    return auth0.authorize_redirect(redirect_uri=red_uri, audience=AUTH0_AUDIENCE)

@app.route('/login/logout')
def logout():
    session.clear()
    params = {'returnTo': url_for('login', _external=True), 'client_id': AUTH0_CLIENT_ID}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))


@app.route('/login/dashboard')
@requires_auth
def dashboard():
    return render_template('dashboard.html',
                           userinfo=session[constants.PROFILE_KEY],
                           userinfo_pretty=json.dumps(session[constants.JWT_PAYLOAD], indent=4))


@app.route("/login/sample/home", methods=["GET", "POST", "PUT"])
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
@requires_authorize
def private_scoped():
    return requires_scope("read:home")

@app.route("/login/twitter")
def login_twitter():
		host_str = request.host 
		return auth0.authorize_redirect(redirect_uri="https://"+host_str+"/login/twitter/callback", audience=AUTH0_AUDIENCE)

@app.route("/login/twitter/callback")
@requires_auth
def check_twitter_scope():
    print('inside check')
    token = auth0.authorize_access_token()
    print(token)
    global ACCESS_TOKEN
    global ID_TOKEN
    global guser_perms
    ACCESS_TOKEN = token.get('access_token')
    ID_TOKEN = token.get('id_token')
    host_str = request.host_url
    URL_PATH = host_str+'login/sample/home'
    header = 'Bearer '+ACCESS_TOKEN
    print('header: '+header)
    HEADERS = {
        'Authorization': header
    }
    R = requests.get(URL_PATH, headers=HEADERS)
    ls = R.text
    print("type1: "+str(type(ls)))
    res = ls.strip('][').split(', ')
    print(res)
    host_str = request.host
    for p in res:
        print(str(p))
        if (p.find("read:twitter") != -1):
            return redirect("https://"+host_str+'/twitter')
    return render_template('403.html')

@app.route("/login/view_tickets")
def view_ticket():
		host_str = request.host
		return auth0.authorize_redirect(redirect_uri="https://"+host_str+"/login/view_ticket/callback", audience=AUTH0_AUDIENCE)

@app.route("/login/view_ticket/callback")
@requires_auth
def check_ticket_scope():
    print('inside check')
    token = auth0.authorize_access_token()
    print(token)
    global ACCESS_TOKEN
    global ID_TOKEN
    global guser_perms
    ACCESS_TOKEN = token.get('access_token')
    ID_TOKEN = token.get('id_token')
    host_str = request.host_url
    URL_PATH = host_str+'login/sample/home'
    header = 'Bearer '+ACCESS_TOKEN
    print('header: '+header)
    HEADERS = {
        'Authorization': header
    }
    R = requests.get(URL_PATH, headers=HEADERS)
    ls = R.text
    print("type1: "+str(type(ls)))
    #ur = url_for('ticket/getperms')
    res = ls.strip('][').split(', ')
    host_str = request.host_url
    resp = requests.post(host_str+'ticket/getperms', json={"read":"ticket"})
    if (resp.ok):
        print('Success !!!')
    print(res)
    host_str = request.host
    for p in res:
        print(str(p))
        if (p.find("read:ticket") != -1):
            return redirect("https://"+host_str+'/ticket/view_tickets')
    return render_template('403.html')

@app.route("/login/file_issue")
def file_ticket():
		host_str = request.host
		return auth0.authorize_redirect(redirect_uri="https://"+host_str+"/login/file_ticket/callback", audience=AUTH0_AUDIENCE)

@app.route("/login/file_ticket/callback")
@requires_auth
def check_file_ticket_scope():
    print('inside check')
    token = auth0.authorize_access_token()
    print(token)
    global ACCESS_TOKEN
    global ID_TOKEN
    global guser_perms
    ACCESS_TOKEN = token.get('access_token')
    ID_TOKEN = token.get('id_token')
    host_str = request.host_url
    URL_PATH = host_str+'login/sample/home'
    header = 'Bearer '+ACCESS_TOKEN
    print('header: '+header)
    HEADERS = {
        'Authorization': header
    }
    R = requests.get(URL_PATH, headers=HEADERS)
    ls = R.text
    print("type1: "+str(type(ls)))
    res = ls.strip('][').split(', ')
    print(res)
    host_str = request.host
    for p in res:
        print(str(p))
        if (p.find("create:ticket") != -1):
            return redirect("https://"+host_str+'/ticket/file_issue')
    return render_template('403.html')

@app.route("/login/invoice")
def login_invoice():
		host_str = request.host
		return auth0.authorize_redirect(redirect_uri="https://"+host_str+"/login/invoice/callback", audience=AUTH0_AUDIENCE)

@app.route("/login/invoice/callback")
@requires_auth
def check_invoice_scope():
    print('inside check')
    token = auth0.authorize_access_token()
    print(token)
    global ACCESS_TOKEN
    global ID_TOKEN
    global guser_perms
    ACCESS_TOKEN = token.get('access_token')
    ID_TOKEN = token.get('id_token')
    host_str = request.host_url
    URL_PATH = host_str+'login/sample/home'
    header = 'Bearer '+ACCESS_TOKEN
    print('header: '+header)
    HEADERS = {
        'Authorization': header
    }
    R = requests.get(URL_PATH, headers=HEADERS)
    ls = R.text
    print("type1: "+str(type(ls)))
    res = ls.strip('][').split(', ')
    print(res)
    host_str = request.host
    for p in res:
        print(str(p))
        if (p.find("read:invoice") != -1):
            return redirect("https://"+host_str+'/invoice')
    return render_template('403.html')

@app.route("/login/customers")
def customer_ticket():
		host_str = request.host
		return auth0.authorize_redirect(redirect_uri="https://"+host_str+"/login/customers/callback", audience=AUTH0_AUDIENCE)

@app.route("/login/customers/callback")
@requires_auth
def check_customers_scope():
    print('inside check')
    token = auth0.authorize_access_token()
    print(token)
    global ACCESS_TOKEN
    global ID_TOKEN
    global guser_perms
    ACCESS_TOKEN = token.get('access_token')
    ID_TOKEN = token.get('id_token')
    host_str = request.host_url
    URL_PATH = host_str+'login/sample/home'
    header = 'Bearer '+ACCESS_TOKEN
    print('header: '+header)
    HEADERS = {
        'Authorization': header
    }
    R = requests.get(URL_PATH, headers=HEADERS)
    ls = R.text
    print("type1: "+str(type(ls)))
    res = ls.strip('][').split(', ')
    print(res)
    host_str = request.host
    for p in res:
        print(str(p))
        if (p.find("read:customers") != -1):
            return redirect("https://"+host_str+'/customers/')
    return render_template('403.html')

if __name__ == "__main__":
    #app.run(host='0.0.0.0', port=env.get('PORT', 3000))
    app.run()
