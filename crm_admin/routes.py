from crm_admin import crm_admin

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
from authlib.flask.client import OAuth
from six.moves.urllib.parse import urlencode

app = Flask(__name__)
app = Flask(__name__, template_folder='templates')

oauth = OAuth(app)

load_dotenv()

auth0 = oauth.register(
    'auth0',
    client_id='JdyuTjYXfiV1JkZ7qI8ZtMG79cOGAKdz',
    client_secret='KHVCDtbG89J0xmKKbDJ7RcpCQ31lzxG4gZX22jtb1dkH3FzVvxxOv2etmXO61_ju',
    api_base_url='https://django-app1.auth0.com',
    access_token_url='https://django-app1.auth0.com/oauth/token',
    authorize_url='https://django-app1.auth0.com/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    },
)


#@crm_admin.route('/')
@crm_admin.route('/index')
def index():
    return "Hello, World!"

@crm_admin.route('/callback')
def callback_handling():
    # Handles response from token endpoint
    auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()

    # Store the user information in flask session.
    session['jwt_payload'] = userinfo
    session['profile'] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }
    return redirect('/dashboard')

@crm_admin.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri='http://127.0.0.1:5000/callback')

def requires_auth(f):
  @wraps(f)
  def decorated(*args, **kwargs):
    if 'profile' not in session:
      # Redirect to Login page here
      return redirect('/login')
    return f(*args, **kwargs)

  return decorated

@crm_admin.route('/dashboard')
#@crm_admin.route('/')
@requires_auth
def dashboard():
    return render_template('dashboard.html',
                           userinfo=session['profile'],
                           userinfo_pretty=json.dumps(session['jwt_payload'], indent=4))
@crm_admin.route('/logout')
def logout():
    # Clear session stored data
    session.clear()
    # Redirect user to logout endpoint
    params = {'returnTo': url_for('home', _external=True), 'client_id': 'JdyuTjYXfiV1JkZ7qI8ZtMG79cOGAKdz'}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))

