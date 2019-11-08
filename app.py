#from app import app

from functools import wraps
import json
from os import environ as env
from werkzeug.exceptions import HTTPException
import config

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask_httpauth import HTTPBasicAuth
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO

from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.flask.client import OAuth
from six.moves.urllib.parse import urlencode

app = Flask(__name__)
app = Flask(__name__, template_folder='templates')

'''config_name = os.environ.get('FLASK_CONFIG', 'dev')
app.config.from_object(getattr(config, config_name.title() + 'Config'))

db = SQLAlchemy(app)
migrate = Migrate(app, db)
basic_auth = HTTPBasicAuth()

message_queue = 'redis://' + os.environ['REDIS'] if 'REDIS' in os.environ \
    else None
if message_queue:
    socketio = SocketIO(message_queue=message_queue)
else:
    socketio = None
'''
app.secret_key = "the random string"

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
@app.route('/login/index')
def index():
    return "Hello, World!"

@app.route('/login/callback')
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
    return redirect('/login/dashboard')

@app.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri='http://192.168.33.15/login/callback')

def requires_auth(f):
  @wraps(f)
  def decorated(*args, **kwargs):
    if 'profile' not in session:
      # Redirect to Login page here
      return redirect('/login')
    return f(*args, **kwargs)

  return decorated

@app.route('/login/dashboard')
#@crm_admin.route('/')
@requires_auth
def dashboard():
    return render_template('dashboard.html',
                           userinfo=session['profile'],
                           userinfo_pretty=json.dumps(session['jwt_payload'], indent=4))
@app.route('/login/logout')
def logout():
    # Clear session stored data
    session.clear()
    # Redirect user to logout endpoint
    params = {'returnTo': url_for('dashboard', _external=True), 'client_id': 'JdyuTjYXfiV1JkZ7qI8ZtMG79cOGAKdz'}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))


if __name__ == "__main__":
    app.debug = True
    app.run()
