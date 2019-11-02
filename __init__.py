from flask import Flask

crm_admin = Flask(__name__)

from app import routes
crm_admin.secret_key = 'the random string'
