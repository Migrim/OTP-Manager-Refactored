from flask import (
    Flask, render_template, request, redirect, url_for, flash, session,
    make_response, jsonify, send_file, Blueprint
)
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import (
    StringField, SubmitField, RadioField, HiddenField, IntegerField, SelectField,
    PasswordField
)
from wtforms.validators import (
    DataRequired, Length, InputRequired, NumberRange, Email, Optional
)
from pyotp import totp, hotp
from flask_session import Session
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
from flask_login import LoginManager, current_user, login_user, UserMixin
from flask_cors import CORS
from collections import defaultdict
from subprocess import Popen, PIPE
from markupsafe import Markup
from threading import Lock
import pyotp
import ntplib
import time
import requests
import bcrypt
import shutil
import os
import subprocess
import sqlite3
import logging
import re
import uuid
import signal
import json
import sys

from instance.database import db_blueprint, init_db

#End of declaring the Imports

logging.basicConfig(filename='MV.log', level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
my_logger = logging.getLogger('MV_logger')

app = Flask(__name__)
bcrypt = Bcrypt(app)
CORS(app)
start_time = datetime.now()

# Please enter your secure Secret key here!
app.config['SECRET_KEY'] = 'enter-your-secret-key!'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
Session(app)
Bootstrap(app)

app.register_blueprint(db_blueprint, url_prefix='/db')

login_manager = LoginManager()
login_manager.init_app(app)

app.logger.handlers = []
app.logger.propagate = False

werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.disabled = True

handler = logging.FileHandler('MV.log')
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

formatter = logging.Formatter('%(asctime)s %(message)s')
handler.setFormatter(formatter)

broadcast_message = None
slow_requests_counter = 0
flash_messages = []

@app.route('/')
def hello_world():
    return 'Hello, World!'

def log_and_print(message, level='info'):
    print(message)
    if level == 'error':
        my_logger.error(message)
    else:
        my_logger.info(message)

if __name__ == '__main__':
    port = 3000
    log_and_print("Checking database...")
    try:
        init_db()
        log_and_print("Database check complete.")
    except Exception as e:
        log_and_print(f"Failed to check database: {e}", 'error')

    log_and_print("Starting Flask application...")
    try:
        app.run(debug=True, port=port, host='0.0.0.0')
    except Exception as e:
        log_and_print(f"Failed to start Flask application: {e}", 'error')
