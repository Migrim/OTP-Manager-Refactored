from . import main_bp
from flask import render_template
from database import get_db_connection
import pyotp
from flask import jsonify
from flask import make_response

@main_bp.route('/current-otps')
def current_otps():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name, email, secret FROM otp_secrets")
    otps = cursor.fetchall()
    conn.close()

    otps_with_current_otp = []
    for otp in otps:
        otp_dict = dict(otp)
        otp_secret = otp_dict['secret']
        totp = pyotp.TOTP(otp_secret)
        otp_dict['current_otp'] = totp.now()
        otps_with_current_otp.append(otp_dict)

    response = make_response(jsonify({'otps': [{'name': otp['name'], 'current_otp': otp['current_otp']} for otp in otps_with_current_otp]}))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@main_bp.route('/home')
def home():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT name, email, secret FROM otp_secrets")
    otps = cursor.fetchall()
    conn.close()

    # Convert each Row object to a dictionary and add the current OTP
    otps_with_current_otp = []
    for otp in otps:
        # Convert sqlite3.Row to a dictionary
        otp_dict = dict(otp)
        otp_secret = otp_dict['secret']
        totp = pyotp.TOTP(otp_secret)
        otp_dict['current_otp'] = totp.now()  # Adds the current OTP
        otps_with_current_otp.append(otp_dict)

    return render_template('home.html', otps=otps_with_current_otp)
