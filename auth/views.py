from . import auth_bp
from flask import render_template, redirect, url_for

@auth_bp.route('/login')
def login():
    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    # Logic to log out the user.
    return redirect(url_for('main.index'))
