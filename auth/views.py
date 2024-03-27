from . import auth_bp
from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required
from .forms import LoginForm
from .models import User
from database import get_db_connection 

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        conn = get_db_connection()
        user_row = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user_row and user_row['password'] == password:  

            user = User(id=user_row['id'], username=user_row['username'], password=user_row['password'])
            return redirect(url_for('main.home'))  
        else:
            flash('Invalid username or password.')
    return render_template('login.html', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    print("Logging out user")  
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('auth.login'))