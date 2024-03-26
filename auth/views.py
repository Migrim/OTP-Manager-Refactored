from . import auth_bp
from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required
from .forms import LoginForm
from .models import User

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        if form.username.data == 'admin' and form.password.data == 'password':  
            user = User(id=1, username=form.username.data, password=form.password.data)
            if user.check_password(form.password.data):
                login_user(user, remember=True)
                return redirect(url_for('main.home')) 
            else:
                flash('Invalid username or password.')
        else:
            flash('Invalid username or password.')
    return render_template('login.html', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('auth.login'))
