import os
from subprocess import check_output
import psutil
from flask import render_template, flash, redirect, url_for, request
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.urls import url_parse
from app import app, db
from app.forms import LoginForm, RegistrationForm
from app.models import User


@app.route('/')
@app.route('/index')
@login_required
def index():
    cpld = psutil.cpu_percent()
    loadmem = float(dict(psutil.virtual_memory()._asdict())['used']) / float(dict(psutil.virtual_memory()._asdict())['total'])
    posts = [('CPU temperature: ', str(float(check_output("cat /sys/class/thermal/thermal_zone0/temp",shell=True)) / 1000) + 'C'),
            ('CPU Load: ', str(cpld) + ' %'),
            ('Memory total: ', str(str(dict(psutil.virtual_memory()._asdict())['total']) + ' kB')),
            ('Memory used:  ', str(str(dict(psutil.virtual_memory()._asdict())['used']) + ' kB')),
            ('Memory free:  ', str(str(dict(psutil.virtual_memory()._asdict())['free']) + ' kB')),
            ('Memory load:  ', str(loadmem*100) + ' %' )]
    return render_template('index.html', title='Home', posts=posts)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        ipad = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        os.system('iptables -F')
        os.system('iptables -X')
        os.system('iptables -t nat -F')
        os.system('iptables -t nat -X')
        os.system('iptables -t mangle -F')
        os.system('iptables -t mangle -X')
        os.system('iptables -P INPUT ACCEPT')
        os.system('iptables -P FORWARD ACCEPT')
        os.system('iptables -P OUTPUT ACCEPT')
        #os.system(f'sudo iptables -t filter -A INPUT -p tcp -s {ipad} --dport 80 -j ACCEPT')#  sudo iptables -t filter -A INPUT -p tcp --dport 80 -j ACCEPT
        os.system('sudo iptables-save')#  sudo iptables-save
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)


@app.route('/logout')
def logout():
    ipaddr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    logout_user()
    #os.system(f'sudo iptables -D INPUT -i eth1 -p tcp -s {ipaddr} --dport 80 -j DROP')
    # sudo iptables -A INPUT -i eth1 -p tcp -s 1.2.3.4 --dport 80 -j DROP
    # sudo iptables-save
    os.system('sudo iptables -A INPUT -p tcp --dport 80 -j DROP')
    os.system('sudo iptables-save')
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)
