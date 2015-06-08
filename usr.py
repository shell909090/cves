#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-08-01
@author: shell.xu
'''
import logging
from os import path
from email.mime.text import MIMEText
import bottle, utils, db
from bottle import route, post, template, request, redirect

app = bottle.default_app()
sess = app.config['db.session']
basepath = app.config['basepath']

def sendmail(username, title, body):
    cfg = app.config['cfg']
    sender = cfg.get('email', 'mail')
    dryrun = cfg.get('main', 'dryrun')
    with utils.with_emailconfig(cfg, dryrun) as srv:
        msg = MIMEText(body)
        msg['Subject'] = title
        msg['From'] = sender
        msg['To'] = username
        srv.sendmail(sender, msg['To'].split(','), msg.as_string())

@route(path.join(basepath, 'login'))
def _login():
    return template('login.html')

@post(path.join(basepath, 'login'))
def _login_post():
    username = request.forms.get('username')
    password = request.forms.get('password')

    if request.forms.get('register'): return register(username)
    if request.forms.get('retrieve'): return retrieve(username)

    logging.debug("login with {}".format(username))
    user = sess.query(db.Users).filter_by(username=username).scalar()
    if not user or not db.check_pass(password, str(user.passwd)):
        errmsg = "login failed %s." % username
        logging.info(errmsg)
        return template('login.html', errmsg=errmsg)
    logging.info("login successed {}.".format(username))

    session = request.environ.get('beaker.session')
    session['username'] = username
    return redirect(request.query.next or app.config.get('basepath'))

def chklogin(nexturl=None):
    def receiver(func):
        def _inner(*p, **kw):
            session = request.environ.get('beaker.session')
            if 'username' not in session:
                return redirect('%s/login?next=%s' % (
                        app.config.get('basepath'), nexturl or request.path))
            return func(session, *p, **kw)
        return _inner
    return receiver

@route(path.join(basepath, 'logout'))
@chklogin(nexturl='login')
def _logout(session):
    if 'username' in session:
        del session['username']
    return redirect(request.query.next or '.')

def register(username):
    cfg = app.config['cfg']
    if cfg.has_option('main', 'auth') and cfg.get('main', 'auth') != 'db':
        return 'can\'t register under non-db auth mode'

    user = sess.query(db.Users).filter_by(username=username).scalar()
    if user: return 'failed.'

    user = db.Users(username=username, passwd=db.crypto_pass(db.gentoken(30)))
    sess.add(user)
    # FIXME: 是否会招致token发不出去而卡住？
    if not user.uptoken(): return 'too fast'
    sess.commit()

    cfg = app.config['cfg']
    url = '%s/retrieve?token=%s' % (cfg.get('web', 'baseurl'), user.token)
    body = 'You have been invited for using cves, here is your token: %s. Use it in an hour.\n click: %s.' % (
        user.token, url)
    sendmail(username, 'cves register mail', body)
    return redirect('.')

def retrieve(username):
    cfg = app.config['cfg']
    if cfg.has_option('main', 'auth') and cfg.get('main', 'auth') != 'db':
        return 'can\'t retrieve under non-db auth mode'

    user = sess.query(db.Users).filter_by(username=username).scalar()
    if not user: return 'failed.'

    if not user.uptoken(): return 'too fast'
    sess.commit()

    cfg = app.config['cfg']
    url = '%s/retrieve?token=%s' % (cfg.get('web', 'baseurl'), user.token)
    body = 'Retrieve password for cves, here is your token: %s. Use it in an hour.\n click: %s.' % (
        user.token, url)
    sendmail(username, 'retrieve password', body)
    return redirect('.')

# FIXME: retrieve的时候是否最好跟用户名
@route(path.join(basepath, 'retrieve'))
def _retrieve():
    token = request.query.get('token')
    return template('retrieve.html', token=token)

@post(path.join(basepath, 'retrieve'))
def _retrieve_post():
    token = request.forms.get('token')
    password = request.forms.get('password')
    if not password: return 'failed.'

    user = sess.query(db.Users).filter_by(token=token).scalar()
    if not user: return 'failed.'
    logging.info('retrieve password for {}.'.format(user.username))
    user.renew_pass(token, password)
    sess.commit()
    return redirect('login')

@route(path.join(basepath, 'setcc'))
@chklogin()
def _setcc(session):
    user = sess.query(db.Users).filter_by(username=session['username']).scalar()
    if not user: return 'user in session not exist'
    return template('setcc.html', data=user.cclist)

@post(path.join(basepath, 'setcc'))
@chklogin()
def _setcc_post(session):
    user = sess.query(db.Users).filter_by(username=session['username']).scalar()
    if not user: return 'user in session not exist'

    user.cclist = request.forms.get('data')
    sess.commit()
    return redirect('.')
