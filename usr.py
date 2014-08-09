#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-08-01
@author: shell.xu
'''
import os, sys, logging
from email.mime.text import MIMEText
import bottle, cves
from bottle import route, template, request, response, redirect
from db import *

logger = logging.getLogger('users')
app = bottle.default_app()
sess = app.config['db.session']

def sendmail(username, title, body):
    cfg = app.config['cfg']
    sender = cfg.get('email', 'mail')
    with cves.with_emailconfig(cfg, False) as srv:
        msg = MIMEText(body)
        msg['Subject'] = title
        msg['From'] = sender
        msg['To'] = username
        srv.sendmail(sender, msg['To'].split(','), msg.as_string())

@route('/login')
def _login():
    return template('login.html')

@route('/login', method='POST')
def _login():
    session = request.environ.get('beaker.session')
    username = request.forms.get('username')
    password = request.forms.get('password')
    retrieve = request.forms.get('retrieve')

    if retrieve:
        user = sess.query(Users).filter_by(username=username).scalar()
        if not user: return 'failed.'

        r = user.uptoken()
        sess.commit()
        if not r: return 'too fast'

        cfg = app.config['cfg']
        url = '%s/retrieve?token=%s' % (cfg.get('main', 'baseurl'), user.token)
        body = 'Retrieve password for cves, here is your token: %s. Use it in an hour.\n click: %s.' % (
            user.token, url)
        sendmail(username, 'retrieve password', body)
        return bottle.redirect('.')

    logger.debug("login with %s" % username)
    user = sess.query(Users).filter_by(username=username).scalar()
    if not user or not check_pass(password, str(user.passwd)):
        errmsg = "login failed %s." % username
        logger.info(errmsg)
        return template('login.html', errmsg=errmsg)
    logger.info("login successed %s." % username)
    session['username'] = username
    return bottle.redirect(request.query.next or '.')

def chklogin(perm=None, next=None):
    def receiver(func):
        def _inner(*p, **kw):
            session = request.environ.get('beaker.session')
            if 'username' not in session:
                return redirect('login?next=%s' % (next or request.path))
            return func(session, *p, **kw)
        return _inner
    return receiver

@route('/logout')
@chklogin(next='login')
def _logout(session):
    if 'username' in session:
        del session['username']
    return bottle.redirect(request.query.next or '.')

@route('/invite')
@chklogin()
def _invite(session):
    return template('inv.html')

@route('/invite', method='POST')
@chklogin()
def _invite(session):
    username = request.forms.get('username')
    user = sess.query(Users).filter_by(username=username).scalar()
    if user: return 'failed.'

    self = sess.query(Users).filter_by(username=session['username']).scalar()
    if not self: return 'failed.'

    user = Users(username=username, passwd=crypto_pass(gentoken(30)), inviter=session['username'])
    sess.add(user)

    r = user.uptoken()
    sess.commit()
    if not r: return 'too fast'

    cfg = app.config['cfg']
    url = '%s/retrieve?token=%s' % (cfg.get('main', 'baseurl'), user.token)
    body = 'You have been invited for using cves, here is your token: %s. Use it in an hour.\n click: %s.' % (
        user.token, url)
    sendmail(username, 'cves invite from %s' % self.username, body)
    return bottle.redirect('.')

@route('/retrieve')
def _retrieve():
    token = request.query.get('token')
    return template('retrieve.html', token=token)

@route('/retrieve', method='POST')
def _retrieve():
    token = request.forms.get('token')
    password = request.forms.get('password')
    if not password: return 'failed.'

    user = sess.query(Users).filter_by(token=token).scalar()
    if not user: return 'failed.'
    logging.info('retrieve password for %s.' % user.username)
    user.renew_pass(token, password)
    sess.commit()
    return bottle.redirect('login')
