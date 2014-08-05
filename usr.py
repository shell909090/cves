#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-08-01
@author: shell.xu
'''
import os, sys, logging
import bottle, cves
from bottle import route, template, request, response, redirect
from db import *

logger = logging.getLogger('users')
app = bottle.default_app()
sess = app.config['db.session']

@route('/login')
def _login():
    return template('login.html')

# @route('/retrieve', method='POST')
# def _retrieve():
#     username = request.forms.get('username')
#     user = sess.query(Users).filter_by(username=username).scalar()
#     if not user: return 'failed.'
#     if user.
#     logger.debug("retrieve with %s" % username)

@route('/login', method='POST')
def _login():
    session = request.environ.get('beaker.session')
    username = request.forms.get('username')
    password = request.forms.get('password')
    retrieve = request.forms.get('retrieve')

    # TODO:
    if retrieve:
        return bottle.redirect('/')

    logger.debug("login with %s" % username)
    user = sess.query(Users).filter_by(username=username).scalar()
    if not user or not check_pass(password, user.passwd):
        errmsg = "login failed %s." % username
        logger.info(errmsg)
        return template('login.html', errmsg=errmsg)
    logger.info("login successed %s." % username)
    session['username'] = username
    return bottle.redirect(request.query.next or '/')

def chklogin(perm=None, next=None):
    def receiver(func):
        def _inner(*p, **kw):
            session = request.environ.get('beaker.session')
            if 'username' not in session:
                return redirect('/login?next=%s' % (next or request.path))
            return func(session, *p, **kw)
        return _inner
    return receiver

@route('/logout')
@chklogin(next='/')
def _logout(session):
    if 'username' in session:
        del session['username']
    return bottle.redirect(request.query.next or '/')

@route('/invite')
@chklogin(next='/')
def _invite(session):
    return template('inv.html')

@route('/invite', method='POST')
@chklogin(next='/')
def _invite(session):
    username = request.forms.get('username')
    user = sess.query(Users).filter_by(username=username).scalar()
    if user: return 'failed.'

    self = sess.query(Users).filter_by(username=session['username']).scalar()
    if not self: return 'failed.'

    u = Users(username=args[0], passwd=crypto_pass(username), inviter=self)
    sess.add(u)
    r = u.uptoken()
    sess.commit()
    if not r: return 'too fast'

    cfg = app.config['cfg']
    sender = cfg.get('email', 'mail')
    url = 'http://%s:%s/retrieve?token=%s' % (
        cfg.get('main', 'addr'), cfg.get('main', 'port'), u.token)
    body = 'You have been invited for using cves, here is your token: %s. Use it in an hour.\n click: %s.' % (
        u.token, url)
    with cves.with_emailconfig(cfg, False) as srv:
        msg = MIMEText(body)
        msg['Subject'] = 'cves invite from %s' % self.username
        msg['From'] = sender
        msg['To'] = username
        srv.sendmail(sender, msg['To'].split(','), msg.as_string())

@route('/retrieve')
def _retrieve():
    token = request.query.get('token')
    return template('retrieve.html', token=token)

@route('/retrieve', method='POST')
def _retrieve():
    token = request.forms.get('token')
    password = request.forms.get('password')
    if not password: return 'failed.'

    u = sess.query(Users).filter_by(token=token).scalar()
    u.renew_pass(token, password)
    return bottle.redirect('/login')
    
