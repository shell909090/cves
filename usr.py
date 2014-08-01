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

@route('/login', method='POST')
def _login():
    session = request.environ.get('beaker.session')
    username = request.forms.get('username')
    password = request.forms.get('password')
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

# invite
# retrieved password
