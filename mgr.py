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

@route('/')
@chklogin()
def _list(session):
    chs = sess.query(Channels).filter_by(username=session['username']).order_by(Channels.id)
    return template('chs.html', chs=chs)

@route('/add', method='POST')
@chklogin()
def _add(session):
    sess.add(Channels(
        name=request.forms.get('name'),
        username=session['username'],
        severity=request.forms.get('severity')))
    sess.commit()
    return bottle.redirect('/')

@route('/del/<id:int>')
@chklogin()
def _del(session, id):
    ch = sess.query(Channels).filter_by(id=id).scalar()
    if not ch: return 'channel not exists.'
    sess.delete(ch)
    sess.commit()
    return bottle.redirect('/')

@route('/sev/<id:int>')
@chklogin()
def _sev(session, id):
    pass

@route('/edit/<id:int>')
@chklogin()
def _edit(session, id):
    return template('imp.html', data=''.join(getprods(id)))

@route('/edit/<id:int>', method='POST')
@chklogin()
def _edit(session, id):
    ch = sess.query(Channels).filter_by(id=id).scalar()
    if not ch: return 'channel not exists.'
    sess.query(Produces).filter_by(chanid=id).delete()
    for p in ch.import_stream(request.forms['data'].splitlines()):
        sess.add(sess.merge(p))
    sess.commit()

@route('/imp/<id:int>')
@chklogin()
def _import(session, id):
    return template('imp.html', data='')

@route('/imp/<id:int>', method='POST')
@chklogin()
def _import(session, id):
    ch = sess.query(Channels).filter_by(id=id).scalar()
    if not ch: return 'channel not exists.'
    for p in ch.import_stream(request.forms['data'].splitlines()):
        sess.add(sess.merge(p))
    sess.commit()

def getprods(id):
    prods = list(sess.query(Produces).filter_by(chanid=id))
    for i in sorted(prods, key=lambda x:x.prod):
        yield '%s %s\n' % (i.prod, i.ver)

@route('/exp/<id:int>')
@chklogin()
def _export(session, id):
    response.set_header('Content-Type', 'text/plain')
    return getprods(id)

@route('/clean/<id:int>')
@chklogin()
def _cleanup(session, id):
    sess.query(Readed).filter_by(chanid=id).delete()
    sess.commit()
    return bottle.redirect('/')

@route('/run/<id:int>')
@chklogin()
def _run(session, id):
    ch = sess.query(Channels).filter_by(id=id).scalar()
    cfg = app.config['cfg']
    cvelist = list(cves.getcves(cfg))
    dryrun = cfg.getboolean('main', 'dryrun')
    return ch.gen_body(cvelist, sess, dryrun=dryrun)
