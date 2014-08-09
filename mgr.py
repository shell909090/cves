#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-08-01
@author: shell.xu
'''
import os, sys, logging
from os import path
import bottle, cves
from bottle import route, post, template, request, response, redirect
from db import *
import usr

logger = logging.getLogger('channel')
app = bottle.default_app()
sess = app.config['db.session']
basepath = app.config['basepath']

@route(basepath + '/')
@usr.chklogin()
def _list(session):
    chs = sess.query(Channels).filter_by(
        username=session['username']).order_by(Channels.id)
    return template('chs.html', chs=chs)

@post(path.join(basepath, 'add'))
@usr.chklogin()
def _add(session):
    severity = request.forms.get('severity')
    if severity not in cves.SM: return 'invalid severity'
    sess.add(Channels(
        name=request.forms.get('name'),
        username=session['username'],
        severity=severity))
    sess.commit()
    return redirect('.')

@route(path.join(basepath, 'del/<id:int>'))
@usr.chklogin()
def _del(session, id):
    ch = sess.query(Channels).filter_by(id=id).scalar()
    if not ch: return 'channel not exists.'
    if ch.username != session['username']:
        return 'channel not belongs to you'

    sess.delete(ch)
    sess.commit()
    return redirect('..')

@route(path.join(basepath, 'sev/<id:int>'))
@usr.chklogin()
def _sev(session, id):
    ch = sess.query(Channels).filter_by(id=id).scalar()
    if not ch: return 'channel not exists.'
    if ch.username != session['username']:
        return 'channel not belongs to you'

    return template('sev.html', ch=ch)

@post(path.join(basepath, 'sev/<id:int>'))
@usr.chklogin()
def _sev(session, id):
    ch = sess.query(Channels).filter_by(id=id).scalar()
    if not ch: return 'channel not exists.'
    if ch.username != session['username']:
        return 'channel not belongs to you'

    severity = request.forms.get('severity')
    if severity not in cves.SM: return 'invalid severity'
    ch.severity = severity
    sess.commit()
    return redirect('..')

@route(path.join(basepath, 'edit/<id:int>'))
@usr.chklogin()
def _edit(session, id):
    ch = sess.query(Channels).filter_by(id=id).scalar()
    if not ch: return 'channel not exists.'
    if ch.username != session['username']:
        return 'channel not belongs to you'

    return template('imp.html', data=''.join(getprods(id)))

@post(path.join(basepath, 'edit/<id:int>'))
@usr.chklogin()
def _edit(session, id):
    ch = sess.query(Channels).filter_by(id=id).scalar()
    if not ch: return 'channel not exists.'
    if ch.username != session['username']:
        return 'channel not belongs to you'

    sess.query(Produces).filter_by(chanid=id).delete()
    for p in ch.import_stream(request.forms['data'].splitlines()):
        sess.add(sess.merge(p))
    sess.commit()
    return redirect('..')

@route(path.join(basepath, 'imp/<id:int>'))
@usr.chklogin()
def _import(session, id):
    return template('imp.html', data='')

@post(path.join(basepath, 'imp/<id:int>'))
@usr.chklogin()
def _import(session, id):
    ch = sess.query(Channels).filter_by(id=id).scalar()
    if not ch: return 'channel not exists.'
    if ch.username != session['username']:
        return 'channel not belongs to you'

    for p in ch.import_stream(request.forms['data'].splitlines()):
        sess.add(sess.merge(p))
    sess.commit()
    return redirect('..')

def getprods(id):
    prods = list(sess.query(Produces).filter_by(chanid=id))
    for i in sorted(prods, key=lambda x:x.prod):
        yield '%s %s\n' % (i.prod, i.ver)

@route(path.join(basepath, 'exp/<id:int>'))
@usr.chklogin()
def _export(session, id):
    ch = sess.query(Channels).filter_by(id=id).scalar()
    if not ch: return 'channel not exists.'
    if ch.username != session['username']:
        return 'channel not belongs to you'

    response.set_header('Content-Type', 'text/plain')
    return getprods(id)

@route(path.join(basepath, 'clean/<id:int>'))
@usr.chklogin()
def _cleanup(session, id):
    ch = sess.query(Channels).filter_by(id=id).scalar()
    if not ch: return 'channel not exists.'
    if ch.username != session['username']:
        return 'channel not belongs to you'

    sess.query(Readed).filter_by(chanid=id).delete()
    sess.commit()
    return redirect('..')

@route(path.join(basepath, 'run/<id:int>'))
@usr.chklogin()
def _run(session, id):
    ch = sess.query(Channels).filter_by(id=id).scalar()
    if not ch: return 'channel not exists.'
    if ch.username != session['username']:
        return 'channel not belongs to you'

    cfg = app.config['cfg']
    cvelist = list(cves.getcves(cfg))
    response.set_header('Content-Type', 'text/plain')
    return ch.gen_body(cvelist, sess, dryrun=True)
