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
import usr

logger = logging.getLogger('channel')
app = bottle.default_app()
sess = app.config['db.session']

@route('/')
@usr.chklogin()
def _list(session):
    chs = sess.query(Channels).filter_by(
        username=session['username']).order_by(Channels.id)
    return template('chs.html', chs=chs)

@route('/add', method='POST')
@usr.chklogin()
def _add(session):
    sess.add(Channels(
        name=request.forms.get('name'),
        username=session['username'],
        severity=request.forms.get('severity')))
    sess.commit()
    return bottle.redirect('/')

@route('/del/<id:int>')
@usr.chklogin()
def _del(session, id):
    ch = sess.query(Channels).filter_by(id=id).scalar()
    if not ch: return 'channel not exists.'
    if ch.username != session['username']:
        return 'channel not belongs to you'

    sess.delete(ch)
    sess.commit()
    return bottle.redirect('/')

@route('/sev/<id:int>')
@usr.chklogin()
def _sev(session, id):
    ch = sess.query(Channels).filter_by(id=id).scalar()
    if not ch: return 'channel not exists.'
    if ch.username != session['username']:
        return 'channel not belongs to you'

    return template('sev.html', ch=ch)

@route('/sev/<id:int>', method='POST')
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
    return bottle.redirect('/')

@route('/edit/<id:int>')
@usr.chklogin()
def _edit(session, id):
    ch = sess.query(Channels).filter_by(id=id).scalar()
    if not ch: return 'channel not exists.'
    if ch.username != session['username']:
        return 'channel not belongs to you'

    return template('imp.html', data=''.join(getprods(id)))

@route('/edit/<id:int>', method='POST')
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
    return bottle.redirect('/')

@route('/imp/<id:int>')
@usr.chklogin()
def _import(session, id):
    return template('imp.html', data='')

@route('/imp/<id:int>', method='POST')
@usr.chklogin()
def _import(session, id):
    ch = sess.query(Channels).filter_by(id=id).scalar()
    if not ch: return 'channel not exists.'
    if ch.username != session['username']:
        return 'channel not belongs to you'

    for p in ch.import_stream(request.forms['data'].splitlines()):
        sess.add(sess.merge(p))
    sess.commit()

def getprods(id):
    prods = list(sess.query(Produces).filter_by(chanid=id))
    for i in sorted(prods, key=lambda x:x.prod):
        yield '%s %s\n' % (i.prod, i.ver)

@route('/exp/<id:int>')
@usr.chklogin()
def _export(session, id):
    ch = sess.query(Channels).filter_by(id=id).scalar()
    if not ch: return 'channel not exists.'
    if ch.username != session['username']:
        return 'channel not belongs to you'

    response.set_header('Content-Type', 'text/plain')
    return getprods(id)

@route('/clean/<id:int>')
@usr.chklogin()
def _cleanup(session, id):
    ch = sess.query(Channels).filter_by(id=id).scalar()
    if not ch: return 'channel not exists.'
    if ch.username != session['username']:
        return 'channel not belongs to you'

    sess.query(Readed).filter_by(chanid=id).delete()
    sess.commit()
    return bottle.redirect('/')

@route('/run/<id:int>')
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
