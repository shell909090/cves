#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-08-01
@author: shell.xu
'''
import logging
from os import path
import bottle, cves
from bottle import route, post, template, request, response, redirect
import db, usr

logger = logging.getLogger('channel')
app = bottle.default_app()
sess = app.config['db.session']
basepath = app.config['basepath']

@route(basepath + '/')
@usr.chklogin()
def _list(session):
    chs = sess.query(db.Channels).filter_by(
        username=session['username']).order_by(db.Channels.id)
    return template('chs.html', chs=chs)

@route(path.join(basepath, 'addchan'))
@usr.chklogin()
def _addchan(session):
    return template('addchan.html')

@post(path.join(basepath, 'addchan'))
@usr.chklogin()
def _addchan_post(session):
    severity = request.forms.get('severity')
    if severity not in db.SM: return 'invalid severity'
    sess.add(db.Channels(
        name=request.forms.get('name'),
        username=session['username'],
        severity=severity))
    sess.commit()
    return redirect('.')

@route(path.join(basepath, 'del/<chid:int>'))
@usr.chklogin()
def _del(session, chid):
    ch = sess.query(db.Channels).filter_by(id=chid).scalar()
    if not ch: return 'channel not exists.'
    if ch.username != session['username']:
        return 'channel not belongs to you'

    sess.delete(ch)
    sess.commit()
    return redirect('..')

@route(path.join(basepath, 'sev/<chid:int>'))
@usr.chklogin()
def _sev(session, chid):
    ch = sess.query(db.Channels).filter_by(id=chid).scalar()
    if not ch: return 'channel not exists.'
    if ch.username != session['username']:
        return 'channel not belongs to you'

    return template('sev.html', ch=ch)

@post(path.join(basepath, 'sev/<chid:int>'))
@usr.chklogin()
def _sev_post(session, chid):
    ch = sess.query(db.Channels).filter_by(id=chid).scalar()
    if not ch: return 'channel not exists.'
    if ch.username != session['username']:
        return 'channel not belongs to you'

    severity = request.forms.get('severity')
    if severity not in db.SM: return 'invalid severity'
    ch.severity = severity
    sess.commit()
    return redirect('..')

@route(path.join(basepath, 'edit/<chid:int>'))
@usr.chklogin()
def _edit(session, chid):
    ch = sess.query(db.Channels).filter_by(id=chid).scalar()
    if not ch: return 'channel not exists.'
    if ch.username != session['username']:
        return 'channel not belongs to you'

    return template('imp.html', data=''.join(getprods(chid)))

@post(path.join(basepath, 'edit/<chid:int>'))
@usr.chklogin()
def _edit_post(session, chid):
    ch = sess.query(db.Channels).filter_by(id=chid).scalar()
    if not ch: return 'channel not exists.'
    if ch.username != session['username']:
        return 'channel not belongs to you'

    produces = set(request.forms['data'].splitlines())
    ch.produces = '\n'.join(sorted(list(produces)))
    sess.commit()
    return redirect('..')

@route(path.join(basepath, 'imp/<chid:int>'))
@usr.chklogin()
def _import(session, chid):
    return template('imp.html', data='')

@post(path.join(basepath, 'imp/<chid:int>'))
@usr.chklogin()
def _import_post(session, chid):
    ch = sess.query(db.Channels).filter_by(id=chid).scalar()
    if not ch: return 'channel not exists.'
    if ch.username != session['username']:
        return 'channel not belongs to you'

    produces = set(ch.produces.splitlines()) + set(request.forms['data'].splitlines())
    ch.produces = '\n'.join(sorted(list(produces)))
    sess.commit()
    return redirect('..')

@route(path.join(basepath, 'exp/<chid:int>'))
@usr.chklogin()
def _export(session, chid):
    ch = sess.query(db.Channels).filter_by(id=chid).scalar()
    if not ch: return 'channel not exists.'
    if ch.username != session['username']:
        return 'channel not belongs to you'

    response.set_header('Content-Type', 'text/plain')
    return ch.produces

@route(path.join(basepath, 'clean/<chid:int>'))
@usr.chklogin()
def _cleanup(session, chid):
    ch = sess.query(db.Channels).filter_by(id=chid).scalar()
    if not ch: return 'channel not exists.'
    if ch.username != session['username']:
        return 'channel not belongs to you'

    sess.query(db.Readed).filter_by(chanid=chid).delete()
    sess.commit()
    return redirect('..')

@route(path.join(basepath, 'run/<chid:int>'))
@usr.chklogin()
def _run(session, chid):
    ch = sess.query(db.Channels).filter_by(id=chid).scalar()
    if not ch: return 'channel not exists.'
    if ch.username != session['username']:
        return 'channel not belongs to you'

    # FIXME: rewrite
    cfg = app.config['cfg']
    cvelist = list(cves.getcves(cfg))
    response.set_header('Content-Type', 'text/plain')
    return ch.gen_body(cvelist, sess, dryrun=True)
