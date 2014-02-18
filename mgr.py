#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-02-17
@author: shell.xu
'''
import os, sys, logging
import web
import core

class UserList(object):
    def GET(self):
        users = web.config.db.select('users', what='id, email')
        return web.config.render.users(users=[dict(user) for user in users])

class ChanList(object):
    def GET(self, userid):
        f = ChanAdd.form()
        chans = [dict(chan) for chan in web.config.db.select(
            'channels', what='id, name, severity',
            where='user = $u', vars={'u': int(userid)})]
        return web.config.render.user(userid=userid, form=f, chans=chans)

class ChanAdd(object):
    form = web.form.Form(
        web.form.Textbox('name', description='name'),
        web.form.Dropdown('severity', args=['high', 'medium', 'low'],
                          description='severity'),
        web.form.Button('create', type='submit', description='create'),
        )
    def POST(self, userid):
        f = register_form()
        if f.validates():
            web.config.db.insert(
                'channels', user=int(userid),
                name=form['name'], severity=form['severity'])
        web.seeother('/user/%s' % userid)

class ChanDel(object):
    def POST(self, chid):
        userid = web.config.db.select(
            'channels', what='user', where='id = $ch',
            vars={'ch': int(chid)})[0]['user']
        with web.config.db.transaction():
            web.config.db.delete(
                'produces', where='channel = $ch', vars={'ch': int(chid)})
            web.config.db.delete(
                'channels', where='id = $ch', vars={'ch': int(chid)})
        web.seeother('/user/%d' % userid)

class ChanSeverity(object):
    SM = {'high': 3, 'medium': 2, 'low': 1}
    def GET(self, chid):
        return web.config.render.severity(errmsg='')

    def POST(self, chid):
        data = web.input()['data']
        r = self.SM.get(data)
        if r is None:
            return web.config.render.severity(errmsg='invaild severity')
        web.config.db.update(
            'channels', where='id = $ch', vars={'ch': chid}, severity=data)
        userid = web.config.db.select(
            'channels', what='user', where='id = $ch',
            vars={'ch': int(chid)})[0]['user']
        web.seeother('/user/%d' % userid)

class ChanEdit(object):
    def GET(self, chid):
        return web.config.render.imports(
            errmsg='', data=''.join(getprods(int(chid))))

    def POST(self, chid):
        chid = int(chid)
        with web.config.db.transaction():
            web.config.db.delete(
                'produces', where='channel = $ch', vars={'ch': chid})
            l = []
            for line in web.input()['data'].splitlines():
                line = line.strip()
                if not line: continue
                produce, version = line.split(' ', 1)
                l.append({'channel': chid, 'produce': produce, 'version': version})
            web.config.db.multiple_insert('produces', l)
        return web.seeother('/user/%s' % chid)

class ChanImport(object):
    def GET(self, chid):
        return web.config.render.imports(errmsg='', data='')

    def POST(self, chid):
        chid = int(chid)
        with web.config.db.transaction():
            for line in web.input()['data'].splitlines():
                line = line.strip()
                if not line: continue
                produce, version = line.split(' ', 1)
                if not web.config.db.update(
                    'produces', where='channel = $ch and produce = $pr',
                    vars={'ch': chid, 'pr': produce}, channel=int(chid),
                    produce=produce, version=version):
                    web.config.db.insert(
                        'produces', channel=int(chid), produce=produce, version=version)
        return web.seeother('/user/%s' % chid)

def getprods(chid):
    prods = list(web.config.db.select(
        'produces', what='produce, version',
        where='channel = $ch', vars={'ch': chid}))
    for i in sorted(prods, key=lambda x:x['produce']):
        yield '%s %s\n' % (i['produce'], i['version'])

class ChanExport(object):
    def GET(self, chid):
        return getprods(int(chid))

class ChanCleanup(object):
    def POST(self, chid):
        userid = web.config.db.select(
            'channels', what='user', where='id = $ch',
            vars={'ch': int(chid)})[0]['user']
        web.config.db.delete(
            'readed', where='channel = $ch', vars={'ch': int(chid)})
        web.seeother('/user/%d' % userid)

def getcves():
    urls = ((k, v) for k, v in web.config.cfg.items('urls')
            if k.startswith('url'))
    urls = map(lambda x:x[1], sorted(urls, key=lambda x:x[0]))
    return cves.getcves(urls, cfg.get('urls', 'tmp'))

class ChanRun(object):
    def GET(self, chid):
        i = web.config.db.select(
            ['channels', 'users'],
            what='channels.id, name, email, user, severity',
            where='channels.id = $ch', vars={'ch': int(chid)})[0]
        c = core.Chan(web.config.db, i, True)
        return c.geninfo(core.getcves(web.config.cfg))
