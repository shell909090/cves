#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-02-17
@author: shell.xu
'''
import os, sys, logging
import web, cves

db = web.config.db
render = web.config.render

class Login(object):
    form = web.form.Form(
        web.form.Textbox('email', description='email'),
        web.form.Password('password', description='Password'),
        web.form.Button('login', type='submit', description='login'),
        )
    def GET(self):
        print web.input()
        return render.login(form=f, errmsg='')

    def POST(self):
        f = self.form()
        if not f.validates():
            return render.login(form=f, errmsg='invaild form')
        try:
            user = db.select('users', where='email=$email', vars={'email': f.d['email']})[0]
            if cves.check_pass(f.d['password'], user['passwd']):
                web.config.session.user = user
                return web.seeother(web.input().get('next') or '/')
        except Exception, err: pass
        return render.login(form=f, errmsg='user not exist or password wrong')

def chklg():
    def recver(func):
        def inner(self, *p, **kw):
            user = web.config.session.get('user')
            if not user:
                web.seeother('/login?next=%s' % web.ctx.path)
            return func(self, userid, *p, **kw)
        return inner
    return recver

class UserList(object):
    def GET(self):
        users = db.select('users', what='id, email')
        return render.users(users=[dict(user) for user in users])

class ChanList(object):
    def GET(self, userid):
        f = ChanAdd.form()
        chans = [dict(chan) for chan in db.select(
            'channels', what='id, name, severity',
            where='user = $u', vars={'u': int(userid)})]
        return render.user(userid=userid, form=f, chans=chans)

class ChanAdd(object):
    form = web.form.Form(
        web.form.Textbox('name', description='name'),
        web.form.Dropdown('severity', args=['high', 'medium', 'low'],
                          description='severity'),
        web.form.Button('create', type='submit', description='create'),
        )
    def POST(self, userid):
        f = self.form()
        if f.validates():
            db.insert(
                'channels', user=int(userid),
                name=f.d['name'], severity=f.d['severity'])
        return web.seeother('/user/%s' % userid)

class ChanDel(object):
    def POST(self, chid):
        userid = db.select(
            'channels', what='user', where='id = $ch',
            vars={'ch': int(chid)})[0]['user']
        with db.transaction():
            db.delete(
                'produces', where='channel = $ch', vars={'ch': int(chid)})
            db.delete(
                'channels', where='id = $ch', vars={'ch': int(chid)})
        web.seeother('/user/%d' % userid)

class ChanSeverity(object):
    SM = {'high': 3, 'medium': 2, 'low': 1}
    form = web.form.Form(
        web.form.Dropdown('severity', args=['high', 'medium', 'low'],
                          description='severity'),
        web.form.Button('update', type='submit', description='update'),
        )
    def GET(self, chid):
        f = self.form()
        return render.severity(form=f, errmsg='')

    def POST(self, chid):
        f = self.form()
        if not f.validates():
            return render.severity(form=f, errmsg='invaild form')
        severity = f.d['severity']
        r = self.SM.get(severity)
        if r is None:
            return render.severity(form=f, errmsg='invaild severity')
        db.update(
            'channels', where='id = $ch', vars={'ch': chid}, severity=severity)
        userid = db.select(
            'channels', what='user', where='id = $ch',
            vars={'ch': int(chid)})[0]['user']
        return web.seeother('/user/%d' % userid)

class ChanEdit(object):
    def GET(self, chid):
        return render.imports(
            errmsg='', data=''.join(getprods(int(chid))))

    def POST(self, chid):
        chid = int(chid)
        userid = db.select(
            'channels', what='user', where='id = $ch',
            vars={'ch': chid})[0]['user']
        with db.transaction():
            db.delete(
                'produces', where='channel = $ch', vars={'ch': chid})
            l = []
            for line in web.input()['data'].splitlines():
                line = line.strip()
                if not line: continue
                produce, version = line.split(' ', 1)
                l.append({'channel': chid, 'produce': produce, 'version': version})
            db.multiple_insert('produces', l)
        return web.seeother('/user/%s' % userid)

class ChanImport(object):
    def GET(self, chid):
        return render.imports(errmsg='', data='')

    def POST(self, chid):
        chid = int(chid)
        userid = db.select(
            'channels', what='user', where='id = $ch',
            vars={'ch': chid})[0]['user']
        with db.transaction():
            for line in web.input()['data'].splitlines():
                line = line.strip()
                if not line: continue
                produce, version = line.split(' ', 1)
                if not db.update(
                    'produces', where='channel = $ch and produce = $pr',
                    vars={'ch': chid, 'pr': produce}, channel=int(chid),
                    produce=produce, version=version):
                    db.insert(
                        'produces', channel=int(chid), produce=produce, version=version)
        return web.seeother('/user/%s' % userid)

def getprods(chid):
    prods = list(db.select(
        'produces', what='produce, version',
        where='channel = $ch', vars={'ch': chid}))
    for i in sorted(prods, key=lambda x:x['produce']):
        yield '%s %s\n' % (i['produce'], i['version'])

class ChanExport(object):
    def GET(self, chid):
        return getprods(int(chid))

class ChanCleanup(object):
    def POST(self, chid):
        userid = db.select(
            'channels', what='user', where='id = $ch',
            vars={'ch': int(chid)})[0]['user']
        db.delete(
            'readed', where='channel = $ch', vars={'ch': int(chid)})
        web.seeother('/user/%d' % userid)

# class ChanRun(object):
#     def GET(self, chid):
#         i = db.select(
#             ['channels', 'users'],
#             what='channels.id, name, email, user, severity',
#             where='channels.id = $ch', vars={'ch': int(chid)})[0]
#         c = cves.Chan(db, i, True)
#         return c.geninfo(core.getcves(web.config.cfg))

app = web.application((
    r'/login', Login,
    r'/add/(\d*)', ChanAdd,
    r'/del/(\d*)', ChanDel,
    r'/sev/(\d*)', ChanSeverity,
    r'/edit/(\d*)', ChanEdit,
    r'/import/(\d*)', ChanImport,
    r'/export/(\d*)', ChanExport,
    r'/cleanup/(\d*)', ChanCleanup,
    # r'/run/(\d*)', ChanRun,
))
