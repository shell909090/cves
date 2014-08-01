#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2011-05-05
@author: shell.xu
@version: 0.8.1
'''
import os, sys, web, base64, getopt, logging
from os import path
import bottle, cves
from beaker.middleware import SessionMiddleware
import sqlalchemy, sqlalchemy.orm

logger = logging.getLogger('main')
app = bottle.default_app()

optlist, args = getopt.getopt(sys.argv[1:], 'a:hp:')
optdict = dict(optlist)

cfg = cves.getcfg(['cves.ini', '/etc/cves.ini'])
app.config['cfg'] = cfg
cves.initlog(cfg.get('log', 'level'), cfg.get('log', 'file'))

engine = sqlalchemy.create_engine(cfg.get('db', 'url'))
sess = sqlalchemy.orm.sessionmaker(bind=engine)()
app.config['db.engine'] = engine
app.config['db.session'] = sess

session_opts = {
    'session.type': 'ext:database',
    'session.url': cfg.get('db', 'url'),
    'session.lock_dir': '/var/lock',
    'session.cookie_expires': 3600,
    'session.auto': True
}
application = SessionMiddleware(app, session_opts)

@bottle.route('/static/<filename:path>')
def _static(filename):
    return bottle.static_file(filename, root='static/')

import mgr

def main():
    optlist, args = getopt.getopt(sys.argv[1:], 'dhp:')
    optdict = dict(optlist)
    if '-h' in optdict:
        print main.__doc__
        return

    host = optdict.get('-a') or cfg.get('main', 'addr')
    port = int(optdict.get('-p') or cfg.get('main', 'port'))
    bottle.run(app=application, host=host, port=port, reloader=True)

if __name__ == '__main__': main()
else: application = app.wsgifunc()
