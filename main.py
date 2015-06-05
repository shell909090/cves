#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2011-05-05
@author: shell.xu
@version: 0.8.1
'''
import os, sys, base64, getopt, logging
from os import path
import bottle, utils, cves
from beaker.middleware import SessionMiddleware
import sqlalchemy, sqlalchemy.orm

def built_db():
    import db
    db.Base.metadata.create_all(engine)
    if '-d' in optdict:
        utils.sess.add(Users(username='guest@mail.com', passwd=crypto_pass('123')))
        utils.sess.commit()

def cron_job():
    dryrun = utils.cfg.getboolean('main', 'dryrun')
    with utils.with_emailconfig(utils.cfg, dryrun) as srv:
        vuln.run(srv, dryrun)

    # remove readed record for more then half a year
    utils.sess.query(Readed).filter(Readed.ts < '"CURRENT_TIMESTAMP - 180 * 86400"').delete()
    utils.sess.commit()

def web_main():
    app = bottle.default_app()
    app.config['cfg'] = cfg
    app.config['db.engine'] = engine
    app.config['db.session'] = utils.sess

    session_opts = {
        'session.type': 'ext:database',
        'session.url': utils.cfg.get('db', 'url'),
        'session.lock_dir': '/var/lock',
        'session.cookie_expires': 3600,
        'session.auto': True
    }
    global application
    application = SessionMiddleware(app, session_opts)

    from urlparse import urlparse
    u = urlparse(utils.cfg.get('main', 'baseurl'))
    app.config['baseurl'] = u
    app.config['basepath'] = u.path

    @bottle.route(path.join(u.path, 'static/<filename:path>'))
    def _static(filename):
        return bottle.static_file(filename, root='static/')

    import usr
    import mgr

    bottle.run(app=application, host=app.config['baseurl'].hostname,
               port=app.config['baseurl'].port, reloader=True)

def main():
    global optdict
    optlist, args = getopt.getopt(sys.argv[1:], 'bc:dhj')
    optdict = dict(optlist)
    if '-h' in optdict:
        print main.__doc__
        return

    cfgpathes = ['cves.ini', '/etc/cves.ini']
    if '-c' in optdict:
        cfgpathes.insert(0, optdict['-c'])
    cfg = utils.getcfg(cfgpathes)
    utils.cfg = cfg

    utils.initlog(cfg.get('log', 'level'), cfg.get('log', 'file'))

    global engine
    echo = cfg.has_option('db', 'echo') and cfg.getboolean('db', 'echo')
    engine = sqlalchemy.create_engine(cfg.get('db', 'url'), echo=echo)
    sess = sqlalchemy.orm.sessionmaker(bind=engine)()
    utils.sess = sess

    if '-j' in optdict:
        return cron_job()
    elif '-b' in optdict:
        return built_db()
    else: return web_main()

if __name__ == '__main__': main()
