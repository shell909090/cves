#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2011-05-05
@author: shell.xu
@version: 0.8.1
'''
import sys, getopt
from os import path
import sqlalchemy, sqlalchemy.orm
import bottle 
from beaker.middleware import SessionMiddleware
import db, utils, vuln

application = None
optdict     = None

def built_db():
    db.Base.metadata.create_all(utils.engine)
    if '-d' in optdict:
        utils.sess.add(db.Users(username='guest@mail.com', passwd=db.crypto_pass('123')))
        utils.sess.commit()

def cron_job():
    dryrun = utils.cfg.getboolean('main', 'dryrun')
    with utils.with_emailconfig(utils.cfg, dryrun) as srv:
        vuln.run(srv, dryrun)

    # remove readed record for more then half a year
    utils.sess.query(db.Readed).filter(db.Readed.ts < '"CURRENT_TIMESTAMP - 180 * 86400"').delete()
    utils.sess.commit()

def web_main():
    app = bottle.default_app()
    app.config['cfg'] = utils.cfg
    app.config['db.engine'] = utils.engine
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
    u = urlparse(utils.cfg.get('web', 'baseurl'))
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
    utils.cfg = utils.getcfg(cfgpathes)

    utils.initlog(utils.cfg.get('log', 'level'), utils.cfg.get('log', 'file'))

    echo = utils.cfg.has_option('db', 'echo') and utils.cfg.getboolean('db', 'echo')
    utils.engine = sqlalchemy.create_engine(utils.cfg.get('db', 'url'), echo=echo)
    utils.sess = sqlalchemy.orm.sessionmaker(bind=utils.engine)()

    if '-j' in optdict:
        return cron_job()
    elif '-b' in optdict:
        return built_db()
    else: return web_main()

if __name__ == '__main__': main()
