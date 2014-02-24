#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2013-12-21
@author: shell.xu
'''
import os, time, logging
from os import path
from email.mime.text import MIMEText
import web, utils, core

rootdir = path.dirname(__file__)
os.chdir(rootdir)

cfg = utils.getcfg(['cves.conf', '/etc/cves.conf'])
db = web.database(**dict(cfg.items('db')))

def sendmail(srv, sender, i, body):
    msg = MIMEText(body)
    msg['Subject'] = 'CVE for %s' % i['name']
    msg['From'] = sender
    msg['To'] = i['email']
    logging.info('send email to %s' % msg['to'])
    srv.sendmail(sender, msg['To'].split(','), msg.as_string())

def main():
    utils.initlog(cfg.get('log', 'loglevel'), cfg.get('log', 'logfile'))
    sender = cfg.get('email', 'mail')
    cvelist = list(core.getcves(cfg))
    logging.debug('cvelist length %d' % len(cvelist))

    db.query('BEGIN')
    if cfg.getboolean('main', 'dryrun'):
        for i in db.select(
                ['channels', 'users'],
                what='channels.id, name, email, user, severity',
                where='channels.user = users.id'):
            c = core.Chan(db, i, cfg.getboolean('main', 'dryrun'))
            body = c.geninfo(cvelist)
            print body
    else:
        with utils.with_emailconfig(cfg) as srv:
            for i in db.select(
                    ['channels', 'users'],
                    what='channels.id, name, email, user, severity',
                    where='channels.user = users.id'):
                c = core.Chan(db, i, cfg.getboolean('main', 'dryrun'))
                body = c.geninfo(cvelist)
                if body: sendmail(srv, sender, i, body)

    # remove readed record for more then half a year
    db.delete('readed', where='uptime < $ti',
              vars={'ti': int(time.time() - 180 * 86400)})

if __name__ == '__main__': main()
