#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2013-12-21
@author: shell.xu
'''
import os, time, logging
from os import path
from email.mime.text import MIMEText
import web, cves

rootdir = path.dirname(__file__)
os.chdir(rootdir)

cfg = cves.getcfg(['cves.conf', '/etc/cves.conf'])
db = web.database(**dict(cfg.items('db')))

def sendmail(srv, sender, i, body):
    msg = MIMEText(body)
    msg['Subject'] = 'CVE for %s' % i['name']
    msg['From'] = sender
    msg['To'] = i['email']
    logging.info('send email to %s' % msg['to'])
    srv.sendmail(sender, msg['To'].split(','), msg.as_string())

def main():
    cves.initlog(cfg.get('log', 'level'), cfg.get('log', 'file'))
    sender = cfg.get('email', 'mail')
    cvelist = list(cves.getcves(cfg))
    logging.debug('cvelist length %d' % len(cvelist))

    dryrun = cfg.getboolean('main', 'dryrun')
    db.query('BEGIN')
    with cves.with_emailconfig(cfg, dryrun) as srv:
        for i in db.select(
                ['channels', 'users'],
                what='channels.id, name, email, user, severity',
                where='channels.user = users.id'):
            body = cves.chan_with_db(db, i)
            if not body: continue
            if not dryrun:
                sendmail(srv, sender, i, body)
            else: print body

    # remove readed record for more then half a year
    db.delete('readed', where='uptime < $ti',
              vars={'ti': int(time.time() - 180 * 86400)})

if __name__ == '__main__': main()
