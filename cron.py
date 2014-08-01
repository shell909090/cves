#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2013-12-21
@author: shell.xu
'''
import os, time, logging
from os import path
from email.mime.text import MIMEText
import sqlalchemy, cves
from db import *

rootdir = path.dirname(__file__)
if rootdir: os.chdir(rootdir)

def main():
    cfg = cves.getcfg(['cves.ini', '/etc/cves.ini'])
    cves.initlog(cfg.get('log', 'level'), cfg.get('log', 'file'))
    engine = sqlalchemy.create_engine(cfg.get('db', 'url'))
    sess = sqlalchemy.orm.sessionmaker(bind=engine)()

    sender = cfg.get('email', 'mail')
    cvelist = list(cves.getcves(cfg))
    logging.debug('cvelist length %d' % len(cvelist))

    dryrun = cfg.getboolean('main', 'dryrun')
    with cves.with_emailconfig(cfg, dryrun) as srv:
        for ch in sess.query(Channels):
            body = ch.gen_body(cvelist, sess, dryrun=dryrun)
            if not body: continue
            if not dryrun:
                msg = MIMEText(body)
                msg['Subject'] = 'CVE for %s' % ch.name
                msg['From'] = sender
                msg['To'] = ch.user.username
                logging.info('send email to %s' % msg['to'])
                srv.sendmail(sender, msg['To'].split(','), msg.as_string())
            else: print body

    # remove readed record for more then half a year
    sess.query(Readed).filter(Readed.ts < 'CURRENT_TIMESTAMP - 180 * 86400').delete()
    sess.commit()

if __name__ == '__main__': main()
