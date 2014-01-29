#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-01-06
@author: shell.xu
'''
import smtplib, logging
from contextlib import contextmanager

LOGFMT = '%(asctime)s.%(msecs)03d[%(levelname)s](%(module)s:%(lineno)d): %(message)s'
def initlog(lv, logfile=None, stream=None, longdate=False):
    if isinstance(lv, basestring): lv = getattr(logging, lv)
    kw = {'format': LOGFMT, 'datefmt': '%H:%M:%S', 'level': lv}
    if logfile: kw['filename'] = logfile
    if stream: kw['stream'] = stream
    if longdate: kw['datefmt'] = '%Y-%m-%d %H:%M:%S'
    logging.basicConfig(**kw)

def getcfg(cfgpathes):
    from ConfigParser import SafeConfigParser
    cp = SafeConfigParser()
    cp.read(cfgpathes)
    return cp

@contextmanager
def with_emailconfig(cfg):
    srv = smtplib.SMTP(cfg.get('email', 'smtp'))
    if cfg.getboolean('email', 'ssl'):
        srv.ehlo()
        srv.starttls()
        srv.ehlo()
    if cfg.getboolean('email', 'debug'):
        srv.set_debuglevel(1)
    if cfg.has_option('email', 'passwd'):
        srv.login(cfg.get('email', 'mail'), cfg.get('email', 'passwd'))
    try: yield srv
    finally: srv.close()

@contextmanager
def with_smtp(server, username=None, password=None, ssl=False, debug=False):
    srv = smtplib.SMTP(server)
    if ssl:
        srv.ehlo()
        srv.starttls()
        srv.ehlo()
    if debug: srv.set_debuglevel(1)
    if username and password: srv.login(username, password)
    try: yield srv
    finally: srv.close()
