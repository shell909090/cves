#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2015-05-13
@author: shell.xu
'''
import os, sys, logging
from ConfigParser import SafeConfigParser
from contextlib import contextmanager
import requests

sess = None
cfg  = None

LOGFMT = '%(asctime)s.%(msecs)03d[%(levelname)s](%(module)s:%(lineno)d): %(message)s'
def initlog(lv, logfile=None, stream=None, longdate=False):
    if isinstance(lv, basestring): lv = getattr(logging, lv)
    kw = {'format': LOGFMT, 'datefmt': '%H:%M:%S', 'level': lv}
    if logfile: kw['filename'] = logfile
    if stream: kw['stream'] = stream
    if longdate: kw['datefmt'] = '%Y-%m-%d %H:%M:%S'
    logging.basicConfig(**kw)

def getcfg(cfgpathes):
    cp = SafeConfigParser()
    cp.read(cfgpathes)
    return cp

def cfg_option(cfg, sec, opt):
    return cfg.has_option(sec, opt) and cfg.getboolean(sec, opt)

class FakeSMTP(object):
    def sendmail(self, sender, to, msg):
        logging.info('sender: %s, to: %s' % (sender, to))
        logging.info('msg: ' + msg)

@contextmanager
def with_emailconfig(cfg):
    if cfg_option(cfg, 'email', 'dryrun'):
        yield FakeSMTP()
        return
    srv = smtplib.SMTP(cfg.get('email', 'smtp'))
    if cfg_option(cfg, 'email', 'ssl'):
        srv.ehlo()
        srv.starttls()
        srv.ehlo()
    if cfg_option(cfg, 'email', 'debug'):
        srv.set_debuglevel(1)
    if cfg.has_option('email', 'passwd'):
        srv.login(cfg.get('email', 'mail'), cfg.get('email', 'passwd'))
    try: yield srv
    finally: srv.close()

def download(url, headers=None, retry=3, timeout=10):
    if headers is None: headers = {}
    reqsess = requests.Session()
    reqsess.mount('http://', requests.adapters.HTTPAdapter(max_retries=retry))
    logging.info('download %s.' % url)
    return reqsess.get(url, headers=headers, timeout=timeout)

def download_cached(url, retry=3, timeout=10):
    headers = {}

    ue = sess.query(HttpCache).filter_by(url=url).scalar()
    if ue:
        logging.debug('etag found: %s' % ue.etag)
        headers['If-None-Match'] = ue.etag
        # TODO: if modified since

    r = download(url, headers, retry, timeout)

    if r.status_code == 304:
        logging.debug('not modify, use cache.')
        return
    
    if 'Etag' in r.headers:
        # TODO: if modified since
        sess.add(sess.merge(HttpCache(url=url, etag=r.headers['Etag'])))
        sess.commit()

    return r.content
