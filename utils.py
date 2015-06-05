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
    sess = requests.Session()
    sess.mount('http://', requests.adapters.HTTPAdapter(max_retries=3))
    logging.info('download %s.' % url)
    return sess.get(url, headers=headers, timeout=timeout)

# def download(url, etagpath, retry=3, timeout=10):
#     if path.exists(etagpath):
#         if time.time() - os.stat(etagpath).st_mtime < 3600:
#             logging.debug('etag less then a hour')
#             return
#         with open(etagpath, 'rb') as fi: etag = fi.read()
#         logging.debug('etag found: %s' % etag)
#         headers['If-None-Match'] = etag
#     r = download_retry(url, headers, retry, timeout)
#     with open(etagpath, 'wb') as fo: fo.write(r.headers['Etag'])
#     if r.status_code == 304:
#         logging.debug('not modify, use cache.')
#         return
#     logging.debug('new data, update etag.')
#     return r.content
