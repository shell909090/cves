#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2013-12-20
@author: shell.xu
'''
import re, os, time, json, gzip, smtplib, logging, datetime, cStringIO
from os import path
from contextlib import contextmanager

NS = 'http://nvd.nist.gov/feeds/cve/1.2'

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
def with_emailconfig(cfg, dryrun=False):
    if dryrun:
        yield None
        return
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

def download(url, etagpath, retry=3, timeout=10):
    import requests
    logging.info('download %s.' % url)
    headers = {}

    if path.exists(etagpath):
        if time.time() - os.stat(etagpath).st_mtime < 3600:
            logging.debug('etag less then a hour')
            return
        with open(etagpath, 'rb') as fi: etag = fi.read()
        logging.debug('etag found: %s' % etag)
        headers['If-None-Match'] = etag

    sess = requests.Session()
    sess.mount('http://', requests.adapters.HTTPAdapter(max_retries=3))
    r = sess.get(url, headers=headers, timeout=timeout)

    with open(etagpath, 'wb') as fo: fo.write(r.headers['Etag'])
    if r.status_code == 304:
        logging.debug('not modify, use cache.')
        return
    logging.debug('new data, update etag.')
    return r.content

def parse_nvdcve(stream):
    from lxml import etree
    logging.debug('new stream')
    tree = etree.parse(stream)
    for e in tree.getroot():
        vs = e.find('ns:vuln_soft', namespaces={'ns': NS})
        if vs is None: continue
        logging.debug('vuln %s hit' % e.get('name'))
        for p in vs:
            prod = p.get('name').lower()
            vers = [i.get('num') for i in p]
        desc = e.find('ns:desc', namespaces={'ns': NS})[0].text
        refs = [ref.get('url') for ref in e.find('ns:refs', namespaces={'ns': NS})]
        yield {'name': e.get('name'), 'produce': prod, 'vers': vers,
               'severity': e.get('severity'), 'published': e.get('published'),
               'desc': desc, 'refs': refs}

def open_cve_source(url, cfg):
    tmpdir = cfg.get('main', 'tmp')
    filepath = path.join(tmpdir, path.basename(url))
    r = download(url, filepath + '.etag',
                 timeout=cfg.getfloat('main', 'timeout'),
                 retry=cfg.getint('main', 'retry'))
    if not r:
        with gzip.open(filepath + '.json.gz', 'rb') as fi: return json.load(fi)
    objs = list(parse_nvdcve(cStringIO.StringIO(r)))
    with gzip.open(filepath + '.json.gz', 'wb') as fo: json.dump(objs, fo)
    return objs

def getcves(cfg):
    urls = ((k, v) for k, v in cfg.items('urls') if k.startswith('url'))
    urls = map(lambda x:x[1], sorted(urls, key=lambda x:x[0]))
    for url in urls:
        for o in open_cve_source(url, cfg): yield o

def version_compare(v1, v2):
    vs1 = v1.split('.'); vs2 = v2.split('.')
    for i in xrange(min(len(vs1), len(vs2))):
        try: ivs1, ivs2 = int(vs1[i]), int(vs2[i])
        except ValueError: ivs1, ivs2 = None, None
        if ivs1 is None or ivs2 is None:
            if vs1[i] < vs2[i]: return -1
            if vs1[i] > vs2[i]: return 1
        else:
            if ivs1 < ivs2: return -1
            if ivs1 > ivs2: return 1
    if len(vs1) < len(vs2): return -1
    if len(vs1) > len(vs2): return 1
    return 0

SM = {'high': 3, 'medium': 2, 'low': 1}
def severity_filter(s):
    m = SM[s.lower()]
    def inner(v):
        if v.get('severity') is None:
            logging.warning('severity of valu is none: %s' % str(v))
            return True
        return SM[v['severity'].lower()] >= m
    return inner

def readed_filter(readed):
    return lambda cve: cve['name'] not in readed

re_split = re.compile('[^a-zA-Z0-9]+')
def vuln(prod):
    def inner(cve):
        for n in set(re_split.split(cve['produce'])):
            if n not in prod: continue
            v = prod[n]
            if v == 'all': return True
            cve['vers'].sort(cmp=lambda x,y: version_compare(x, y) <= 0)
            vers = cve['vers']
            if version_compare(v, vers[-1]) <= 0 and version_compare(v, vers[0]) > 0:
                logging.debug('%s(%s) in %s - %s' % (cve['produce'], v, vers[0], vers[-1]))
                return True
    return inner

def merge_prod(prod):
    rslt = {}
    for k, v in prod.iteritems():
        for n in set(re_split.split(k)):
            if n not in rslt or version_compare(rslt[n], v) > 0:
                rslt[n] = v
    return rslt

def gen_chan_body(src, prod, id, readed=None, servity=None):
    logging.info('new chan %s' % id)
    if servity: src = filter(severity_filter(severity), src)
    if readed: src = filter(readed_filter(readed), src)
    stream, readed = cStringIO.StringIO(), []
    for cve in filter(vuln(merge_prod(prod)), src):
        stream.write('%s [%s] %s (%s to %s)\n' % (
            cve['name'], cve['severity'], cve['produce'],
            cve['vers'][0], cve['vers'][-1]))
        stream.write('    %s\n' % cve['desc'])
        for r in cve['refs']: stream.write('    * %s\n' % r)
        stream.write('\n')
        readed.append(cve['name'])
    return stream.getvalue().strip(), readed

def chan_with_db(db, dbobj, dryrun=False):
    id = dbobj['id']
    prod, readed = {}, set()
    for i in db.select(
            'produces', what='produce, version',
            where='channel=$cid', vars={'cid': id}):
        prod[i['produce']] = str(i['version'])
    for i in db.select(
            'readed', what='cvename',
            where='channel = $cid', vars={'cid': id}):
        readed.add(i['cvename'])
    body, newreaded = gen_chan_body(
        cvelist, prod, id, readed, dbobj['severity'])
    if not dryrun:
        for name in newreaded:
            db.insert('readed', channel=id,
                      cvename=name, uptime=int(time.time()))
    return body

# class Chan(object):
#     def __init__(self, db, dbobj, dryrun=False):
#         self.db, self.dbobj, self.id = db, dbobj, dbobj['id']
#         logging.info('new chan %s' % self.id)
#         self.dryrun = dryrun
#         self.prod, self.readed = {}, set()
#         for i in self.db.select(
#                 'produces', what='produce, version',
#                 where='channel=$cid', vars={'cid': self.id}):
#             self.prod[i['produce']] = str(i['version'])
#         for i in self.db.select(
#                 'readed', what='cvename',
#                 where='channel = $cid', vars={'cid': self.id}):
#             self.readed.add(i['cvename'])
#     def vuln(self, cves):
#         for cve in cves:
#             if cve['name'] in self.readed: continue
#             for p, v1 in self.prod.iteritems():
#                 if cve['produce'].find(p) == -1: continue
#                 if v1 == 'all':
#                     yield (cve, cve['vers'])
#                     continue
#                 for v in cve['vers']:
#                     if cves.version_compare(v1, v) <= 0:
#                         logging.debug('%s %s %s' % (p, v1, v))
#                         yield (cve, v)
#                         break
#     def format(self, rslt, stream):
#         for cve, v in rslt:
#             stream.write('\t%s [%s] to %s(%s)\n' % (
#                 cve['name'], cve['severity'], cve['produce'], v))
#             stream.write('\t%s\n' % cve['desc'])
#             for r in cve['refs']: stream.write('\t * %s\n' % r)
#             stream.write('\n')
#             if not self.dryrun:
#                 self.db.insert('readed', channel=self.id,
#                           cvename=cve['name'], uptime=int(time.time()))
#     def geninfo(self, src):
#         src = filter(cves.severity_filter(self.dbobj['severity']), src)
#         buf = cStringIO.StringIO()
#         self.format(self.vuln(src), buf)
#         return buf.getvalue().strip()
