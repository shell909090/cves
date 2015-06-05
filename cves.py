#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2013-12-20
@author: shell.xu
'''
import re, os, time, json, gzip, smtplib
import logging, datetime, cStringIO
from os import path

NS = 'http://nvd.nist.gov/feeds/cve/1.2'

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
    tmpdir = cfg.get('urls', 'tmp')
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

def severity_filter(s):
    m = db.SM[s.lower()]
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
            vs = prod[n]
            if vs == 'all': return True
            cve['vers'].sort(cmp=lambda x,y: version_compare(x, y) <= 0)
            vers = cve['vers']
            for v in vs:
                if version_compare(v, vers[-1]) <= 0 and version_compare(v, vers[0]) > 0:
                    logging.debug('%s(%s) in %s - %s' % (cve['produce'], v, vers[0], vers[-1]))
                    return True
    return inner

def merge_prod(prod):
    rslt = {}
    for k, v in prod:
        for n in set(re_split.split(k)): rslt.setdefault(n, []).append(v)
    for k, v in rslt.items():
        if 'all' in v: rslt[k] = 'all'
    return rslt

def gen_chan_body(src, prod, id, readed=None, severity=None):
    logging.info('new chan %s' % id)
    if severity: src = filter(severity_filter(severity), src)
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
