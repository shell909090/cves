#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2013-12-20
@author: shell.xu
'''
import shutil, urllib2, logging, datetime
from os import path
from lxml import etree

NS = 'http://nvd.nist.gov/feeds/cve/1.2'

def parse_nvdcve(stream):
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

def get_etag(filepath):
    if not path.exists(filepath + '.etag'): return
    with open(filepath + '.etag', 'rb') as fi: return fi.read()

def xfetchurl(url):
    logging.info('download %s.' % url)
    filepath = path.join(cfg.get('urls', 'tmp'), path.basename(url))
    req = urllib2.Request(url)
    etag = get_etag(filepath)
    if etag is not None:
        logging.debug('etag found')
        req.add_header('If-None-Match', etag)

    try: fi = urllib2.urlopen(req)
    except urllib2.HTTPError as err:
        if err.code == 304:
            logging.debug('not modify, use cache.')
            return open(filepath, 'rb')
        raise

    with open(filepath, 'wb') as fo:
        shutil.copyfileobj(fi, fo)
        fi.close()

    logging.debug('new data, update file and etag.')
    etag = fi.info().getheader('ETag')
    with open(filepath + '.etag', 'wb') as fo:
        fo.write(etag)
    return open(filepath, 'rb')

def getcves(urls):
    for url in urls:
        for i in parse_nvdcve(xfetchurl(url)): yield i
