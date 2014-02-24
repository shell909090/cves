#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2013-12-20
@author: shell.xu
'''
import logging, datetime
from os import path
import requests
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

def download(url, headers):
    for i in xrange(retry):
        try:
            return requests.get(
                url, headers=headers, timeout=timeout)
        except requests.exceptions.Timeout: pass
    raise requests.exceptions.Timeout()

def xfetchurl(url, tmp):
    logging.info('download %s.' % url)
    filepath = path.join(tmp, path.basename(url))
    headers, etag = {}, get_etag(filepath)
    if etag is not None:
        logging.debug('etag found: %s' % etag)
        headers['If-None-Match'] = etag

    r = download(url, headers)
    if r.status_code == 304:
        logging.debug('not modify, use cache.')
        return open(filepath, 'rb')

    with open(filepath, 'wb') as fo:
        fo.write(r.content)

    logging.debug('new data, update file and etag.')
    with open(filepath + '.etag', 'wb') as fo:
        fo.write(r.headers['Etag'])
    return open(filepath, 'rb')

def getcves(urls, tmp):
    for url in urls:
        for i in parse_nvdcve(xfetchurl(url, tmp)): yield i
