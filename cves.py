#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2013-12-20
@author: shell.xu
'''
import re, os, time, json, gzip, smtplib
import logging, datetime, cStringIO
from os import path

NS  = 'http://nvd.nist.gov/feeds/cve/1.2'
URL = 'http://nvd.nist.gov/download/nvdcve-recent.xml'

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
        vers.sort(cmp=vuln.version_compare)
        yield {'name': e.get('name'), 'produce': prod, 'vers': vers,
               'severity': e.get('severity'), 'published': e.get('published'),
               'desc': desc, 'refs': refs}

def getlist():
    r = download_cached(URL,
                        timeout=utils.cfg.getfloat('main', 'timeout'),
                        retry=utils.cfg.getint('main', 'retry'))
    if not r:
        logging.info('url not modify, passed.')
        return []
    cvelist = list(parse_nvdcve(cStringIO.StringIO(r)))
    logging.debug('cvelist length %d' % len(cvelist))
    return cvelist
