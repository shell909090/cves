#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2013-12-20
@author: shell.xu
'''
import logging, cStringIO
from lxml import etree
import utils

NS  = 'http://nvd.nist.gov/feeds/cve/1.2'
URL = 'http://nvd.nist.gov/download/nvdcve-recent.xml'

def parse_nvdcve():
    # r = utils.download_cached(URL)
    # if not r:
    #     logging.info('cve url not modify, passed.')
    #     return

    with open('nvdcve-recent.xml', 'rb') as fi:
        tree = etree.parse(fi)

    logging.debug('parse cve xml')
    # tree = etree.fromstring(r.content)
    for e in tree.iterfind('ns:entry', namespaces={'ns': NS}):
        vs = e.find('ns:vuln_soft', namespaces={'ns': NS})
        if vs is None: continue
        prods = [p.get('name').lower() for p in vs]

        desc = e.find('ns:desc', namespaces={'ns': NS})[0].text
        refs = [ref.get('url') for ref in e.find('ns:refs', namespaces={'ns': NS})]

        descbuf = cStringIO.StringIO()
        descbuf.write('    %s\n' % desc)
        for r in refs:
            descbuf.write('    * %s\n' % r)
        descbuf.write('\n')

        yield {'name': e.get('name'), 'severity': e.get('severity'),
               'produces': '\n'.join(prods), 'desc': descbuf.getvalue()}

def getlist():
    cvelist = list(parse_nvdcve())
    logging.info('cvelist length {}'.format(len(cvelist)))
    return cvelist
