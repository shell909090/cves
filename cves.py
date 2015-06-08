#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2013-12-20
@author: shell.xu
'''
import logging, cStringIO
import utils, vuln

NS  = 'http://nvd.nist.gov/feeds/cve/1.2'
URL = 'http://nvd.nist.gov/download/nvdcve-recent.xml'

def parse_nvdcve(stream):
    from lxml import etree
    logging.debug('new stream')
    tree = etree.parse(stream)
    for e in tree.getroot():
        vs = e.find('ns:vuln_soft', namespaces={'ns': NS})
        if vs is None: continue
        # logging.debug('vuln {} get in'.format(e.get('name')))
        for p in vs:
            prod = p.get('name').lower()
            vers = [i.get('num') for i in p]

        desc = e.find('ns:desc', namespaces={'ns': NS})[0].text
        refs = [ref.get('url') for ref in e.find('ns:refs', namespaces={'ns': NS})]
        vers.sort(cmp=vuln.version_compare)

        descbuf = cStringIO.StringIO()
        descbuf.write('    %s\n' % desc)
        for r in refs: descbuf.write('    * %s\n' % r)
        descbuf.write('\n')

        yield {'name': e.get('name'), 'produce': prod, 'vers': vers[-1],
               'severity': e.get('severity'), 'desc': descbuf.getvalue()}

def getlist():
    # r = utils.download_cached(URL,
    #                     timeout=utils.cfg.getfloat('main', 'timeout'),
    #                     retry=utils.cfg.getint('main', 'retry'))
    # if not r:
    #     logging.info('url not modify, passed.')
    #     return []
    with open('nvdcve-recent.xml', 'rb') as fi:
        r = fi.read()
    cvelist = list(parse_nvdcve(cStringIO.StringIO(r)))
    logging.info('cvelist length {}'.format(len(cvelist)))
    return cvelist
