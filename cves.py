#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2013-12-20
@author: shell.xu
'''
import logging, cStringIO
import utils, vuln
from lxml import etree

NS  = 'http://nvd.nist.gov/feeds/cve/1.2'
URL = 'http://nvd.nist.gov/download/nvdcve-recent.xml'

def parse_nvdcve(stream):
    logging.debug('parse cve xml')
    tree = etree.parse(stream)
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
    # r = utils.download_cached(URL,
    #                     timeout=utils.cfg.getfloat('main', 'timeout'),
    #                     retry=utils.cfg.getint('main', 'retry'))
    # if not r:
    #     logging.info('url not modify, passed.')
    #     return []
    with open('nvdcve-recent.xml', 'rb') as fi:
        cvelist = list(parse_nvdcve(fi))
    # cvelist = list(parse_nvdcve(r.raw))
    logging.info('cvelist length {}'.format(len(cvelist)))
    return cvelist

def main():
    import pprint
    pprint.pprint(getlist())

if __name__ == '__main__': main()
