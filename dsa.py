#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2015-06-08
@author: shell.xu
'''
import logging, cStringIO
from lxml import etree
from lxml.cssselect import CSSSelector
import utils

NS  = 'http://purl.org/rss/1.0/'
URL = 'https://www.debian.org/security/dsa'

sel_title = CSSSelector('head title')
sel_packages = CSSSelector('div#content dd a')

def parse_dsa(dsaurl):
    r = utils.download_cached(dsaurl)
    if not r:
        logging.info('dsa info url ({}) not modify, passed.'.format(dsaurl))
        return

    tree = etree.HTML(r.content)

    e = sel_title(tree)[0]
    title = e.text.split('--')[-1]
    name = title.strip().split(' ', 1)[0]

    produces, cves = [], []
    for e in sel_packages(tree):
        href = e.get('href')
        if href.startswith('https://packages.debian.org/'):
            produces.append((e.text, href))
        elif href.startswith('https://security-tracker.debian.org/'):
            cves.append((e.text, href))
    prods = [p for p, _ in produces]

    descbuf = cStringIO.StringIO()
    for _, url in produces:
        descbuf.write('    * {}\n'.format(url))
    for cve, url in cves:
        descbuf.write('    # {}\n    * {}\n'.format(cve, url))
    descbuf.write('    * {}\n\n'.format(dsaurl))

    return {'name': name, 'produces': '\n'.join(prods), 'desc': descbuf.getvalue()}

def parse_list():
    r = utils.download_cached(URL)
    if not r:
        logging.info('dsa url not modify, passed.')
        return

    logging.debug('parse dsa xml')
    tree = etree.fromstring(r.content)
    for e in tree.iterfind('ns:item/ns:link', namespaces={'ns': NS}):
        r = parse_dsa(e.text)
        if r: yield r

def getlist():
    dsalist = list(parse_list())
    logging.info('dsalist length {}'.format(len(dsalist)))
    return dsalist
