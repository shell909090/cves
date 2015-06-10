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
    r = utils.download(dsaurl)
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
    descbuf.write('    * {}\n'.format(dsaurl))

    return {'name': name, 'produces': '\n'.join(prods), 'desc': descbuf.getvalue()}

def parse_list(cache):
    r = utils.download_cached(URL)
    if cache and r.status_code == 304:
        logging.info('dsa url not modify, passed.')
        return

    logging.debug('parse dsa xml')
    tree = etree.fromstring(r.content)
    for e in tree.iterfind('ns:item/ns:link', namespaces={'ns': NS}):
        r = parse_dsa(e.text)
        if r: yield r

def getlist(cache):
    try:
        dsalist = list(parse_list(cache))
        logging.info('dsalist length {}'.format(len(dsalist)))
        return dsalist
    except Exception as err:
        import traceback
        logging.error(traceback.format_exc())
        return []
