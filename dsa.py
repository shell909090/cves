#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2015-06-08
@author: shell.xu
'''
import logging, cStringIO
import utils, vuln
from lxml import etree
from lxml.cssselect import CSSSelector

NS  = 'http://purl.org/rss/1.0/'
URL = 'https://www.debian.org/security/dsa'

sel_title = CSSSelector('head title')
sel_packages = CSSSelector('div#content dd a')

def parse_dsa(url):
    r = utils.download(url)
    # r = utils.download_cached(url,
    #                     timeout=utils.cfg.getfloat('main', 'timeout'),
    #                     retry=utils.cfg.getint('main', 'retry'))
    if not r:
        logging.info('url not modify, passed.')
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
    descbuf.write('    * {}\n\n'.format(url))

    return {'name': name, 'produces': '\n'.join(prods), 'desc': descbuf.getvalue()}

def parse_list(stream):
    logging.debug('parse dsa xml')
    tree = etree.parse(stream)
    for e in tree.iterfind('ns:item/ns:link', namespaces={'ns': NS}):
        r = parse_dsa(e.text)
        if r: yield r

def getlist():
    # r = utils.download_cached(URL,
    #                     timeout=utils.cfg.getfloat('main', 'timeout'),
    #                     retry=utils.cfg.getint('main', 'retry'))
    # if not r:
    #     logging.info('url not modify, passed.')
    #     return []
    with open('dsa.xml', 'rb') as fi:
        dsalist = list(parse_list(fi))
        # dsalist = list(parse_list(r.raw))
    logging.info('dsalist length {}'.format(len(dsalist)))
    return dsalist
    
def main():
    import pprint, logging
    logging.basicConfig(level='DEBUG')
    pprint.pprint(getlist())

if __name__ == '__main__': main()
