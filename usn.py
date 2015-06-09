#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2015-06-09
@author: shell.xu
'''
import logging, cStringIO
import utils, vuln
from lxml import etree
from lxml.cssselect import CSSSelector

NS  = 'http://www.w3.org/2005/Atom'
URL = 'http://www.ubuntu.com/usn/rss.xml'

sel_packages = CSSSelector('dl dd>a')

def parse_usn(e):
    name, title = e.find('title').text.split(':', 1)
    name, title = name.strip(), title.strip()
    link = e.find('link').text

    tree = etree.HTML(e.find('description').text)
    produces = [p.text for p in sel_packages(tree)]

    desc = '{}\n    * {}\n\n'.format(title, link)
    return {'name': name, 'produces': '\n'.join(produces), 'desc': desc}

def parse_list():
    r = utils.download_cached(URL,
                        timeout=utils.cfg.getfloat('main', 'timeout'),
                        retry=utils.cfg.getint('main', 'retry'))
    if not r:
        logging.info('usn url not modify, passed.')
        return
    logging.debug('parse usn xml')
    tree = etree.parse(r.raw)
    for e in tree.iterfind('channel/item', namespaces={'ns': NS}):
        yield parse_usn(e)

def getlist():
    usnlist = list(parse_list())
    logging.info('usnlist length {}'.format(len(usnlist)))
    return usnlist

def main():
    import pprint, logging
    logging.basicConfig(level='DEBUG')
    pprint.pprint(getlist())

if __name__ == '__main__': main()
