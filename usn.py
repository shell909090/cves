#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2015-06-09
@author: shell.xu
'''
import logging, cStringIO
from lxml import etree
from lxml.cssselect import CSSSelector
import utils

NS  = 'http://www.w3.org/2005/Atom'
URL = 'http://www.ubuntu.com/usn/rss.xml'

sel_packages = CSSSelector('dl dd>a')
sel_cves = CSSSelector('p>a')

def get_details(tree):
    run = False
    texts = []
    for e in tree.iter():
        if e.tag == 'h3':
            run = e.text == 'Details'
        elif run:
            s = etree.tostring(e, method='text', encoding='UTF-8').strip()
            texts.append(s)
    return ' '.join(texts)

def get_cves(tree):
    for cve in sel_cves(tree):
        href = cve.get('href')
        if href.startswith('http://people.ubuntu.com/~ubuntu-security/cve'):
            yield (cve.text, href)
    return

def parse_usn(e):
    name, title = e.find('title').text.split(':', 1)
    name, title = name.strip(), title.strip()
    link = e.find('link').text

    tree = etree.HTML(e.find('description').text)
    produces = [p.text for p in sel_packages(tree)]

    details = get_details(tree)
    descbuf = cStringIO.StringIO()
    descbuf.write('    {}\n    {}\n    * {}\n'.format(title, details, link))
    for cve, url in get_cves(tree):
        descbuf.write('    # {}\n    * {}\n'.format(cve, url))

    return {'name': name, 'produces': '\n'.join(produces), 'desc': descbuf.getvalue()}

def parse_list(cache):
    r = utils.download(URL)
    if cache and r.status_code == 304:
        logging.info('usn url not modify, passed.')
        return

    logging.debug('parse usn xml')
    tree = etree.fromstring(r.content)
    for e in tree.iterfind('channel/item', namespaces={'ns': NS}):
        yield parse_usn(e)

def getlist(cache):
    try:
        usnlist = list(parse_list(cache))
        logging.info('usnlist length {}'.format(len(usnlist)))
        return usnlist
    except Exception as err:
        import traceback
        logging.error(traceback.format_exc())
        return []
