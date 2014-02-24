#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2011-05-05
@author: shell.xu
@version: 0.8.1
'''
import os, sys, web, base64, getopt
from os import path
from web.contrib.template import render_mako
import utils
from mgr import *

cfg = utils.getcfg(['cves.conf', '/etc/cves.conf'])
web.config.cfg = cfg
DEBUG = not path.isfile('RELEASE')
web.config.debug = DEBUG
web.config.rootdir = path.dirname(__file__)
web.config.db = web.database(**dict(cfg.items('db')))
web.config.render = render_mako(
    directories = ['templates'],  imports = ['import web'],
    default_filters = ['decode.utf8'], filesystem_checks = DEBUG,
    module_directory = None if DEBUG else '/tmp/mako_modules',
    input_encoding = 'utf-8', output_encoding = 'utf-8')

def serve_file(filepath):
    class ServeFile(object):
        def GET(self):
            with open(filepath, 'rb') as fi:
                return fi.read()
    return ServeFile

def serve_path(dirname):
    class ServePath(object):
        def GET(self, p):
            with open(path.join(dirname, p), 'rb') as fi:
                return fi.read()
    return ServePath

urls = (
    '/users/', UserList,
    r'/user/(\d*)', ChanList,
    r'/chan/add/(\d*)', ChanAdd,
    r'/chan/del/(\d*)', ChanDel,
    r'/chan/sev/(\d*)', ChanSeverity,
    r'/chan/edit/(\d*)', ChanEdit,
    r'/chan/import/(\d*)', ChanImport,
    r'/chan/export/(\d*)', ChanExport,
    r'/chan/cleanup/(\d*)', ChanCleanup,
    r'/chan/run/(\d*)', ChanRun,
)
app = web.application(urls)

def main():
    web.config.users = dict(cfg.items('users'))
    utils.initlog(cfg.get('log', 'loglevel'), cfg.get('log', 'logfile'))
    if web.config.rootdir: os.chdir(web.config.rootdir)

    optlist, args = getopt.getopt(sys.argv[1:], 'dhp:')
    optdict = dict(optlist)
    if '-h' in optdict:
        print main.__doc__
        return

    port = int(optdict.get('-p') or cfg.get('main', 'port') or 9872)
    addr = (cfg.get('main', 'addr'), cfg.getint('main', 'port'))
        
    from gevent.pywsgi import WSGIServer
    print 'service port :%d' % cfg.getint('main', 'port')
    WSGIServer(addr, app.wsgifunc()).serve_forever()

if __name__ == '__main__': main()
else: application = app.wsgifunc()
