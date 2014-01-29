#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2011-05-05
@author: shell.xu
@version: 0.8.1
'''
import os, sys, web, base64, getopt
from os import path
import utils

cfg = utils.getcfg(['cves.conf', '/etc/cves.conf'])
DEBUG = not path.isfile('RELEASE')
web.config.debug = DEBUG
web.config.rootdir = path.dirname(__file__)

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
    '/static/(.*)', serve_path('static/'),
    # info actions
    '/', serve_file('static/home.html'),
    '/list.json', lxcweb.ListJson,
    '/info/(.*).json', lxcweb.InfoJson,
    '/ps/(.*).json', lxcweb.PsJson,
    '/ps/.*', serve_file('static/ps.html'),
    '/config/(.*).json', lxcweb.ConfigJson,
    '/fstab/(.*).json', lxcweb.FstabJson,
    '/config/.*', serve_file('static/config.html'),

    # image actions
    '/clone/(.*)/(.*)', lxcweb.Clone,
    '/create/(.*)', lxcweb.Create,
    '/destroy/(.*)', lxcweb.Destroy,
    '/merge/(.*)', lxcweb.Merge,

    # container actions
    '/start/(.*)', lxcweb.Start,
    '/stop/(.*)', lxcweb.Stop,
    '/shutdown/(.*)', lxcweb.Shutdown,
    '/reboot/(.*)', lxcweb.Reboot,
    '/freeze/(.*)', lxcweb.Freeze,
    '/unfreeze/(.*)', lxcweb.Unfreeze,

    # runtime actions
    '/attach/(.*)', lxcweb.Attach,
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

    port = int(optdict.get('-p') or maincfg.get('port') or 9872)
    addr = (cfg.get('main', 'addr'), cfg.getint('main', 'port'))
        
    from gevent.pywsgi import WSGIServer
    print 'service port :%d' % cfg.getint('main', 'port')
    WSGIServer(addr, app.wsgifunc()).serve_forever()

if __name__ == '__main__': main()
else: application = app.wsgifunc()
