#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-07-30
@author: shell.xu
'''
import os, sys, getopt
import web, cves

cfg = cves.getcfg(['cves.conf', '/etc/cves.conf'])
db = web.database(**dict(cfg.items('db')))

def main():
    global optdict
    optlist, args = getopt.getopt(sys.argv[1:], 'hu')
    optdict = dict(optlist)
    if '-h' in optdict:
        print main.__doc__
        return

    cves.initlog(cfg.get('log', 'level'), cfg.get('log', 'file'))

    if '-u' in optdict:
        db.insert('users', email=args[0], passwd=cves.crypto_pass(args[1]))
    
if __name__ == '__main__': main()
