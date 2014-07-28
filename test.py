#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-07-28
@author: shell.xu
'''
import os, sys, pprint
import cves

def main():
    cfg = cves.getcfg(['cves.conf',])
    cves.initlog(cfg.get('log', 'level'), cfg.get('log', 'file'))
    src = list(cves.getcves(cfg))
    body, readed = cves.gen_chan_body(src, {'linux': '3.2', 'ubuntu_linux': '12.04'}, 'id')
    print body
    print readed
    
if __name__ == '__main__': main()
