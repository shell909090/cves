#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-02-18
@author: shell.xu
'''
import time, logging, cStringIO
import cves

def version_compare(v1, v2):
    vs1 = v1.split('.'); vs2 = v2.split('.')
    for i in xrange(min(len(vs1), len(vs2))):
        try: ivs1, ivs2 = int(vs1[i]), int(vs2[i])
        except ValueError: ivs1, ivs2 = None, None
        if ivs1 is None or ivs2 is None:
            if vs1[i] < vs2[i]: return -1
            if vs1[i] > vs2[i]: return 1
        else:
            if ivs1 < ivs2: return -1
            if ivs1 > ivs2: return 1
    if len(vs1) < len(vs2): return -1
    if len(vs1) > len(vs2): return 1
    return 0

SM = {'high': 3, 'medium': 2, 'low': 1}
def severity_filter(s):
    return lambda v: SM[v['severity'].lower()] >= SM[s.lower()]

def getcves(cfg):
    urls = ((k, v) for k, v in cfg.items('urls') if k.startswith('url'))
    urls = map(lambda x:x[1], sorted(urls, key=lambda x:x[0]))
    cves.retry = cfg.getint('main', 'retry')
    cves.timeout = cfg.getfloat('main', 'timeout')
    return cves.getcves(urls, cfg.get('urls', 'tmp'))

class Chan(object):

    def __init__(self, db, dbobj, dryrun=False):
        self.db, self.dbobj, self.id = db, dbobj, dbobj['id']
        logging.info('new chan %s' % self.id)
        self.dryrun = dryrun
        self.prod, self.readed = {}, set()
        for i in self.db.select(
                'produces', what='produce, version',
                where='channel=$cid', vars={'cid': self.id}):
            self.prod[i['produce']] = str(i['version'])
        for i in self.db.select(
                'readed', what='cvename',
                where='channel = $cid', vars={'cid': self.id}):
            self.readed.add(i['cvename'])

    def vuln(self, cves):
        for cve in cves:
            if cve['name'] in self.readed: continue
            for p, v1 in self.prod.iteritems():
                if cve['produce'].find(p) == -1: continue
                if v1 == 'all':
                    yield (cve, cve['vers'])
                    continue
                for v in cve['vers']:
                    if version_compare(v1, v) <= 0:
                        logging.debug('%s %s %s' % (p, v1, v))
                        yield (cve, v)
                        break

    def format(self, rslt, stream):
        for cve, v in rslt:
            stream.write('\t%s [%s] to %s(%s)\n' % (
                cve['name'], cve['severity'], cve['produce'], v))
            stream.write('\t%s\n' % cve['desc'])
            for r in cve['refs']: stream.write('\t * %s\n' % r)
            stream.write('\n')
            if not self.dryrun:
                self.db.insert('readed', channel=self.id,
                          cvename=cve['name'], uptime=int(time.time()))

    def geninfo(self, src):
        src = filter(severity_filter(self.dbobj['severity']), src)
        buf = cStringIO.StringIO()
        self.format(self.vuln(src), buf)
        return buf.getvalue().strip()
