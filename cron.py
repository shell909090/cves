#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2013-12-21
@author: shell.xu
'''
import os, sys, time, sqlite3, logging, cStringIO
from os import path
from datetime import datetime
from email.mime.text import MIMEText
import web
import utils

rootdir = path.dirname(__file__)
os.chdir(rootdir)

cfg = utils.getcfg(['cves.conf', '/etc/cves.conf'])
db = web.database(**dict(cfg.items('db')))

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

class Chan(object):

    def __init__(self, dbobj):
        self.dbobj, self.id = dbobj, dbobj['id']
        logging.info('new chan %s' % self.id)
        self.prod, self.readed = {}, set()
        for i in db.select(
                'produces', what='produce, version',
                where='channel=$cid', vars={'cid': self.id}):
            self.prod[i['produce']] = str(i['version'])
        for i in db.select(
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
            if not cfg.getboolean('main', 'dryrun'):
                db.insert('readed', channel=self.id,
                          cvename=cve['name'], uptime=int(time.time()))

    def genmail(self, sender, src):
        src = filter(severity_filter(self.dbobj['severity']), src)
        buf = cStringIO.StringIO()
        self.format(self.vuln(src), buf)
        body = buf.getvalue().strip()
        if not body.strip(): return

        msg = MIMEText(body)
        msg['Subject'] = 'CVE for %s' % self.dbobj['name']
        msg['From'] = sender
        msg['To'] = self.dbobj['email']
        return msg

def getcves():
    urls = map(
        lambda x:x[1],
        sorted(
            ((k, v) for k, v in cfg.items('urls') if k.startswith('url')),
            key=lambda x:x[0]))
    import cves
    cves.cfg = cfg
    return list(cves.getcves(urls))

def main():
    utils.initlog(cfg.get('log', 'loglevel'), cfg.get('log', 'logfile'))
    sender = cfg.get('email', 'mail')
    cvelist = getcves()
    logging.debug('cvelist length %d' % len(cvelist))

    db.query('BEGIN')
    with utils.with_emailconfig(cfg) as srv:
        for i in db.select(
                ['channels', 'users'],
                what='channels.id, name, email, user, severity',
                where='channels.user=users.id'):
            c = Chan(i)
            msg = c.genmail(sender, cvelist)
            if msg:
                if cfg.getboolean('main', 'dryrun'):
                    print msg.as_string()
                else:
                    logging.info('send email to %s' % msg['to'])
                    srv.sendmail(sender, msg['To'].split(','), msg.as_string())

    # remove readed record for more then half a year
    db.delete('readed', where='uptime < $ti',
              vars={'ti': int(time.time() - 180 * 86400)})

if __name__ == '__main__': main()
