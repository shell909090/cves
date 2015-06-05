#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2015-06-05
@author: shell.xu
'''
import os, sys

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

re_split = re.compile('[^a-zA-Z0-9]+')
def merge_prod(prod):
    '''
    split prod name into words, so we can cross compare those words with vuln's name
    '''
    rslt = {}
    for k, v in prod:
        for n in set(re_split.split(k)):
            rslt.setdefault(n, []).append(v)
    for k, v in rslt.items():
        if 'all' in v: rslt[k] = 'all'
    return rslt

class ChanVulns(object):

    def __init__(self, chan, dryrun):
        self.chan, self.dryrun = chan, dryrun
        self.severity = db.SM[s.lower()]
        self.vulns, self.readed, self.prod = [], set(), []
        for p in sess.query(Produces).filter_by(chan=self.chan):
            self.prod.append((p.prod, p.ver))
        self.prod = merge_prod(self.prod)
        if not dryrun:
            for r in utils.sess.query(Readed).filter_by(chan=chan):
                self.readed.add(r.cve)

    def f_severity(self, v):
        if v.get('severity') is None:
            logging.warning('severity of valu is none: %s' % str(v))
            return True
        return db.SM[v['severity'].lower()] >= m

    def f_readed(self, v):
        return v['name'] not in self.readed

    def f_vuln(self, vuln):
        for n in set(re_split.split(vuln['produce'])):
            if n not in self.prod: continue
            vs = prod[n]
            if vs == 'all': return True
            vers = vuln['vers']
            for v in vs:
                if version_compare(v, vers[-1]) <= 0 and version_compare(v, vers[0]) > 0:
                    logging.debug('%s(%s) in %s - %s' % (vuln['produce'], v, vers[0], vers[-1]))
                    return True

    def update(self, sources):
        logging.info('chan %s in new source' % self.chan.id)
        src = filter(self.f_severity, src)
        src = filter(self.f_readed, src)
        src = filter(vuln(merge_prod(prod)), src)
        for vuln in src:
            self.vulns.append(vuln)

    def format(self):
        stream = cStringIO.StringIO()
        for vuln in self.vulns:
            stream.write('%s [%s] %s (%s to %s)\n' % (
                vuln['name'], vuln['severity'], vuln['produce'],
                vuln['vers'][0], vuln['vers'][-1]))
            stream.write('    %s\n' % vuln['desc'])
            for r in vuln['refs']: stream.write('    * %s\n' % r)
            stream.write('\n')
        return stream.getvalue().strip()

    def sendmail(self, mailsrv, sender):
        body = self.format()
        if not body: return
        if self.dryrun:
            print body
            return
        msg = MIMEText(body)
        msg['Subject'] = 'CVE for %s' % cv.chan.name
        msg['From'] = sender
        # FIXME: cc list
        msg['To'] = cv.chan.user.username
        logging.info('send email to %s' % msg['To'])
        mailsrv.sendmail(sender, msg['To'].split(','), msg.as_string())

    def readed(self,):
        if self.dryrun: return
        for vuln in self.vulns:
            utils.sess.add(Readed(chan=self.chan, cve=vuln['name']))
        utils.sess.commit()

def run(mailsrv, dryrun=False):
    sender = utils.cfg.get('email', 'mail')
    cvs = [ChanVulns(chan, dryrun) for chan in utils.sess.query(Channels)]
    for src in [cves.getlist,]:
        vulns = src()
        for cv in cvs: cv.update(vulns)
    for cv in cvs:
        # send in mail
        cv.sendmail(mailsrv, sender, dryrun)
        self.readed()
