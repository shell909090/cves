#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2015-06-05
@author: shell.xu
'''
import re, logging, cStringIO
from email.mime.text import MIMEText
import utils, db

re_split = re.compile('[^a-zA-Z0-9]+')
def make_prod_keywords(prods):
    '''
    assume prod is a list of produces
    split every element to keywords
    accumulate keywords into keyword set.
    '''
    rslt = set()
    for k in prods:
        rslt |= set(re_split.split(k))
    return rslt

class ChanVulns(object):

    def __init__(self, chan, dryrun):
        self.chan, self.dryrun = chan, dryrun
        self.severity = db.SM[chan.severity.lower()]
        self.vulns, self.readed = {}, set()
        self.prod_kw = make_prod_keywords(self.chan.produces.splitlines())
        if not dryrun:
            for r in utils.sess.query(db.Readed).filter_by(chan=chan):
                self.readed.add(r.name)

    def f_severity(self, v):
        if 'severity' not in v: return True
        return db.SM[v['severity'].lower()] >= self.severity

    def f_readed(self, v):
        return v['name'] not in self.readed

    def f_vuln(self, v):
        for kw in self.prod_kw:
            if kw in v['produces']: return True

    def update(self, vulns):
        vulns = filter(self.f_vuln, vulns)
        logging.debug('chan {} in new source {}'.format(self.chan.id, len(vulns)))

        vulns = filter(self.f_severity, vulns)
        logging.debug('chan {} {} after severity.'.format(self.chan.id, len(vulns)))

        vulns = filter(self.f_readed, vulns)
        logging.debug('chan {} {} after readed.'.format(self.chan.id, len(vulns)))

        for v in vulns:
            self.vulns[v['name']] = v

    def format(self):
        stream = cStringIO.StringIO()
        for vuln in self.vulns.values():
            stream.write('%s %s%s\n%s' % (
                vuln['name'], '[%s] ' % vuln['severity'] if 'severity' in vuln else '',
                vuln['produces'].replace('\n', ';'), vuln['desc']))
        return stream.getvalue().strip()

    def sendmail(self, mailsrv, sender):
        body = self.format()
        if not body: return
        if self.dryrun:
            print body
            return
        msg = MIMEText(body)
        msg['Subject'] = 'CVE for %s' % self.chan.name
        msg['From'] = sender
        tolist = [self.chan.user.username]
        if self.chan.user.cclist:
            tolist.extend(self.chan.user.cclist.splitlines())
        msg['To'] = ','.join(tolist)
        logging.info('send email to ' + msg['To'])
        mailsrv.sendmail(sender, msg['To'].split(','), msg.as_string())

    def mark_readed(self):
        if self.dryrun: return
        for vuln in self.vulns:
            utils.sess.add(db.Readed(chan=self.chan, cve=vuln['name']))
        utils.sess.commit()

def run(mailsrv, dryrun=False):
    import cve, usn, dsa
    sender = utils.cfg.get('email', 'mail')
    cvs = [ChanVulns(chan, dryrun) for chan in utils.sess.query(db.Channels)]
    # dsa.getlist
    for src in [cve.getlist, usn.getlist]:
        vulns = src()
        for cv in cvs: cv.update(vulns)
    for cv in cvs:
        # send in mail
        cv.sendmail(mailsrv, sender)
        cv.mark_readed()
