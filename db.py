#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-07-31
@author: shell.xu
'''
import os, sys, time, random, string
import bcrypt, sqlalchemy, cves
from sqlalchemy import desc, or_, Table, Column, Integer, String
from sqlalchemy import DateTime, Boolean, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base

__all__ = [
    'crypto_pass', 'check_pass', 'gentoken',
    'Users', 'Channels', 'Produces', 'Readed']

Base = declarative_base()

def crypto_pass(p):
    return bcrypt.hashpw(p, bcrypt.gensalt())

def check_pass(p, h):
    return bcrypt.hashpw(p, h) == h

def gentoken(l):
    return ''.join([random.choice(string.letters) for i in xrange(l)])

class Users(Base):
    __tablename__ = 'users'
    username = Column(String(40), primary_key=True)
    passwd = Column(String, nullable=False)
    inviter = Column(String(40))
    token = Column(String)
    token_ts = Column(Integer)

    def uptoken(self):
        if self.token_ts and time.time() - self.token_ts < 3600: return
        self.token = gentoken(30)
        self.token_ts = time.time()
        return True

    def renew_pass(self, token, password):
        if time.time() - self.token_ts > 3600 or self.token != token: return
        self.token = ''
        self.token_ts = 0
        self.passwd = crypto_pass(password)

class Channels(Base):
    __tablename__ = 'channels'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    username = Column(String, ForeignKey('users.username'))
    user = relationship("Users")
    severity = Column(String)

    def gen_body(self, src, sess, dryrun=False):
        prod, readed = {}, set()
        for p in sess.query(Produces).filter_by(chan=self):
            prod[p.prod] = p.ver
        for r in sess.query(Readed).filter_by(chan=self):
            readed.add(r.cve)
        body, newreaded = cves.gen_chan_body(
            src, prod, self.id, readed, self.severity)
        if not dryrun:
            for name in newreaded:
                sess.add(Readed(chan=self, cve=name))
            sess.commit()
        return body

    def import_stream(self, stream):
        for line in stream:
            line = line.strip()
            if not line: continue
            prod, ver = line.split(' ', 1)
            yield Produces(chan=self, prod=prod, ver=ver)

class Produces(Base):
    __tablename__ = 'produces'
    id = Column(Integer, primary_key=True)
    chanid = Column(Integer, ForeignKey('channels.id'))
    chan = relationship("Channels", backref='prods')
    prod = Column(String)
    ver = Column(String)

class Readed(Base):
    __tablename__ = 'readed'
    id = Column(Integer, primary_key=True)
    chanid = Column(Integer, ForeignKey('channels.id'))
    chan = relationship("Channels", backref='readed')
    cve = Column(String)
    ts = Column(DateTime, server_default=sqlalchemy.text('CURRENT_TIMESTAMP'))

def main():
    import getopt, subprocess, ConfigParser
    optlist, args = getopt.getopt(sys.argv[1:], 'bhnu')
    optdict = dict(optlist)
    if '-h' in optdict:
        print main.__doc__
        return

    cfg = cves.getcfg(['cves.ini', '/etc/cves.ini'])
    cves.initlog(cfg.get('log', 'level'), cfg.get('log', 'file'))
    engine = sqlalchemy.create_engine(cfg.get('db', 'url'))
    sess = sqlalchemy.orm.sessionmaker(bind=engine)()

    if '-b' in optdict:
        Base.metadata.create_all(engine)
    elif '-u' in optdict:
        u = Users(username=args[0], passwd=crypto_pass(args[1]))
        sess.add(u)
        sess.commit()
    elif '-n' in optdict:
        ch = Channels(name=args[0], username=args[1], severity=args[2])
        sess.add(ch)
        for p in ch.import_stream(sys.stdin): sess.add(p)
        sess.commit()

if __name__ == '__main__': main()
