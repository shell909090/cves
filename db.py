#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-07-31
@author: shell.xu
'''
import os, sys, time, random, string
import bcrypt, sqlalchemy, utils, cves
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
    cclist = Column(String)
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

SM = {'high': 3, 'medium': 2, 'low': 1}

class Channels(Base):
    __tablename__ = 'channels'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    username = Column(String, ForeignKey('users.username'))
    user = relationship("Users")
    severity = Column(String)

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

class HttpCache(Base):
    __tablename__ = 'urletags'
    id = Column(Integer, primary_key=True)
    url = Column(String, unique=True)
    etag = Column(String)
    last_change = Column(DateTime, server_default=sqlalchemy.text('CURRENT_TIMESTAMP'))
    cache_file = Column(String)

def download(sess, url, retry=3, timeout=10):
    headers = {}

    ue = sess.query(HttpCache).filter_by(url=url).scalar()
    if ue and path.exists(ue.cache_file):
        logging.debug('etag found: %s' % ue.etag)
        headers['If-None-Match'] = ue.etag
        # TODO: if modified since

    r = utils.download(url, headers, retry, timeout)

    if r.status_code == 304:
        logging.debug('not modify, use cache.')
        with open(ue.cache_file) as fi:
            return fi.read()
    
    if 'Etag' in r.headers:
        if not ue:
            ue = HttpCache()
            sess.add(ue)
        ue.url = url
        ue.etag = r.headers['Etag']
        # ue.last_change = 
        # ue.cache_file = ??
        with open(ue.cache_file, 'wb') as fo:
            fo.write(r.content)
        sess.commit()

    return r.content
