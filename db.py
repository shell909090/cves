#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-07-31
@author: shell.xu
'''
import time, random, string
import bcrypt, sqlalchemy
from sqlalchemy import Column, Integer, String, DateTime, LargeBinary, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

__all__ = [
    'crypto_pass', 'check_pass', 'gentoken', 'Users', 'Channels', 'Readed']

Base = declarative_base()

def crypto_pass(p):
    return bcrypt.hashpw(p, bcrypt.gensalt())

def check_pass(p, h):
    return bcrypt.hashpw(p, h) == h

def gentoken(l):
    return ''.join([random.choice(string.letters) for _ in xrange(l)])

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
    produces = Column(String)

class Readed(Base):
    __tablename__ = 'readed'
    id = Column(Integer, primary_key=True)
    chanid = Column(Integer, ForeignKey('channels.id'))
    chan = relationship("Channels", backref='readed')
    name = Column(String)
    ts = Column(DateTime, server_default=sqlalchemy.text('CURRENT_TIMESTAMP'))

class HttpCache(Base):
    __tablename__ = 'httpcache'
    url = Column(String, primary_key=True)
    etag = Column(String)
    last_change = Column(DateTime, server_default=sqlalchemy.text('CURRENT_TIMESTAMP'))
    data = Column(LargeBinary)
