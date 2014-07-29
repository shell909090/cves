BEGIN;

create table users (
       id INTEGER PRIMARY KEY,
       email STRING,
       passwd string
);

CREATE TABLE channels (
       id INTEGER PRIMARY KEY,
       'name' STRING,
       'user' REFERENCES users(id),
       severity STRING
);

create table produces (
       channel REFERENCES channels(id),
       produce STRING,
       version TEXT
);

CREATE TABLE readed (
       channel REFERENCES channels(id),
       cvename STRING,
       uptime INTEGER DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (id, email) VALUES (1, 'shell909090@gmail.com');

COMMIT;
