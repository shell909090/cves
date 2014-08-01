### Makefile --- 

## Author: shell@localhost
## Version: $Id: Makefile,v 0.0 2013/12/21 16:59:42 shell Exp $
## Keywords: 
## X-URL: 

build:
	python db.py -b
	python db.py -u shell909090@gmail.com 123
	python db.py -n 'home' 'shell909090@gmail.com' 'low' < home.list

clean:
	rm -f cves.db

### Makefile ends here
