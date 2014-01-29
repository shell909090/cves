### Makefile --- 

## Author: shell@localhost
## Version: $Id: Makefile,v 0.0 2013/12/21 16:59:42 shell Exp $
## Keywords: 
## X-URL: 

build:
	sqlite3 cves.db < cves.sql

clean:
	rm -f cves.db

### Makefile ends here
