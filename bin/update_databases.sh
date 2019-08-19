#!/bin/bash

#
# Update IRR-Stuff
#



cd /mount/storage/db/irr
for f in *.db*; do mv "$f" old/""${f%}"_$(date '+%Y_%m_%d-%H')"; done

wget -4  http://ftp.afrinic.net/pub/dbase/afrinic.db.gz
wget -4  ftp://ftp.arin.net/pub/rr/arin.db
wget -4  ftp://ftp.radb.net/radb/dbase/radb.db.gz
wget -4  ftp://ftp.ripe.net/ripe/dbase/split/ripe.db.route.gz
wget -4  ftp://ftp.ripe.net/ripe/dbase/split/ripe.db.route6.gz
wget -4  ftp://ftp.apnic.net/pub/apnic/whois/apnic.db.route.gz
wget -4  ftp://ftp.apnic.net/pub/apnic/whois/apnic.db.route6.gz

gunzip ./*

cd ../rpki
for f in *; do mv "$f" old/""${f%}"_$(date '+%Y_%m_%d-%H')"; done
routinator vrps > current

cd /home/debian/ba/bin/
/home/debian/ba/bin/luke_dbwalker.pl
systemctl reload ris-live
