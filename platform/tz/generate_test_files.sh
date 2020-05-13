#!/bin/bash
rm download/download.tar
rm download/tz_seed
rm download/4b2f44a9-b840-448f-90a4-170930dffb75.ta

cp lib/host/libssl.* download
cp lib/host/libcrypto.* download
cp tz_seed download
cp ta/4b2f44a9-b840-448f-90a4-170930dffb75.ta download

cd download
tar cvf download.tar *
sudo cp download.tar /var/www/html
