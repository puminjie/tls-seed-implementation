export V?=0

include buildenv.mk

.PHONY: all
all:
	make -f tz_u.mk CROSS_COMPILE=$(HOST_CROSS_COMPILE)
	make -C ta CROSS_COMPILE=$(TA_CROSS_COMPILE)

.PHONY: clean
clean:
	make -f tz_u.mk clean
	make -C ta clean

install: 
	./generate_test_files.sh
	sudo cp tz_seed /var/www/html
	sudo cp ta/4b2f44a9-b840-448f-90a4-170930dffb75.ta /var/www/html
	sudo cp lib/host/libcrypto.a /var/www/html/libcrypto.a
	sudo cp lib/host/libssl.a /var/www/html/libssl.a
	sudo cp download/download.tar /var/www/html
