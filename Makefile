.PHONY: all aix solaris

all: aix solaris test

aix:
	cd src && make aix

solaris:
	cd src && make solaris

test:
	cd src && make test

clean:
	cd src && make clean
