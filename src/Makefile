CFILE := $(shell ls *.c 2> /dev/null)
OFILE := $(patsubst %.c,%.o,$(CFILE))
CC=gcc
CFLAGS=-std=gnu99 -g -O0 -Wall
#CFLAGS=-std=gnu99 -g -O0 -Wall -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes \
# -Wmissing-declarations -Wpointer-arith -Wwrite-strings

default: igmpproxy

all: igmpproxy

%.o : %.c
	$(CROSS)$(CC) $(CFLAGS) -I. -c -o $@ $<

#igmpproxy : igmpproxy.o config.o confread.o request.o udpsock.o mcgroup.o rttable.o \
#			igmp.o ifvc.o callout.o kern.o syslog.o lib.o mroute-api.o list.o

igmpproxy: $(OFILE) Makefile
	$(CROSS)$(CC) $(CFLAGS) -o $@ $(OFILE)


config_rule:

distclean : clean  uninstall
clean:
	rm -f igmpproxy *.o

install install_rule: igmpproxy
	install -m 755 $^ $(TI_filesystem_path)/bin
	$(CROSS)strip $(TI_filesystem_path)/bin/$^

uninstall uninstall_rule:
	rm -f  $(TI_filesystem_path)/bin/igmpproxy

