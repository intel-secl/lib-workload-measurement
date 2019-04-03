#
# Root Makefile
# Arvind Rawat
#
#
WMLROOT=..
OBJROOTR=$(WMLROOT)/build
BIN=$(WMLROOT)/bin
LIB=$(WMLROOT)/lib

RMOBJROOTR=$(WMLROOT)/build/
RMBIN=$(WMLROOT)/bin
RMLIB=$(WMLROOT)/lib

BUILD_TARGETS=  makedirstructure \
				wml-g  \
				measure-g

TARGETS=$(BUILD_TARGETS) clean

.PHONY: $(TARGETS)

all: $(BUILD_TARGETS)

makedirstructure:
	mkdir -p $(BIN)
	mkdir -p $(LIB)
	mkdir -p $(OBJROOTR)

measure-g:
	mkdir -p $(OBJROOTR)/measureobjects
	$(MAKE) -C measure debug=$(debug) -f measure-g.mak

wml-g:
	mkdir -p $(OBJROOTR)/wmlobjects
	$(MAKE) -C wml debug=$(debug) -f wml-g.mak

clean:
	rm -f $(RMOBJROOTR)/*objects/*.o
	rm -f $(RMOBJROOTR)/*objects/*.s
	rm -f $(RMOBJROOTR)/*.o
	rm -f $(RMOBJROOTR)/*/*.o
	rm -f $(RMOBJROOTR)/*/*.s
	rm -rf $(RMOBJROOTR)/*
	rm -f $(RMBIN)/*.exe
	rm -f $(RMBIN)/*
	rm -f $(RMLIB)/*.so
