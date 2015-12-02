ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

RTE_TARGET ?= x86_64-default-linuxapp-gcc

USTACK_TARGET = $(shell pwd)

CC = gcc
#CFLAGS= -Wall  -g -O2 -fno-strict-aliasing  -static -m64
#CFLAGS= -Wall  -g -O2 -fno-strict-aliasing -m64
#CFLAGS= -Wall -g -pg -O2 -fno-strict-aliasing -m64
CFLAGS= -Wall -g -O2 -static -m64  -fno-strict-aliasing #-fno-omit-frame-pointer #--eh-frame-hdr
#LFLAGS= -Wall  -g -O2 -m64
LFLAGS= -Wall -m64

SRCDIR1=./net/
SRCDIR2=./app/
SRC=$(shell find $(SRCDIR1) -name '*.c')
SRC+=$(shell find $(SRCDIR2) -name '*.c')
OBJ=$(SRC:%.c=%.o)

#INCDIR=./include
#INC=$(shell find $(INCDIR) -name '*.h' )


LIBS = -Wl,--start-group \
		   -lrte_pmd_ixgbe \
		   -lethdev \
		   -lrte_eal \
		   -lrte_lpm  \
		   -lrte_mbuf \
		   -lrte_cmdline \
		   -lrte_hash \
		   -lrte_malloc \
		   -lrte_mempool \
		   -lrte_ring \
		   -lrte_timer \
		   -lpthread \
		   -lrte_pmd_ring\
		   -Wl,--end-group 

INCLUDES = -I${RTE_SDK}/${RTE_TARGET}/include \
		   -I${USTACK_TARGET}/include \
	 -include ${RTE_SDK}/${RTE_TARGET}/include/rte_config.h \

EXE = US_APP

all:$(EXE)

$(EXE):$(OBJ)
	$(CC) $(CFLAGS) -o $(EXE) $(OBJ) $(INC) -L${RTE_SDK}/${RTE_TARGET}/lib  ${LIBS} -lm -lrt #-lprofiler 
%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@ $(INCLUDES) 

clean:
	echo $(EXE)
	rm -f *.o $(EXE) $(OBJ)

.PHONY: all clean
