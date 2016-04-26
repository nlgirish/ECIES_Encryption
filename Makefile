# define the C compiler to use
CC = gcc

LOGS = -D__DEBUG
CFLAGS = -c -g -Wall

INCLUDES = -I .

SRCS =  ecies.c  keys.c  secure.c
ASRCS =  example.c 
CSRCS =  client.c
SSRCS =  server.c

OBJS = $(SRCS:.c=.o)
AOBJS = $(ASRCS:.c=.o)
COBJS = $(CSRCS:.c=.o)
SOBJS = $(SSRCS:.c=.o)

SHARED_OBJS = -lssl -lcrypto

APP = testApp
CLI = client
SER = server

.PHONY: depend clean

all:    $(CLI) $(SER)
	@echo all applications are compiled
cli:    $(CLI)
	@echo client application has been compiled
ser:    $(SER)
	@echo server application has been compiled

$(CLI): $(OBJS) $(COBJS) 
	$(CC) $(OBJS) $(COBJS) -o $(CLI) $(SHARED_OBJS) 
$(SER): $(OBJS) $(SOBJS) 
	$(CC) $(OBJS) $(SOBJS) -o $(SER) $(SHARED_OBJS) 
$(APP): $(OBJS) $(AOBJS) 
	$(CC) $(OBJS) $(AOBJS) -o $(APP) $(SHARED_OBJS) 

$(COBJS): $(CSRCS)
	$(CC) $(LOGS) $(CFLAGS) $(INCLUDES) $(CSRCS)
$(SOBJS): $(SSRCS)
	$(CC) $(LOGS) $(CFLAGS) $(INCLUDES) $(SSRCS)
$(AOBJS): $(ASRCS)
	$(CC) $(LOGS) $(CFLAGS) $(INCLUDES) $(ASRCS)
$(OBJS): $(SRCS)
	$(CC) $(LOGS) $(CFLAGS) $(INCLUDES) $(SRCS)
clean:
	$(RM) *.o *~ $(APP) $(CLI) $(SER)

depend: $(SRCS)
	makedepend $(INCLUDES) $^

# DO NOT DELETE THIS LINE -- make depend needs it


