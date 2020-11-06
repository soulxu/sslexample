BINS = sslserver sslclient sslclient-async
SERVER_OBJS = server.o
CLIENT_OBJS = client.o
CLIENT_ASYNC_OBJS = client-async.o

all: $(BINS)

sslserver: $(SERVER_OBJS)
	gcc server.c -o sslserver -lssl -lcrypto 

sslclient: $(CLIENT_OBJS)
	gcc client.c -o sslclient -lssl -lcrypto 

sslclient-async: $(CLIENT_ASYNC_OBJS)
	gcc client-async.c -o sslclient-async -lssl -lcrypto
.PHONY: clean

clean:
	rm $(BINS) $(SERVER_OBJS) $(CLIENT_OBJS) $(CLIENT_ASYNC_OBJS)
