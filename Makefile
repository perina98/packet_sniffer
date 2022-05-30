all: ipk-sniffer.c
	@gcc ipk-sniffer.c $(CFLAGS) -o ipk-sniffer -lpcap
