target all:
	gcc -g sniffer.c -o sniffer -lpcap
	gcc -g dev-info.c -o dev-info -lpcap
clean:
	rm sniffer dev-info
