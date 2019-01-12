all:
	sudo apt-get install libpcap-dev
	gcc HNU.c -lpcap -lpthread -o lhnu
	gcc hnu_cli.c -lrt -o hnu_cli
clean:
	rm HNU
