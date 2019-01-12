#include<stdio.h>
#include<stdlib.h>
#include<pcap.h>
#include<string.h>
#include<sys/ipc.h> 
#include<sys/shm.h> 
#include<sys/mman.h>
#include<sys/stat.h>
#include<arpa/inet.h>
#include<signal.h>
#include<unistd.h>
#include<fcntl.h>
#include<time.h>
#include<pthread.h>

#define PIDF "/var/run/hnu.pid"
#define CONF "/etc/hnu.conf"
#define IPM "/etc/hnu_ip_map"
#define IPV4 16

FILE* ipcf;
FILE* ip_map;
FILE* configfile;
FILE* pidfile;
FILE* statistics;
FILE* iplfile;

char device[30];//network interface	
char ebuf[PCAP_ERRBUF_SIZE]; // Error buffer
char dir[24]="/var/log/hnu_statistics_";//statistics file 

int ip_counter = -1;
int bt_counter = -1;
int status = 1;

//*******IPC VAR********
#define HNU_F 1
#define CLI_F 1
char* constructor; //command consturctor
int thid = 1;//thread id
pthread_t ipc_thread;//ipc communication thread
key_t key_hnu_f;//ipc hnu flags
key_t key_cli_f;//ipc cli flags
char* ptr_cli_f;//ipc ptrs...
char* ptr_hnu_f;
int shmid_cli_f;
int shmid_hnu_f;
//*******IPC VAR********

struct ip_account* ip_acc_base;
struct tree * iptree;

char* ip_list_file; // ip list file
char* s_file;// statistics file

pcap_t* handle;//pcap session descriptor

// default snap length (maximum bytes per packet to capture)
#define SNAP_LEN 1518

// ethernet headers are always exactly 14 bytes [1] 
#define SIZE_ETHERNET 14

// Ethernet addresses are 6 bytes 
#define ETHER_ADDR_LEN	6

//Struct for ip statistics
struct ip_account
{
	char ip[IPV4];
	unsigned long long tcp_c; //packet counters
	unsigned long long udp_c;
	unsigned long long icmp_c;
	unsigned long long ip_c;
	unsigned long long unknown_c;
	int dip;//IP IN INT
};

struct node
{
  struct ip_account data;
  struct node * left;
  struct node * right;
};
 
struct tree
{
  struct node * root; 
  int count;         
};

// Ethernet header 
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    // destination host address 
        u_char  ether_shost[ETHER_ADDR_LEN];    // source host address 
        u_short ether_type;                     // IP? ARP? RARP? etc 
};

// IP header 
struct sniff_ip {
        u_char  ip_vhl;                 // version << 4 | header length >> 2 
        u_char  ip_tos;                 // type of service 
        u_short ip_len;                 // total length 
        u_short ip_id;                  // identification 
        u_short ip_off;                 // fragment offset field 
        #define IP_RF 0x8000            // reserved fragment flag 
        #define IP_DF 0x4000            // dont fragment flag 
        #define IP_MF 0x2000            // more fragments flag 
        #define IP_OFFMASK 0x1fff       // mask for fragmenting bits 
        u_char  ip_ttl;                 // time to live 
        u_char  ip_p;                   // protocol 
        u_short ip_sum;                 // checksum 
        struct  in_addr ip_src,ip_dst;  // source and dest address 
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

//TCP header
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               // source port 
        u_short th_dport;               // destination port 
        tcp_seq th_seq;                 // sequence number 
        tcp_seq th_ack;                 // acknowledgement number 
        u_char  th_offx2;               // data offset, rsvd 
	#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 // window 
        u_short th_sum;                 // checksum
        u_short th_urp;                 // urgent pointer 
};

char* concat(const char *s1, const char *s2)
{
	char *result = malloc(strlen(s1)+strlen(s2)+1);//+1 for the null-terminator
	if(result != NULL)
	{
		strcpy(result, s1);
		strcat(result, s2);
		return result;
	}
	else
	{
		fprintf(stderr, "Couldn't allocate memory for new string.");
		exit(0);
	}
}

//*********************************IPC FUNCTIONS**********************************
void read_shared_memory(key_t* key, int* shmid, int size, char* name, char* to_read) 
{
	*key = ftok(name, 'H'); 
     	*shmid = shmget(*key, size, 0666|IPC_CREAT); //shmget returns an identifier in shmid 
    	char *str = (char*) shmat(*shmid,(void*)0,0); //shmat to attach to shared memory  
	strcpy(to_read,str);
	//printf("Data read from memory: %s\n",to_read);  
    	shmdt(str);//detach from shared memory 
    	shmctl(*shmid,IPC_RMID,NULL);// destroy the shared memory
	
}

void write_shared_memory(key_t* key, int* shmid, char* name, char* to_write) 
{
	*key = ftok(name, 'H'); // shmget returns an identifier in shmid
    	*shmid = shmget(*key, strlen(to_write)+1, 0666|IPC_CREAT); 
	char *str = (char*) shmat(*shmid,(void*)0,0); //shmat to attach to shared memory  
	// shmat to attach to shared memory 
    	memcpy(str, to_write, strlen(to_write)+1);
   	//printf("Data written in memory: %s\n",str); 
        shmdt(str); //detach from shared memory  
}
//*********************************IPC FUNCTIONS**********************************

//*********************************BINARY TREE************************************

struct tree * tree_create(void)
{
    struct tree * new_tree = malloc(sizeof * new_tree);
    if (new_tree == NULL) return NULL;
    new_tree->root = NULL;
    new_tree->count = 0;
    return new_tree;
}

static void node_destroy(struct node * search_node)
{
    if(search_node == NULL) return;
    node_destroy(search_node->left);
    node_destroy(search_node->right);
    free(search_node);
} 
 
void tree_destroy(struct tree * search_tree)
{
    node_destroy(search_tree->root);
    free(search_tree);
}

struct ip_account* bin_search(struct tree * search_tree, struct ip_account item)
{
    struct node * search_node;
    search_node = search_tree->root;
    for(;;)
    {
        if (search_node == NULL) return NULL;
        else if (item.dip == search_node->data.dip) return &search_node->data;
        else if (item.dip > search_node->data.dip) search_node = search_node->right;  
        else search_node = search_node->left;  
    }
}

int insert(struct tree * search_tree, struct ip_account item)
{
    struct node * search_node, **new;
 
    new = &search_tree->root;
    search_node = search_tree->root;
 
    for(;;)
    {
        if(search_node == NULL)
        {
            search_node = *new = malloc(sizeof * search_node);
            if(search_node != NULL)
            {
                search_node->data = item;
                search_node->left = search_node->right=NULL;
                search_tree->count++;
                return 1;
            }
            else return 0;
        }
        else if(item.dip == search_node->data.dip) return 2;
	else if(item.dip > search_node->data.dip)
	{
		new = &search_node->right;
          	search_node = search_node->right;
        }
        else
        {
           	 new = &search_node->left;
           	 search_node = search_node->left;
        }
    }
}

//print tree from node
static void walk(const struct node * search_node)
{
    if(search_node == NULL) return;
    walk(search_node->left);
    printf("%s\n", search_node->data.ip);
    walk(search_node->right);
}   
 
//print tree from root
void walk2(const struct tree * my_tree)
{
    walk(my_tree->root);
}
//*********************************BINARY TREE************************************
int ip_account_to_int(char* ip)
{
	int len = strlen(ip);
	int i, sum = 0;
	for(i=0;i<len;i++)
	{
		sum+=(int)ip[i];
	}
	return sum;
}

//********************************DUMP FUNC*********************************
static void make_dump(const struct node * search_node)// make IP statisctics dump
{
	int i;
	int size = sizeof(struct ip_account);
	if(search_node == NULL) return;
 	make_dump(search_node->left);
	char* pt = (char*)(&search_node->data);
	ip_map = fopen(IPM, "a+b");
	if(ip_map != NULL)
	{
		for(i = 0; i < size;i++)
		{
			putc(*pt++, ip_map);
		}
		fclose(ip_map);
	}
	else
	{
		fprintf(stderr,"Couldn't write struct ip_account dump");	
	}
 	//printf("%s\n", search_node->data.ip);
 	make_dump(search_node->right);				
}

void read_dump(void)// read IP statisctics dump
{
	int i;
	char* pt;
	int size = sizeof(struct ip_account);
	int byte_counter = 0;  
	ip_map = fopen(IPM, "rb");
	if(ip_map != NULL)
	{
		while((i=getc(ip_map))!=EOF)
		{
			byte_counter++;		
		}
		if(byte_counter % size == 0)
		{
			ip_acc_base = calloc(byte_counter*size,size);
			ip_counter = byte_counter/size;
			pt = (char*)ip_acc_base;
			fseek(ip_map, 0L, SEEK_SET);
			while((i=getc(ip_map))!=EOF)
			{
				*pt = i;
				pt++;		
			}
		}
		else
		{
			fprintf(stderr, "Bad dump file.");		
		}
		fclose(ip_map);
		for(i=0;i<ip_counter;i++)
		{
			insert(iptree, ip_acc_base[i]);
		}
	}
	else
	{
		fprintf(stderr, "Dump file not exists.");
	}
}
//********************************DUMP FUNC*********************************
int write_pid(int pid)//Write pidfile
{
	pidfile = fopen(PIDF, "w");
	if(pidfile==NULL)
	{ 
		fprintf(stderr, "Couldn't open /var/run/hnu.pid to write.\n");
		return (-1);
	}
	else
	{
		fprintf(pidfile, "%d", pid);
		fclose(pidfile);
		return 1;
	}
}

void read_config(char* device) //Read network interface function
{	
	char* iface;
	configfile = fopen(CONF, "r");
	if(configfile==NULL)
	{
		fprintf(stderr,"Couldn't open /etc/hnu.conf to read.\n");
		device = "eth0"; //default network interface
	}
	else
	{
		fscanf(configfile, "%s", device);
		fclose(configfile);
	}
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	if(ip_counter > 65536) // memory allocate limit!!! 
	{
		free(ip_acc_base);
		ip_counter = 0;	
	}
	_Bool invalid_packet = 0;
	int found = 0;// IP exists in ip_account struct? (FLAG)
	_Bool tcpf = 0, udpf = 0, icmpf = 0, ipf = 0, unkf = 0; //packet found flags
 	const struct sniff_ethernet *ethernet;//Ethernet header
	static char b[IPV4];
	struct ip_account cap_ip_acc;
	struct ip_account* buf_ip_acc;
	const struct sniff_ip *ip; //IP header
	const struct sniff_tcp *tcp;//TCP header 
	const char *payload; // Data from packet
	time_t long_time=header->ts.tv_sec; // timestamp to time_t
	struct tm* timestamp = localtime(&long_time); // convert epoch time to utc format
	char buf[64];
	char* cap_ip;
	
	u_int size_ip;
	u_int size_tcp;

	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) //check ip header
	{
		invalid_packet = 1;
 	   //printf("   * Invalid IP header length: %u bytes\n", size_ip);
  	 	return;
	}
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) //check tcp header 
	{
		invalid_packet = 1;
	   // printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
	    return;
	}
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	//Writing statistic file ->>
	cap_ip = inet_ntoa(ip->ip_src);
	statistics = fopen(s_file, "a");
	if(statistics != NULL)
	{
 		strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S %Z", timestamp);
		fprintf(statistics, "Time: %s\r", buf);
		fprintf(statistics,"From: %s ", cap_ip);
		/* determine protocol */	
		switch(ip->ip_p) {
			case IPPROTO_TCP:
				fprintf(statistics, "Protocol: TCP ");
				tcpf = 1;
				break;
			case IPPROTO_UDP:
				fprintf(statistics ,"Protocol: UDP ");
				udpf = 1;
				break;
			case IPPROTO_ICMP:
				fprintf(statistics, "Protocol: ICMP ");
				icmpf = 1;
				break;
			case IPPROTO_IP:
				fprintf(statistics, "Protocol: IP ");
				ipf = 1;
				break;
			default:
				fprintf(statistics, "Protocol: unknown ");
				unkf = 1;
			break;
		}
		fprintf(statistics, "Size(byte): %d\n", strlen(payload));
		fclose(statistics);	
	}
	int i;
	strncpy(cap_ip_acc.ip,cap_ip,IPV4);
	cap_ip_acc.dip=ip_account_to_int(cap_ip_acc.ip);
	buf_ip_acc=bin_search(iptree, cap_ip_acc);
	if(buf_ip_acc == NULL)
	{
		cap_ip_acc.tcp_c=0;
		cap_ip_acc.udp_c=0;
		cap_ip_acc.icmp_c=0;
		cap_ip_acc.ip_c=0;
		cap_ip_acc.unknown_c=0;
		cap_ip_acc.tcp_c+=tcpf;//inc packet counter
		cap_ip_acc.udp_c+=udpf;
		cap_ip_acc.icmp_c+=icmpf;
		cap_ip_acc.ip_c+=ipf;
		cap_ip_acc.unknown_c+=unkf;
		insert(iptree, cap_ip_acc);//insert new node to binary tree
		//Write to file
		char dir_ip[10]="/var/log/";//ip list file
		char* iplway = calloc(1,25);//allocate memory for new ip list string way
		strncat(iplway, dir_ip, sizeof("/var/log/"));
		strncat(iplway, cap_ip, IPV4);
		iplfile = fopen(iplway, "w");
		if(iplfile != NULL)
		{
			fprintf(iplfile, "From:%s\nTCP:%d\nUDP:%d\nICMP:%d\nIP:%d\nUNK:%d\n", cap_ip, 
				cap_ip_acc.tcp_c,
				cap_ip_acc.udp_c,
				cap_ip_acc.icmp_c,
				cap_ip_acc.ip_c,
				cap_ip_acc.unknown_c
			);
			fclose(iplfile);
		}
		else
		{
			fprintf(stderr, "Couldn't write statistics from interface");		
		}
		free(iplway);
		remove(IPM);
		make_dump(iptree->root);//Create ip_account struct dump
	}
	else
	{
		buf_ip_acc->tcp_c+=tcpf;//inc packet counter
		buf_ip_acc->udp_c+=udpf;
		buf_ip_acc->icmp_c+=icmpf;
		buf_ip_acc->ip_c+=ipf;
		buf_ip_acc->unknown_c+=unkf; 
		//Write to file
		char dir_ip[10]="/var/log/";//ip list file
		char* iplway = calloc(1,25);//allocate memory for new ip list string way
		strncat(iplway, dir_ip, sizeof("/var/log/"));
		strncat(iplway, cap_ip, IPV4);
		iplfile = fopen(iplway, "w");
		if(iplfile != NULL)
		{
			fprintf(iplfile, "From:%s\nTCP:%d\nUDP:%d\nICMP:%d\nIP:%d\nUNK:%d\n", cap_ip, 
			buf_ip_acc->tcp_c,
			buf_ip_acc->udp_c,
			buf_ip_acc->icmp_c,
			buf_ip_acc->ip_c,
			buf_ip_acc->unknown_c
			);			
			fclose(iplfile);
		}
		else
		{
			fprintf(stderr, "Couldn't write statistics from interface");		
		}
		free(iplway);
		remove(IPM);
		make_dump(iptree->root);//Create ip_account struct dump
		//printf("START\n");
		//walk2(iptree);	
		//printf("END\n");
	}
	
}

void turnoff_hnd(int signum)//signal event function
{	
	if(signum == SIGTERM)//stop sniffing, free memory and turn off.
	{
		write_pid(11111111);
		pthread_cancel(ipc_thread);
		pcap_close(handle);
		free(ip_acc_base);
		tree_destroy(iptree);
		free(s_file);
		free(ptr_hnu_f);
		free(ptr_cli_f);
		exit(0);    	
	}
}

void start_hnd(int signum)
{
	if(signum == SIGCONT)
	{
		if(status == 0)
		{
			status = 1;
			pcap_loop(handle, -1, packet_handler, NULL);
		}
	}
}

void stop_hnd(int signum)
{
	if(signum == SIGUSR2)
	{	
		if(status == 1)
		{
			status = 0;
			pcap_breakloop(handle);
			while(status!=1){}
		}	 	
	}
}

void cli_hnd(int signum)
{
	if(signum == SIGUSR1)
	{
		int i, j;
		read_shared_memory(&key_hnu_f, &shmid_hnu_f, HNU_F, "hnu_f", ptr_hnu_f);
		if(ptr_hnu_f[0]=='f')
		{
			pcap_close(handle);
			read_config(device);	
			free(s_file);
			s_file = concat("/var/log/hnu_statistics_", device);
			printf("%s", s_file);
			handle = pcap_open_live(device, BUFSIZ, 0, 1000, ebuf);
			if (handle == NULL) 
			{
	    			fprintf(stderr, "Couldn't open device %s: %s\n", device, ebuf);
			}
			status=1;
			pcap_loop(handle, -1, packet_handler, NULL);
		}
		if(ptr_hnu_f[0]=='i')
		{
			char* ip = calloc(1, 15);
			char* cpid = calloc(1, 5);			
			char* ips;//ip statistics
			char* to_write;			
			char kill_com[9] = "kill -10 ";
			i = 1;
			while(ptr_hnu_f[i] != 'p')
			{
				cpid[i-1]=ptr_hnu_f[i];
				i++;
			}
			j = 0; i+=2;
			while(ptr_hnu_f[i] != 'e')
			{				
				ip[j]=ptr_hnu_f[i];
				i++;
				j++;
			}
			char* ipc_way = concat("/var/log/", ip);
			//printf("PID: %s\n", cpid);
			//printf("IP: %s\n", ip);
			//printf("IPC %s\n", ipc_way);
			ipcf = fopen(ipc_way, "rb");
			if(ipcf != NULL)
			{
				fseek(ipcf, 0, SEEK_END);
				long fsize = ftell(ipcf);
				fseek(ipcf, 0, SEEK_SET);
				ips = calloc(1,fsize+1);
				fread(ips, fsize, 1, ipcf);
				fclose(ipcf);
				//printf("IPS: %s\n", ips);
				to_write=concat("SAY: ",ips);	
				write_shared_memory(&key_cli_f, &shmid_cli_f, "cli_f", to_write);
				constructor = calloc(1, strlen(cpid)+strlen(kill_com));
				strncat(constructor, kill_com, 9);
				strncat(constructor, cpid, strlen(cpid)+9);
				system(constructor);	
				free(ips);
				free(ipc_way);
				free(ip);			
			}
			else
			{
				write_shared_memory(&key_cli_f, &shmid_cli_f, "cli_f", "NOT EXISTS");
				constructor = calloc(1, strlen(cpid)+strlen(kill_com));
				strncat(constructor, kill_com, 9);
				strncat(constructor, cpid, strlen(cpid)+9);
				system(constructor);		
			}
			free(constructor);
			free(cpid);
			
		}
		if(ptr_hnu_f[0]=='s')
		{
			char* rif = calloc(1, 15);
			char* cpid = calloc(1, 5);			
			char* ips;//ip statistics
			char* to_write;			
			char kill_com[9] = "kill -10 ";
			i = 1;
			while(ptr_hnu_f[i] != 'p')
			{
				cpid[i-1]=ptr_hnu_f[i];
				i++;
			}
			j = 0; i+=2;
			while(ptr_hnu_f[i] != 'e')
			{				
				rif[j]=ptr_hnu_f[i];
				i++;
				j++;
			}
			char* ipc_way = concat("/var/log/hnu_statistics_", rif);
			//printf("PID: %s\n", cpid);
			//printf("IP: %s\n", ip);
			//printf("IPC %s\n", ipc_way);
			ipcf = fopen(ipc_way, "rb");
			if(ipcf != NULL)
			{
				fclose(ipcf);
				//printf("IPS: %s\n", ips);
				to_write=concat("cat ",ipc_way);	
				write_shared_memory(&key_cli_f, &shmid_cli_f, "cli_f", to_write);
				constructor = calloc(1, strlen(cpid)+strlen(kill_com));
				strncat(constructor, kill_com, 9);
				strncat(constructor, cpid, strlen(cpid)+9);
				system(constructor);	
				free(ips);
				free(ipc_way);
				free(rif);			
			}
			else
			{
				write_shared_memory(&key_cli_f, &shmid_cli_f, "cli_f", "NOT EXISTS");
				constructor = calloc(1, strlen(cpid)+strlen(kill_com));
				strncat(constructor, kill_com, 9);
				strncat(constructor, cpid, strlen(cpid)+9);
				system(constructor);		
			}
			free(constructor);
			free(cpid);	
		}		
	}
}


int main(int argc, char* argv[])
{
	read_config(device);
	//Create statistics file name	
	s_file = concat("/var/log/hnu_statistics_", device);
	handle = pcap_open_live(device, BUFSIZ, 0, 1000, ebuf);//Open device "dev" for sniffing with NON promiscuous mode and 1000ms receiving timeout.
	
	if (handle == NULL) 
	{
	    fprintf(stderr, "Couldn't open device %s: %s\n", device, ebuf);
	}
	int pid = fork();//  Try create child process
	switch(pid)// Check child pid
	{
		case 0:
			ptr_hnu_f = calloc(1,HNU_F);
			ptr_cli_f = calloc(1,CLI_F);
			setsid(); // Create new process group
			chdir("/");// Change directory on root, for release storage device
			printf("%s","HOVRASHOK deamon is running...\n");		
			int pid_flag = write_pid(getpid());
			fclose(stdin);
			if(pid_flag == 1)
			{	
				struct sigaction turn_off;
    				memset(&turn_off, 0, sizeof(struct sigaction));
    				turn_off.sa_handler = turnoff_hnd;
    				sigaction(SIGTERM, &turn_off, NULL);
				
				struct sigaction start;
    				memset(&start, 0, sizeof(struct sigaction));
    				start.sa_handler = start_hnd;
    				sigaction(SIGCONT, &start, NULL);

				struct sigaction stop;
    				memset(&stop, 0, sizeof(struct sigaction));
    				stop.sa_handler = stop_hnd;
    				sigaction(SIGUSR2, &stop, NULL);//SIGUSR2

				struct sigaction cli;
    				memset(&cli, 0, sizeof(struct sigaction));
    				cli.sa_handler = cli_hnd;
    				sigaction(SIGUSR1, &cli, NULL);//SIGUSR1
			
				iptree=tree_create();
				read_dump();
				pcap_loop(handle, -1, packet_handler, NULL);// Try start receiving packet
				//**************CREATE PCAP THREAD*************
				/*int otr;	
				otr = pthread_create(&ipc_thread, NULL, ipc_func, &packet_handler);
				if (otr != 0) 
				{
					fprintf(stderr, "Creating the first thread");
					return EXIT_FAILURE;
				}
				otr = pthread_join(ipc_thread, NULL);
				if (otr != 0) 
				{
					fprintf(stderr, "Joining the ipc thread");
					return EXIT_FAILURE;
				}
				//**************CREATE IPC THREAD*************
				while(1)
				{
					printf("reading...\n");				
				}*/
				
				
			}
			else
			{
				fprintf(stderr, "%s", "'Write PID' error");		
			}
			pthread_cancel(ipc_thread);
			pcap_close(handle);
			free(ip_acc_base);
			tree_destroy(iptree);
			free(s_file);
			free(ptr_hnu_f);
			free(ptr_cli_f);
			write_pid(11111111);
			exit(0);
		break;
		case -1:
			printf("Can't start HOVRASHOK NET UTIL deamon.\n");
		break;
	}
	pcap_close(handle);
	free(s_file);
	return 0;
}
