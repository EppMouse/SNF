#include<fcntl.h>
#include<string.h>
#include<stdio.h> 
#include<signal.h>
#include<stdlib.h>
#include<sys/stat.h>
#include<sys/types.h>
#include<sys/ipc.h> 
#include<string.h>
#include<sys/shm.h> 
#include<sys/mman.h>

#define CONF "/etc/hnu.conf"
#define PIDF "/var/run/hnu.pid"

//*******IPC VAR********
#define HNU_F 1
#define CLI_F 1
key_t key_hnu_f;//ipc hnu flags
key_t key_cli_f;//ipc cli flags
char* ptr_cli_f;//ipc ptrs...
char* ptr_hnu_f;
int shmid_cli_f;
int shmid_hnu_f;
//*******IPC VAR********
char pid[5];
char* constructor;
int stats = 0;
int readed = 0;
FILE* pidfile;
FILE* ifacef;
char *end;

char* concat(const char *s1, const char *s2)
{
	char *result = calloc(1,strlen(s1)+strlen(s2)+1);//+1 for the null-terminator
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

void read_shared_memory(key_t* key, int* shmid, int size, char* name, char* to_read) 
{
	*key = ftok(name, 'H'); 
     	*shmid = shmget(*key, size, 0666|IPC_CREAT); //shmget returns an identifier in shmid 
    	char *str = (char*) shmat(*shmid,(void*)0,0); //shmat to attach to shared memory  
	memcpy(to_read, str, strlen(str)+1);
	printf("%s\n",to_read);  
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

void hnu_hnd(int signum)
{
	if(signum == SIGUSR1)
	{
		if(stats == 1)
		{
			read_shared_memory(&key_cli_f, &shmid_cli_f, CLI_F, "cli_f", ptr_cli_f);
			system(ptr_cli_f);
		}
		else
		{				
			read_shared_memory(&key_cli_f, &shmid_cli_f, CLI_F, "cli_f", ptr_cli_f);	
		}	
		readed = 1;	
		free(ptr_hnu_f);
		free(ptr_cli_f);
		free(constructor);
	}
}

void write_iface(char* iface)
{
	int i;
	ifacef = fopen(CONF, "w");
	if(ifacef==NULL)
	{ 
		fprintf(stderr, "Couldn't open /var/run/hnu.pid to write.\n");
	}
	else
	{
		for(i = 0;i < strlen(iface);i++)
		{
			putc(iface[i], ifacef);
		}
		printf("%s", iface);
		fclose(ifacef);
	}
}

void read_hnu_pid(void)
{
	pidfile = fopen(PIDF, "r");
	if(pidfile==NULL)
	{ 
		fprintf(stderr, "Couldn't open /var/run/hnu.pid to write.\n");
	}
	else
	{
		fscanf(pidfile, "%s", pid);
		fclose(pidfile);
	}
}

void usage(const char * s) {
    printf("Usage: %s <start|stop|show [ip] count|select iface [iface]|stat [iface]|--help>\n", s);
}

int main (int argc, char ** argv) 
{
	if(argc < 2) 
	{
		usage(argv[0]);
		return 1;
	}
	else if(strcmp(pid,"11111111") != 0)
	{
		if(strcmp(argv[1],"--help") == 0)
		{
			printf("%s\n%s\n%s\n%s\n%s\n%s\n", "a. start​ (packets are being sniffed from now on from default iface(eth0))", 
			"b. stop​ (packets are not sniffed)",
			"c. show [ip] count ​ (print number of packets received from ip address)",
			"d. select iface [iface] ​ (select interface for sniffing eth0, wlan0, ethN, wlanN...)",
			"e. stat​ ​ [iface]​ show all collected statistics for particular interface, if iface omitted - for all interfaces.",
			"f. ​ --help ​ (show usage information)");
		}
		struct sigaction hnu;
    		memset(&hnu, 0, sizeof(struct sigaction));
    		hnu.sa_handler = hnu_hnd;
    		sigaction(SIGUSR1, &hnu, NULL);//SIGUSR1
		ptr_hnu_f = calloc(1,HNU_F);
		ptr_cli_f = calloc(1,CLI_F);
		read_hnu_pid();
		if(strcmp(argv[1],"start") == 0)
		{
			char kill_com[9] = "kill -18 ";
			constructor = calloc(1, strlen(pid)+strlen(kill_com));
			strncat(constructor, kill_com, 9);
			strncat(constructor, pid, strlen(pid)+9);
			printf("%s",constructor);
			system(constructor);
			
			
		}
		if(strcmp(argv[1],"stop") == 0)
		{
			char kill_com[9] = "kill -12 ";
			constructor = calloc(1, strlen(pid)+strlen(kill_com));
			strncat(constructor, kill_com, 9);
			strncat(constructor, pid, strlen(pid)+9);
			printf("%s",constructor);
			system(constructor);
		}

		if(strcmp(argv[1], "select")==0 && strcmp(argv[2], "iface")==0 && argc == 4)
		{
			printf("WF\n");
			printf("%s\n", argv[3]);
			write_iface(argv[3]);
			write_shared_memory(&key_hnu_f, &shmid_hnu_f, "hnu_f", "f");
			char kill_com[9] = "kill -10 ";
			constructor = calloc(1, strlen(pid)+strlen(kill_com));
			strncat(constructor, kill_com, 9);
			strncat(constructor, pid, strlen(pid)+9);
			printf("%s",constructor);
			system(constructor);		
		}
		
		if(strcmp(argv[1],"show") == 0 && strcmp(argv[3], "count")==0 && argc == 4)
		{
			char* wr;
			char* pr;
			char kill_com[9] = "kill -10 ";
			//printf("%s", argv[2]);
			wr=concat("a",argv[2]);
			pr=concat(pr, wr);
			end = pr;
			end += sprintf(end, "%c", 'i');
			end += sprintf(end, "%d", (long)getpid());
			end += sprintf(end, "%c", 'p');
			wr = concat(pr, wr);
			wr = concat(wr, "e");
			//printf("%s\n", wr);
			write_shared_memory(&key_hnu_f, &shmid_hnu_f, "hnu_f", wr);
			constructor = calloc(1, strlen(pid)+strlen(kill_com));
			strncat(constructor, kill_com, 9);
			strncat(constructor, pid, strlen(pid)+9);
			//printf("%s",constructor);
			system(constructor);
			while(readed != 1){}
		}
		if(strcmp(argv[1], "stat") == 0)
		{
			stats = 1;
			char* wr;
				char* pr;
				char kill_com[9] = "kill -10 ";
				//printf("%s", argv[2]);
				wr=concat("a",argv[2]);
				pr=concat(pr, wr);
				char *end = pr;
				end += sprintf(end, "%c", 's');
				end += sprintf(end, "%d", (long)getpid());
				end += sprintf(end, "%c", 'p');
				wr = concat(pr, wr);
				wr = concat(wr, "e");
				//printf("%s\n", wr);
				write_shared_memory(&key_hnu_f, &shmid_hnu_f, "hnu_f", wr);
				constructor = calloc(1, strlen(pid)+strlen(kill_com));
				strncat(constructor, kill_com, 9);
				strncat(constructor, pid, strlen(pid)+9);
				printf("%s",constructor);
				system(constructor);
				while(readed != 1){}
		}
	}  
	
	//shmctl(shmid_cli_f,IPC_RMID,NULL);// destroy the shared memory
	//shmctl(shmid_cli_d,IPC_RMID,NULL);// destroy the shared memory
	//shmctl(shmid_hnu_d,IPC_RMID,NULL);// destroy the shared memory
	//shmctl(shmid_hnu_f,IPC_RMID,NULL);// destroy the shared memory
	return 0;
}
