#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>


int main(int argc, char *argv[]){
	int c;
	uint32_t i;
	libnet_t *l;
	libnet_ptag_t t;
	char *device =NULL;
	uint8_t *packet;
	uint32_t packet_s;
	char errbuf[LIBNET_ERRBUF_SIZE];
	
	u_char enet_src[6] = {0x08,0x00,0x27,0x92,0x07,0xb6};
	u_char enet_dst[6] = {0x94,0xB8,0X6D,0xFC,0xDA,0xA0};
	u_char ip_dst[4] ={0xc0,0xa8,0x2b,0x92};
	u_char ip_src[4] ={0xc0,0xa8,0x2b,0x01};
	

	printf("libnet 1.1 packet shaping : ARP [link --autobuilding ethernet]\n");
	
	if(argc >1){
		device = argv[1];
	}


	l =libnet_init(LIBNET_LINK_ADV, device,errbuf);

	if(l ==NULL){
		fprintf(stderr,"libnet_init() failed :%s",errbuf);
		exit(EXIT_FAILURE);

	}else
		i =libnet_get_ipaddr4(l);
	
	t=libnet_autobuild_arp(ARPOP_REPLY,enet_src,ip_src,enet_dst,ip_dst,l);
	if(t ==-1)
	{
		fprintf(stderr, "can't build ARP header:%s\n",libnet_geterror(l));
		goto bad;
	}

	t=libnet_autobuild_ethernet(enet_dst,ETHERTYPE_ARP, l);


	if(libnet_adv_cull_packet(l,&packet,&packet_s)==-1){
		fprintf(stderr, "%s",libnet_geterror(l));
	}else{
		fprintf(stderr, "packet size : %d\n", packet_s);
		libnet_adv_free_packet(l,packet);
	}
	c=libnet_write(l);
	if(c==-1){
		fprintf(stderr,"Write error : %s \n",libnet_geterror(l));
		goto bad;

	}else{
		fprintf(stderr,"Wrote %d byte ARP packet from context \ %s\";""check the wire\n",c,libnet_cq_getlabel(l));

	}
	libnet_destroy(l);
	return (EXIT_SUCCESS);
bad :
	libnet_destroy(l);
	return(EXIT_SUCCESS);

}







