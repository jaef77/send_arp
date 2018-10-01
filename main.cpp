#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pcap.h>
#include <netinet/if_ether.h>


typedef struct eth_hdr_custom{
    uint8_t dest_mac[6];
	uint8_t source_mac[6];
	uint16_t eth_type;
}eth_hdr_custom;

typedef struct arp_hdr_custom{
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_add_len;
    uint8_t proto_add_len;
    uint16_t opcode;
}arp_hdr_custom;


// function for dump
void dump(const uint8_t* p, int len) {
	for(int i=0; i<len; i++) {
		printf("%02x ", *p);
		p++;
		if((i & 0x0f) == 0x0f)
			printf("\n");
	}
}


// Get Local MAC ADDRESS & IP ADDRESS
int check_my_add(uint8_t *my_mac, struct in_addr *my_ip, const char *interface)
{
    struct ifreq buf;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0)
    {
        perror("ERROR : socket!");
        return -1;
    }

    strncpy(buf.ifr_name, interface, IFNAMSIZ-1);

    // MAC Address
    if(ioctl(sock, SIOCGIFHWADDR, &buf) < 0)
    {
        perror("ERROR : ioctl - MAC!");
        return -1;
    }
    for(int i=0;i<6;i++)
        my_mac[i] = buf.ifr_hwaddr.sa_data[i];

    //IP Address
    if(ioctl(sock, SIOCGIFADDR, &buf) < 0)
    {
        perror("ERROR : ioctl - IP");
        return -1;
    }
    *my_ip = ((struct sockaddr_in *)&buf.ifr_addr)->sin_addr;

    return 0;
}

// Get VICTIM'S MAC ADDRESS
int victim_mac_req(uint8_t *my_mac, uint8_t *v_mac, struct in_addr my_ip, struct in_addr v_ip, const char *interface)
{
    int debug = 0;
    eth_hdr_custom *ETH = (eth_hdr_custom*)malloc(sizeof(eth_hdr_custom));
    arp_hdr_custom *ARP = (arp_hdr_custom*)malloc(sizeof(arp_hdr_custom));
    char errbuf[PCAP_ERRBUF_SIZE];
    char send_buf[BUFSIZ];
    int offset = 0;
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL)
    {
        perror("ERROR : handle is NULL");
        return -1;
    }

    //for debug
    printf("pcap handle success!\n");

    /***************************Send Request**************************/
    // Ethernet Header Setting
    memset(ETH->dest_mac, 0xFF, sizeof(ETH->dest_mac));
    memcpy(ETH->source_mac, my_mac, sizeof(ETH->source_mac));
    ETH->eth_type = ntohs(ETHERTYPE_ARP);
    memcpy(send_buf, ETH, sizeof(eth_hdr_custom));

    offset += sizeof(eth_hdr_custom);

    // ARP Data Setting
    ARP->hw_type = ntohs((uint16_t)(1));
    ARP->proto_type = ntohs((uint16_t)(0x0800));
    ARP->hw_add_len = (uint8_t)(6);
    ARP->proto_add_len = (uint8_t)(4);
    ARP->opcode = ntohs((uint16_t)(1));

    memcpy(&send_buf[offset], ARP, sizeof(arp_hdr_custom));
    offset += sizeof(arp_hdr_custom);

    // ARP Address Data Setting
    memcpy(&send_buf[offset], my_mac, 6);
    offset += 6;
    memcpy(&send_buf[offset], &my_ip, 4);
    offset += 4;
    for(int i=0;i<6;i++)
        send_buf[offset + i] = 0;
    offset += 6;
    memcpy(&send_buf[offset], &v_ip, 4);
    offset += 4;
    
    // SEND REQUEST
    pcap_sendpacket(handle, (u_char*)(send_buf), offset);

    printf("send packet dump\n");
    dump((u_char* )send_buf, offset);
    printf("\n\n");


    /***************************Receive Reply**************************/
    while(true)
    {
        struct pcap_pkthdr* header;
        const u_char *rcv_buf;
        eth_hdr_custom *rcv_eth;
        int res = pcap_next_ex(handle, &header, &rcv_buf);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        rcv_eth = (eth_hdr_custom *)rcv_buf;
        if(ntohs(rcv_eth->eth_type) == 0x0806)
        {
            printf("ARP packet receive DUMP\n");
            dump((u_char* )rcv_buf, header->caplen);
            printf("\n\n");
            return 0;
        }
    }
    free(ETH);
    free(ARP);
}

// Send ARP Reply to the victim
void send_arp_reply(uint8_t *my_mac, uint8_t *v_mac, struct in_addr my_ip, struct in_addr v_ip, struct in_addr t_ip)
{
    const uint8_t *packet;
}




int main(int argc, char *argv[])
{
    if(argc != 4)
    {
        printf("Execute Code should be\nsend_arp <interface> <send ip> <target ip>");
        return -1;
    }

    // USE CUSTOM ARP_HEADER
    arphdr *ARP;
    struct in_addr victim_ip, target_ip, my_ip;
    uint8_t my_mac[6], victim_mac[6];
    uint8_t errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    // Set victim_ip, target_ip
    if(inet_pton(AF_INET, argv[2], &victim_ip) == 0)
        perror("ERROR : wrong INPUT IP Address! - victim");
    if(inet_pton(AF_INET, argv[3], &target_ip) == 0)
        perror("ERROR : wrong INPUT IP Address! - target");

    // Get my local MAC / IP address
    check_my_add(my_mac, &my_ip, argv[1]);

    // for DEBUG
    printf("IP  : %s\nMAC : ", inet_ntoa(my_ip));
    for(int i=0;i<6;i++)
    {
        printf("%02X", my_mac[i]);
        if(i != 5)
            printf(":");
    }
    printf("\n");

    // Get Victim's MAC Address
    victim_mac_req(my_mac, victim_mac, my_ip, victim_ip, argv[1]);
    printf("Victim's MAC\n");
    for(int i=0;i<6;i++)
    {
        printf("%02X", victim_mac[i]);
        if(i != 5)
            printf(":");
    }
    printf("\n");


    // Send ARP Request(False)
    // send_arp_reply(my_mac, victim_mac, my_ip, victim_ip, target_ip);

    return 0;
}
