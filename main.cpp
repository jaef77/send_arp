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


typedef struct ethhdr{
    uint8_t dest_mac[6];
	uint8_t source_mac[6];
	uint16_t eth_type;
}ethhdr;

typedef struct arphdr{
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_add_len;
    uint8_t proto_add_len;
    uint16_t opcode;
}arphdr;

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
void victim_mac_req(uint8_t *my_mac, uint8_t *v_mac, struct in_addr my_ip, struct in_addr v_ip, const char *interface)
{
    ethhdr *ETH;
    arphdr *ARP;
    char errbuf[PCAP_ERRBUF_SIZE];
    char send_buf[BUFSIZ];
    char rcv_buf[BUFSIZ];
    int offset = 0;
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL)
    {
        perror("ERROR : handle is NULL");
        return -1;
    }
    /***************************Send Request**************************/
    // Ethernet Header Setting
    for(int i=0;i<6;i++)
        ETH->dest_mac[i] = (uint8_t)(0xFF);
    memcpy(ETH->source_mac, my_mac, sizeof(ETH->source_mac));
    ETH->eth_type = ntohs(ETHERTYPE_ARP);
    memcpy(send_buf, ETH, sizeof(ethhdr));
    offset += sizeof(ethhdr);

    // ARP Data Setting
    ARP->hw_type = ntohs((uint16_t)(1));
    ARP->proto_type = ntohs((uint16_t)(0x0800));
    ARP->hw_add_len = (uint8_t)(6);
    ARP->proto_add_len = (uint8_t)(4);
    ARP->opcode = ntohs((uint16_t)(1));

    memcpy(&send_buf[offset], ARP, sizeof(arphdr));
    offset += sizeof(arphdr);

    // ARP Address Data Setting
    memcpy(&send_buf[offset], my_mac, 6);
    offset += 6;
    memcpy(&send_buf[offset], &my_ip, 4);
    offset += 4;
    for(int i=0;i<6;i++)
        send_buf[offset + i] = 0;
    offset += 6;
    memcpy(&send_buf[offset], &v_ip);
    
    // SEND REQUEST
    pcap_sendpacket(handle, static_cast<u_char *>(ARP), sizeof(errbuf));


    /***************************Receive Reply**************************/
    while(true)
    {
        
    }

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
    // victim_mac_req(victim_mac, victim_ip);

    // Send ARP Request(False)
    // send_arp_reply(my_mac, victim_mac, my_ip, victim_ip, target_ip);

    return 0;
}
