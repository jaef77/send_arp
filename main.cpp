#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pcap.h>

typedef struct arphdr{
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_add_len;
    uint8_t proto_add_len;
    uint16_t opcode;
}arphdr;


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

void victim_mac_req(uint8_t *v_mac, struct in_addr v_ip)
{

}

void send_arp_req(uint8_t *my_mac, uint8_t *v_mac, struct in_addr my_ip, struct in_addr v_ip, struct in_addr t_ip)
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
    // uint8_t errbuf[PCAP_ERRBUF_SIZE];
    // pcap_t* handle;

    // Set victim_ip, target_ip
    if(inet_pton(AF_INET, argv[2], &victim_ip) == 0)
        perror("ERROR : wrong INPUT IP Address! - victim");
    if(inet_pton(AF_INET, argv[3], &target_ip) == 0)
        perror("ERROR : wrong INPUT IP Address! - target");

    // Get my local MAC / IP address
    check_my_add(my_mac, &my_ip, argv[1]);

    // for debug
    printf("%s\n", inet_ntoa(my_ip));
    for(int i=0;i<6;i++)
        printf("%02X:", my_mac[i]);
    printf("\n");





    // Get Victim's MAC Address
    // victim_mac_req(victim_mac, victim_ip);

    // Send ARP Request(False)
    // send_arp_req(my_mac, victim_mac, my_ip, victim_ip, target_ip);

    return 0;
}
