#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

typedef struct arphdr{
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_add_len;
    uint8_t proto_add_len;
    uint16_t opcode;
}arphdr;


void check_my_add(uint8_t *my_mac, uint32_t *my_ip)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0)
        perror("ERROR : socket!");
    struct ifreq buf;
    memset(&buf, 0, sizeof(buf));
    strcpy(buf.ifr_name, "eth0");
    // MAC Address
    if(ioctl(sock, SIOCGIFHWADDR, &buf) < 0)
        perror("ERROR : ioctl - MAC!");
    strncpy(my_mac, buf.ifr_hwaddr.sa_data, sizeof(buf.ifr_hwaddr.sa_data));

    //IP Address
    if(ioctl(sock, SIOCGIFADDR, &buf) < 0)
        perror("ERROR : ioctl - IP");
    *my_ip = ((struct sockaddr_in *)&buf.ifr_addr)->sin_addr;

    return;
}

void victim_mac_req(uint8_t *v_mac, uint32_t v_ip)
{

}

void send_arp_request(uint8_t *my_mac, uint8_t *v_mac, uint32_t my_ip, uint32_t v_ip, uint32_t t_ip)
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
    uint32_t victim_ip, target_ip, my_ip;
    uint8_t my_mac[6], victim_mac[6];
    uint8_t errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    // Set victim_ip, target_ip
    if(inet_pton(AF_INET, argv[2], &victim_ip) == 0)
        perror("ERROR : wrong INPUT IP Address! - victim");
    if(inet_pton(AF_INET, argv[3], &target_ip) == 0)
        perror("ERROR : wrong INPUT IP Address! - target");

    // Get my local MAC / IP address
    check_my_add(my_mac, &my_ip);

    // for debug
    printf("%s\n", inet_ntoa(my_ip));
    for(int i=0;i<6;i++)
        printf("%02X:", my_mac[i]);




    // Get Victim's MAC Address
    // victim_mac_req(victim_mac, victim_ip);

    // Send ARP Request(False)
    // send_arp_request(my_mac, victim_mac, my_ip, victim_ip, target_ip);

    return 0;
}
