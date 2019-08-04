#include <stdio.h>
#include "utils.h"
#include "pcap.h"

void usage() {
    printf("syntax: pcap_test <interface> <sender_ip> <target_ip>\n");
    printf("sample: pcap_test wlan0 192.168.9.2 192.168.9.1\n");
}

int main(int argc, char *argv[])
{
    if (argc != 4) {
        usage();
        return -1;
    }
    char *interface = argv[1];    //interface
    char *sender_ip = argv[2];    //victim ip
    char *target_ip = argv[3];    //gateway ip

    if(arp_request(interface, sender_ip, target_ip) != 0)
        return -1;

    return 0;

}
