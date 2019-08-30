#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <pcap.h>
#include <cstring>
#include <math.h>
#include <netinet/in.h>
#include <cstdlib>

#define ARPLEN        42
#define MSGLEN        20
#define MACLEN        6
#define MAXBYTE       40

typedef struct ARP_Packet {
                            // LINK LAYER:
    u_char dst_mac[MACLEN]; // Destination MAC
    u_char src_mac[MACLEN]; // Source MAC
    u_int16_t ethertype;    // Type of Packet
                            // ARP HEADER:
    u_int16_t htype;        // Hardware Type
    u_int16_t ptype;        // Protocol Type
    u_char hlen;            // MAC Length
    u_char plen;            // IP  Length
    u_int16_t oper;         // REPLY/REQUEST
    u_char data[MSGLEN];    // Remainder of Packet.
} ARP;

int main(int argc, char* argv[]) {
    pcap_t *handle;
    const unsigned char* packet = NULL;
    struct pcap_pkthdr header;

    char *device = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    ARP Packet_ARP;

    if ((argc == 1) || (argc > 3)) {
        printf("Usage: %s <message> <interface>\n", argv[0]);
        return(1);
    }

    char* inputText;
    int textLength = strlen(argv[1]);
    int msgLength;

    if (argv[1][0] == '0' && argv[1][1] == 'x') {
        textLength -= 2;
        if (textLength > MSGLEN*2)
            textLength = MSGLEN*2;
        msgLength = ceil(textLength/2);

        char tmp[3];
        tmp[2] = '\0';
        int offset = 0;
        inputText = argv[1] + 2;

        if (textLength % 2) {
            tmp[0] = 0;
            tmp[1] = inputText[0];
            Packet_ARP.data[0] = (u_char) strtol(tmp, NULL, 16);
            offset = 1;
        }

        for(int i = offset; i < msgLength; i++) {
            tmp[0] = inputText[i*2];
            tmp[1] = inputText[i*2 + 1];
            Packet_ARP.data[i] = (u_char) strtol(tmp, NULL, 16);
        }
    }
    else {
        msgLength = textLength;
        if (msgLength > MSGLEN)
            msgLength = MSGLEN;

        inputText = argv[1];

        for (int i = 0; i < msgLength; i++) {
            Packet_ARP.data[i] = (u_char) inputText[i];
        }
    }

    printf("Using keyword: ");
    for (int i = 0; i < msgLength; i++)
        printf("%c", Packet_ARP.data[i]);
    printf(" [%d]\n", msgLength);

    if (msgLength < MSGLEN) {
        srand(time(NULL));
        //  Fill up some space.
        Packet_ARP.data[msgLength] = '\0';
        msgLength += 1;
        for (int i = msgLength; i < MSGLEN; i++) {
            Packet_ARP.data[i] = (u_char) rand();
        }
    }

    if (argc == 2) {
        device = pcap_lookupdev(errbuf);
        if (device == NULL) {
            fprintf(stderr, "Could not find default device: %s\n", errbuf);
            return(2);
        }
        printf("No device specified, defaulting to: %s\n", device);
    }
    else {
        device = argv[2];
    }

    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open %s for injection (%s).\n", device, errbuf);
        return(2);
    }
    else {
        printf("Using %s for injection...  ", device);
    }

    // Link Layer
    for (int i = 0; i < MACLEN; i++)
        Packet_ARP.dst_mac[i] = (u_char) rand();

    for (int i = 0; i < MACLEN; i++)
        Packet_ARP.src_mac[i] = (u_char) rand();

    Packet_ARP.ethertype = ntohs(0x0806);

    // ARP Packet
    Packet_ARP.htype = ntohs(0x0001);
    Packet_ARP.ptype = ntohs(0x0800);
    Packet_ARP.hlen  = 0x06;
    Packet_ARP.plen  = 0x04;
    Packet_ARP.oper  = ntohs(0x0001);

    if (pcap_inject(handle, &Packet_ARP, (size_t) ARPLEN) == -1) {
        printf("Failed to inject packet.");
    } else {
        printf("Injected.\n");
    }

    pcap_close(handle);
    return(0);
}
