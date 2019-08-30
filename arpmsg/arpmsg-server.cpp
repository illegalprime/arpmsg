#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include <signal.h>
#include <math.h>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <string>
#include <iostream>

/*
#define ARP_REQUEST 1
#define ARP_REPLY   2
#define MACLEN      6
#define IPLEN       4
#define true        1
#define false       0
*/
#define MSGLEN         20
#define MAXBYTE        40

static int keepRunning = true;

void intHandler(int) {
    keepRunning = false;
}

typedef struct ARP_Header {
    u_int16_t htype;     // Hardware Type
    u_int16_t ptype;     // Protocol Type
    u_char hlen;         // MAC Length
    u_char plen;         // IP  Length
    u_int16_t oper;      // REPLY/REQUEST
    u_char data[MSGLEN]; // Remainder of Packet.

    /* Normal ARP:
    u_char sha[MACLEN];    // Sender MAC
    u_char spa[IPLEN];    // Sender IP
    u_char tha[MACLEN];    // Target MAC
    u_char tpa[IPLEN];    // Target IP
    */
} ARPhdr;

//  apt-get install libpcap-dev
//  IP:  119.104.111.63  (who? in ASCII)

int compareArray(u_char const *arr1, u_char const *arr2, int length);

int main(int argc, char* argv[]) {
    const unsigned char* packet = NULL;
    struct pcap_pkthdr header;

    char *device = NULL;
    u_char message[MSGLEN];
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    pcap_t *handle;
    ARPhdr *arpheader = NULL;

    if ((argc == 1) || (argc > 3)) {
        printf("Usage: %s <message> <interface>\n", argv[0]);
        return 1;
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
            message[0] = (u_char) strtol(tmp, NULL, 16);
            offset = 1;
        }

        for(int i = offset; i < msgLength; i++) {
            tmp[0] = inputText[i*2];
            tmp[1] = inputText[i*2 + 1];
            message[i] = (u_char) strtol(tmp, NULL, 16);
        }
    }
    else {
        msgLength = textLength;
        if (msgLength > MSGLEN)
            msgLength = MSGLEN;

        inputText = argv[1];

        for (int i = 0; i < msgLength; i++) {
            message[i] = (u_char) inputText[i];
        }
    }

    printf("Using keyword: ");
    for (int i = 0; i < msgLength; i++)
        printf("%c", message[i]);
    printf(" [%d]\n", msgLength);

    if (argc == 2) {
        device = pcap_lookupdev(errbuf);
        if (device == NULL) {
            fprintf(stderr, "Could not find default device: %s\n", errbuf);
            return 2;
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

    signal(SIGINT, intHandler);

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open %s for sniffing: %s \n", device, errbuf);
        return 2;
    }
    else {
        printf("Sniffing on %s ...\n", device);
    }

    if (pcap_compile(handle, &fp, "arp", 0, 0) == -1) {
        fprintf(stderr, "Could not compile filter.\n");
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could set filter.\n");
        return 2;
    }

    while (true) {
        while ( ((packet = pcap_next(handle, &header)) == NULL) && keepRunning ) {
            printf(".");
        }
        if (!keepRunning){
            printf("\n");
            pcap_close(handle);
            return 0;
        }

        arpheader = (struct ARP_Header *)(packet + 14);

        // If is Ethernet and IPv4
        if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800) {
            std::string message_text;
            for (int i = 0; i < MSGLEN; i += 1) {
                char text = arpheader->data[i];
                if (isprint(text)) {
                    message_text += text;
                } else {
                    break;
                }
            }
            std::cout << message_text << std::endl;
        }
    }

    pcap_close(handle);
    return 0;
}

int compareArray(u_char const *arr1, u_char const *arr2, int length) {
    for (int i = 0; i < length; i++) {
        if (arr1[i] != arr2[i])
            return false;
    }
    return true;
}
