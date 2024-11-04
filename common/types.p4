/* -*- P4_16 -*- */

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/

#define ETHERTYPE_TPID  0x8100
#define ETHERTYPE_IPV4  0x0800
#define ETHERTYPE_ARP   0x0806

#define IP_PROTOCOL_TCP    0x06
#define IP_PROTOCOL_UDP    0x11
#define IP_PROTOCOL_ICMP   0x01

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;

#define NEXTHOP_ID_WIDTH 14
typedef bit<NEXTHOP_ID_WIDTH> nexthop_id_t;
const int NEXTHOP_SIZE = 1 << NEXTHOP_ID_WIDTH;

#define SUBSCRIBER_ID_WIDTH 14
typedef bit<SUBSCRIBER_ID_WIDTH> subscriber_id_t;
const int SUBSCRIBER_SIZE = 1 << SUBSCRIBER_ID_WIDTH;

enum bit<16> ether_type_t {
    IPV4 = 0x0800,
    ARP  = 0x0806,
    TPID = 0x8100
}

enum bit<8> ip_protocol_t {
    ICMP = 1,
    IGMP = 2,
    TCP  = 6,
    UDP  = 17
}

enum bit<16> arp_opcode_t {
    REQUEST = 1,
    REPLY   = 2
}

enum bit<8> icmp_type_t {
    ECHO_REPLY   = 0,
    ECHO_REQUEST = 8
}


