/* -*- P4_16 -*- */

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */

#define ETHERNET_HEADER_BYTES 14

header ethernet_h {
    mac_addr_t   dst_addr;
    mac_addr_t   src_addr;
    ether_type_t ether_type;
}

header vlan_tag_h {
    bit<3>       pri;
    bit<1>       dei;
    bit<12>      vid;
    ether_type_t ether_type;
}

#define IPV4_HEADER_BYTES 20

header ipv4_h {
    bit<4>      version;
    bit<4>      ihl;
    // bit<6>      dscp;  // The 6 most significant bits of the diff_serv field.
    // bit<2>      ecn;   // The 2 least significant bits of the diff_serv field.
    bit<8>      diffserv;
    bit<16>     total_len;
    bit<16>     identification;
    bit<1>      reserved;
    bit<1>      do_not_fragment;
    bit<1>      more_fragments;
    bit<13>     frag_offset;
    bit<8>      ttl;
    ip_protocol_t      protocol;
    bit<16>     header_checksum;
    ipv4_addr_t  src_addr;
    ipv4_addr_t  dst_addr;
}

header ipv4_options_h {
    varbit<320> data;
}

header udp_h {
  bit<16> src_port;
  bit<16> dst_port;
  bit<16> hdr_length;
  bit<16> checksum;
}

header tcp_h {
  bit<16> src_port;
  bit<16> dst_port;
  bit<32> seq_no;
  bit<32> ack_no;
  bit<4> data_offset;
  bit<4> res;
  bit<8> flags;
  bit<16> window;
  bit<16> checksum;
  bit<16> urgent_ptr;
}

header icmp_h {
    icmp_type_t msg_type;
    bit<8>      msg_code;
    bit<16>     checksum;
    bit<16>     identifier;
    bit<16>     sequence;
    bit<64>     timestamp;
    bit<384>    data;
}

header arp_h {
    bit<16>       hw_type;
    ether_type_t  proto_type;
    bit<8>        hw_addr_len;
    bit<8>        proto_addr_len;
    arp_opcode_t  opcode;
}

header arp_ipv4_h {
    mac_addr_t   src_hw_addr;
    ipv4_addr_t  src_proto_addr;
    mac_addr_t   dst_hw_addr;
    ipv4_addr_t  dst_proto_addr;
}
