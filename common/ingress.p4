/* -*- P4_16 -*- */

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_h          ethernet;
    vlan_tag_h[2]       vlan_tag;
    arp_h               arp;
    arp_ipv4_h          arp_ipv4;
    ipv4_h              ipv4;
    ipv4_options_h      ipv4_options;
    icmp_h              icmp;
    tcp_h               tcp;
    udp_h               udp;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    PortId_t        Subscriber_port;
    vlan_tag_h      svlan;
    vlan_tag_h      cvlan;
    ipv4_addr_t     dst_ipv4;
    ipv4_addr_t     src_ipv4;
    bit<1>          ipv4_csum_err;
    bit<16>         checksum_icmp_tmp;
    bool            checksum_icmp_ipv4;
    bool            too_many_tags;
}

    /***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    Checksum() ipv4_checksum;
    Checksum() icmp_checksum;

    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.too_many_tags = false;
        meta.Subscriber_port = ig_intr_md.ingress_port;
        transition meta_init;
    }

    state meta_init {
        meta.ipv4_csum_err = 0;
        meta.dst_ipv4      = 0;
        meta.src_ipv4      = 0;
        transition parse_ethernet;
    }

#ifdef PARSER_OPT
    @critical
#endif
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_TPID:  parse_vlan_tag_0;
            ETHERTYPE_IPV4:  parse_ipv4;
            ETHERTYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_vlan_tag_0 {
        pkt.extract(hdr.vlan_tag[0]);
        meta.svlan = hdr.vlan_tag[0];
        transition select(hdr.vlan_tag[0].ether_type) {
            ETHERTYPE_TPID:  parse_vlan_tag_1;
            ETHERTYPE_IPV4:  parse_ipv4;
            ETHERTYPE_ARP:   parse_arp;
            default: accept;
        }
    }

    state parse_vlan_tag_1 {
        pkt.extract(hdr.vlan_tag[1]);
        meta.cvlan = hdr.vlan_tag[1];
        transition select(hdr.vlan_tag[1].ether_type) {
            ETHERTYPE_TPID:  too_many_vlan_tags;
            ETHERTYPE_IPV4:  parse_ipv4;
            ETHERTYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state too_many_vlan_tags {
        meta.too_many_tags = true;
        transition select(hdr.vlan_tag[1].ether_type)
        { /* Force parse exception PARSEE_ERROR_NO_TCAM */}
        /* transition accept; */
    }
    
#ifdef PARSER_OPT
    @critical
#endif

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        meta.dst_ipv4 = hdr.ipv4.dst_addr;
        meta.src_ipv4 = hdr.ipv4.src_addr;
        ipv4_checksum.add(hdr.ipv4);

        transition select(hdr.ipv4.ihl) {
            0x5 : parse_ipv4_no_options;
            0x6 &&& 0xE : parse_ipv4_options;
            0x8 &&& 0x8 : parse_ipv4_options;
            default: reject; // Currently the same as accept
        }
    }

    state parse_ipv4_options {
        pkt.extract(
            hdr.ipv4_options,
            ((bit<32>)hdr.ipv4.ihl - 32w5) * 32);

       ipv4_checksum.add(hdr.ipv4_options);

        transition parse_ipv4_no_options;
    }

    state parse_ipv4_no_options {
        meta.ipv4_csum_err = (bit<1>)ipv4_checksum.verify();
        transition select(hdr.ipv4.frag_offset, hdr.ipv4.protocol) {
            ( 0, ip_protocol_t.ICMP ) : parse_icmp;
            default     : accept;
        }
    }    
    

  state parse_tcp {
    pkt.extract(hdr.tcp);
    transition accept;
  }

  state parse_udp {
    pkt.extract(hdr.udp);
    transition accept;
  }

  state parse_icmp {
    pkt.extract(hdr.icmp);
    transition accept;
  }

  state parse_arp {
    pkt.extract(hdr.arp);
    transition select(hdr.arp.hw_type, hdr.arp.proto_type) {
        (0x0001, ether_type_t.IPV4) : parse_arp_ipv4;
        default: reject; // Currently the same as accept
    }
  }

  state parse_arp_ipv4 {
    pkt.extract(hdr.arp_ipv4);
    meta.dst_ipv4 = hdr.arp_ipv4.dst_proto_addr;
    transition accept;
  }

}

    /***************** M A T C H - A C T I O N  *********************/

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    nexthop_id_t    nexthop_id  = 0;
    subscriber_id_t subscriber_id = 0;
    mac_addr_t      mac_da      = 0;
    mac_addr_t      mac_sa      = 0;
    PortId_t        egress_port = 511; /* Non-existent port */
    bit<8>          ttl_dec     = 0;

#if defined(USE_ALPM)
    Alpm(number_partitions=ALPM_PARTITIONS) lpm_alpm;
#endif

    /****************** Counter Code ********************/

    stats_index_t stats_index = 0;

    Counter< bit<COUNTER_WIDTH>, stats_index_t >(
        STATS_SIZE, CounterType_t.PACKETS_AND_BYTES) ipv4_stats;

    /****************** Meters ********************/

    meter_index_t                                   meter_index;
    Meter<meter_index_t>(10, MeterType_t.PACKETS) packet_meter;

    /****************** Set subscriber ********************/

    action set_subscriber(subscriber_id_t subscriber) {
        subscriber_id = subscriber;
    }

    /****************** IPv4 Lookup ********************/

    action set_nexthop(nexthop_id_t nexthop) {
        nexthop_id = nexthop;
    }

    table from_host_to_Internet {
        key     = { meta.Subscriber_port : exact; hdr.vlan_tag[0].vid : exact; hdr.vlan_tag[1].vid : exact; hdr.ipv4.src_addr : exact; }
        actions = { set_nexthop;
#ifdef ONE_STAGE
            @defaultonly NoAction;
#endif /* ONE_STAGE */
        }

#ifdef ONE_STAGE
        const default_action = NoAction();
#endif /* ONE_STAGE */

        size = IPV4_HOST_SIZE;
    }

    table from_Internet_to_host {
        key     = { hdr.vlan_tag[0].vid : exact; hdr.vlan_tag[1].vid : exact; hdr.ipv4.dst_addr : exact; }
        actions = { set_nexthop;
#ifdef ONE_STAGE
            @defaultonly NoAction;
#endif /* ONE_STAGE */
        }

#ifdef ONE_STAGE
        const default_action = NoAction();
#endif /* ONE_STAGE */

        size = IPV4_HOST_SIZE;
    }

    table ipv4_lpm {
        key            = { meta.dst_ipv4 : lpm; }
        actions = { set_nexthop; }

#if defined(USE_ALPM)
        implementation = lpm_alpm;
#endif
        default_action = set_nexthop(1);
        size           = IPV4_LPM_SIZE;
    }

    table subscriber {
        key            = { meta.Subscriber_port : exact; hdr.vlan_tag[0].vid : exact; hdr.vlan_tag[1].vid : exact; hdr.ipv4.src_addr : exact;}
        actions = { set_subscriber; }
        default_action = set_subscriber(0);  /* Use counter 0 for the default */
        size           = SUBSCRIBER_SIZE;
    }

    /****************** Nexthop ********************/
    action send(PortId_t port, stats_index_t stats_idx, meter_index_t base_meter_index) {
        mac_da      = hdr.ethernet.dst_addr;
        mac_sa      = hdr.ethernet.src_addr;
        egress_port = port;
        ttl_dec     = 0;
        stats_index = stats_idx;
        meter_index = base_meter_index;
    }

    action drop(stats_index_t stats_idx, meter_index_t base_meter_index) {
        ig_dprsr_md.drop_ctl = 1;
        stats_index = stats_idx;
        meter_index = base_meter_index;
    }

    action network_to_access(PortId_t port, bit<48> new_mac_da, bit<48> new_mac_sa, bit<12> outer_vlan, bit<12> iner_vlan, stats_index_t stats_idx, meter_index_t base_meter_index) {
        mac_da      = new_mac_da;
        mac_sa      = new_mac_sa;
        egress_port = port;
        ttl_dec     = 1;

    // Add VLAN tag to the packet
        hdr.vlan_tag[0].vid = outer_vlan;  // VLAN ID
        hdr.vlan_tag[1].vid = iner_vlan;  // VLAN ID

        stats_index = stats_idx;
        meter_index = base_meter_index;      
    }

    action access_to_network(PortId_t port, bit<48> new_mac_da, bit<48> new_mac_sa, bit<12> outer_vlan, bit<12> iner_vlan, stats_index_t stats_idx, meter_index_t base_meter_index) {
        mac_da      = new_mac_da;
        mac_sa      = new_mac_sa;
        egress_port = port;
        ttl_dec     = 1;

        stats_index = stats_idx;
        meter_index = base_meter_index; 

    // Add VLAN tag to the packet
        hdr.vlan_tag[0].vid = outer_vlan;  // VLAN ID
        hdr.vlan_tag[1].vid = iner_vlan;  // VLAN ID     

       // hdr.ethernet.ether_type = hdr.vlan_tag[1].ether_type;
       // hdr.vlan_tag[0].setInvalid();
       // hdr.vlan_tag[1].setInvalid();
    }

    table nexthop {
        key            = { nexthop_id : exact; }
        actions        = { send; drop; network_to_access; access_to_network; }
        size           = NEXTHOP_SIZE;
        default_action = drop(0,0);  /* Use counter 0 for the default */
    }

    /****************** Metadata Processing ********************/

    action send_back() {
        ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
    }

    action forward_ipv4() {
        hdr.ethernet.dst_addr      = mac_da;
        hdr.ethernet.src_addr      = mac_sa;
        hdr.ipv4.ttl               = hdr.ipv4.ttl |-| ttl_dec;
        ig_tm_md.ucast_egress_port = egress_port;
    }

    action send_arp_reply() {
        hdr.ethernet.dst_addr = hdr.arp_ipv4.src_hw_addr;
        hdr.ethernet.src_addr = mac_da;

        hdr.arp.opcode = arp_opcode_t.REPLY;
        hdr.arp_ipv4.dst_hw_addr    = hdr.arp_ipv4.src_hw_addr;
        hdr.arp_ipv4.dst_proto_addr = hdr.arp_ipv4.src_proto_addr;
        hdr.arp_ipv4.src_hw_addr    = mac_da;
        hdr.arp_ipv4.src_proto_addr = meta.dst_ipv4;

        send_back();
    }

    action send_icmp_echo_reply() {
        mac_addr_t  tmp_mac  = hdr.ethernet.src_addr;
        ipv4_addr_t tmp_ipv4 = hdr.ipv4.src_addr;

        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = tmp_mac;

        hdr.ipv4.src_addr = hdr.ipv4.dst_addr;
        hdr.ipv4.dst_addr = tmp_ipv4;

        hdr.ipv4.ttl      = hdr.ipv4.ttl |-| ttl_dec; /* Optional */
        hdr.icmp.msg_type = icmp_type_t.ECHO_REPLY;
        hdr.icmp.checksum = 1; /* ?? */

        send_back();
    }

    table forward_or_respond {
        key = {
            hdr.arp.isValid()       : exact;
            hdr.arp_ipv4.isValid()  : exact;
            hdr.ipv4.isValid()      : exact;
            hdr.icmp.isValid()      : exact;
            hdr.arp.opcode          : ternary;
            hdr.icmp.msg_type       : ternary;
        }
        actions = {
            forward_ipv4;
            send_arp_reply;
            send_icmp_echo_reply;
            drop;
        }
        const entries = {
            (false, false, true,  false, _, _) :
            forward_ipv4();

            (true,  true,  false, false, arp_opcode_t.REQUEST, _ ) :
            send_arp_reply();

            (false, false, true,   true, _, icmp_type_t.ECHO_REQUEST) :
            send_icmp_echo_reply();

            (false, false, true,   true, _, _) :
            forward_ipv4();
        }
        default_action = drop(0,0);  /* Use counter 0 for the default */
    }

 /****************** The algorithm ********************/

    apply {
        if (meta.ipv4_csum_err == 0) {         /* No checksum error for ARP! */
            if (!from_host_to_Internet.apply().hit) {
                from_Internet_to_host.apply();
            }
        }
        subscriber.apply();
        nexthop.apply();
        forward_or_respond.apply();
        ipv4_stats.count(stats_index);
        hdr.ipv4.diffserv = packet_meter.execute(meter_index);
    }
}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Checksum() ipv4_checksum;
    Checksum() icmp_checksum;

    apply {
        hdr.ipv4.header_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.reserved,
                hdr.ipv4.do_not_fragment,
                hdr.ipv4.more_fragments,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });
        hdr.icmp.checksum = icmp_checksum.update ({
                hdr.icmp.msg_type,
                hdr.icmp.msg_code,
                hdr.icmp.identifier,
                hdr.icmp.sequence,
                hdr.icmp.timestamp,
                hdr.icmp.data
        });
        pkt.emit(hdr);
    }
}
