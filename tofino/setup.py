
bfrt
bfrt.bng.pipe.Ingress

# subscriber

subscriber.add_with_set_subscriber(subscriber=10,vlan_tag0_vid=10,vlan_tag1_vid=10,meta_Subscriber_port=1,ipv4_src_addr="192.168.1.1")

# from_host_to_Internet
from_host_to_Internet.add_with_set_nexthop(meta_Subscriber_port=1,vlan_tag0_vid=10,vlan_tag1_vid=10,ipv4_src_addr="192.168.1.1",nexthop=100)
# from_Internet_to_host
from_Internet_to_host.add_with_set_nexthop(vlan_tag0_vid=20,vlan_tag1_vid=20, ipv4_dst_addr="192.168.1.1", nexthop=200)

# nexthop
nexthop.add_with_send(nexthop_id=0, port=64)
nexthop.add_with_drop(nexthop_id=1)
# nexthop -> access_to_network
nexthop.add_with_access_to_network(nexthop_id=100,outer_vlan=20,iner_vlan=20,new_mac_da=0x000001000200, new_mac_sa=0x0000FF0000FE,port=10,stats_idx=1,base_meter_index=1)
# nexthop -> network_to_access
nexthop.add_with_network_to_access(nexthop_id=200,outer_vlan=10,iner_vlan=10,new_mac_da=0x000001000300, new_mac_sa=0x0000FF0000FF,port=1,stats_idx=2,base_meter_index=2)



sendp(Ether()/Dot1Q(vlan=10)/Dot1Q(vlan=10)/IP(dst="192.168.1.1")/UDP()/"Payload", iface="veth30")

sendp(Ether()/Dot1Q(vlan=10)/Dot1Q(vlan=10)/IP(src="192.168.1.1",dst="200.10.10.10")/UDP()/"Payload", iface="veth3")
