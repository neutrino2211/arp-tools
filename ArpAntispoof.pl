#!/usr/bin/perl -w

use Net::PcapUtils;
use NetPacket::Ethernet qw(:types);
use NetPacket::ARP;

    sub process_pkt {
        my ($arg, $hdr, $pkt) = @_;

        my $eth_obj = NetPacket::Ethernet->decode($pkt);
        my $eth_type = $eth_obj->{'type'};
        my $source_addr = $arp_obj->{'sha'};
        my $dest_addr = $arp_obj->{'tha'};
        print "$eth_type";
        if ($eth_type == "ETH_TYPE_ARP") {
            my $arp_obj = NetPacket::ARP->decode($eth_obj->{data}, $eth_obj);
            print("source hw addr=" . $source_addr . ", " .
                "dest hw addr=" . $dest_addr . "\n");
            if($dest_addr == $ARGV[0]){
                print("ARP packaet sent to $dest_addr by $source_addr \nThis is most likely an attack");
            }
        }
    }

Net::PcapUtils::loop(\&process_pkt);