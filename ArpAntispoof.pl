#!/usr/bin/perl 

use strict;
use warnings;
use Async;
use Data::Dumper;
use Net::Pcap;
use Net::Pcap::FindDevice;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use NetPacket::ARP;

my $err;
my $type = 'DLT_IEEE802_11';
my $dev  = find_device($ARGV[0]);
my ( $addr, $net, $mask );
if ( Net::Pcap::lookupnet( $dev, \$net, \$mask, \$err ) ) {
    die "Unable to look up device information for ", $dev, " - ", $err;
}
print STDOUT "${dev}: mask -> $mask\n";

my $WiFiobject = Net::Pcap::open_live( $dev, 128000, -1, 500, \$err );
my $w802 = Net::Pcap::datalink_name_to_val($type);
Net::Pcap::set_datalink( $WiFiobject, $w802 );
unless ( defined $WiFiobject ) {
    die 'Unable to create packet capture on device ', $dev, ' - ', $err;
}
die 'Unable to perform packet capture'
  unless Net::Pcap::loop( $WiFiobject, -1, \&syn_packets, '' );
print Dumper ($WiFiobject);

Net::Pcap::close($WiFiobject);

my %attackers;
my $limit = 10;

sub syn_packets {
    my ( $user_data, $header, $packet ) = @_;
    my $eth_obj = NetPacket::Ethernet->decode($packet);
    # print "$eth_obj->{'src_mac'},  $eth_obj->{'dest_mac'}\n";
    my $eth_type = $eth_obj->{'type'};
    my $arp_obj = NetPacket::ARP->decode($eth_obj->{data}, $eth_obj);
    my $source_addr = $arp_obj->{'sha'};
    my $dest_addr = $arp_obj->{'tha'};

    my $src_mac = $eth_obj->{'src_mac'};
    print "x=$eth_type dest=$dest_addr src=$src_mac\n";
    # print("source hw addr=" . $source_addr . ", " . "dest hw addr=" . $dest_addr . "\n");
    if($dest_addr eq $ARGV[1]){
        # print("Strange packet sent to Gateway by $eth_obj->{'src_mac'} (Attacker)\n");
        if( exists $attackers{$src_mac}){
            if($attackers{$src_mac} eq 10){
                print("Attacker identified ($src_mac)\n")
            } else {
                $attackers{$src_mac} += 1;
            }
        } else {
            $attackers{$src_mac} = 1;
        }
    }
}