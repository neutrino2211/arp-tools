#!/usr/bin/perl 

use feature "say";
use strict;
use warnings;
use Proc::Forkfunc;
use Data::Dumper;
use Net::Pcap;
use Term::ANSIColor;
use Net::Pcap::FindDevice;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use NetPacket::ARP;
use Path::Tiny;
use IO::Socket;
use IO::Interface;
use Getopt::Std;

our %opts;
our $err;
our %attackers;
our $time = time + 30;
our $sock = IO::Socket::INET->new( 'Proto' => 'tcp' );

getopts("i:c:h:v:V",\%opts);

sub intro{
    print color($_[0],'bold'),"\t\t\t*******************************\n";
    print color($_[0],'bold'),"\t\t\t*************0000**************\n";
    print color($_[0],'bold'),"\t\t\t***********00    00************\n";
    print color($_[0],'bold'),"\t\t\t*********000000000000**********\n";
    print color($_[0],'bold'),"\t\t\t*******00            00********\n";
    print color($_[0],'bold'),"\t\t\t*******************************\n";
    print color($_[0],'bold'),"\t\t\t***0000000********0000000******\n";
    print color($_[0],'bold'),"\t\t\t***0      0*******0      0*****\n";
    print color($_[0],'bold'),"\t\t\t***000000/.*******0000000/*****\n";
    print color($_[0],'bold'),"\t\t\t***0      0*******0************\n";
    print color($_[0],'bold'),"\t\t\t***0      0*******0************\n";
    print color($_[0],'bold'),"\t\t\t*******************************\n";
    print color($_[0],'bold'),"\t\t\t***Neutrino2211****************\n";
    print color($_[0],'bold'),"\t\t\t*****Network Protection********\n";
    print color($_[0],'bold'),"\t\t\t*******************************\n";
    print "\n\n\n";
    say "\t\t\tArp tools by neutrino2211\n\n".color("reset");
}

sub oui {
    my $device_manufacturer = "Unknown manufacturer";
    my $oui_file = path('./')->child('OUI.list');
    my $macA = $_[0];
    my $mac = $macA =~ s/:/ /r =~ s/:/ /r;
    my $oui_info = $oui_file->openr_utf8();
    while(my $info = $oui_info->getline()){
        my $parse = substr $info,0,8;
        my $compare = $parse;
        if(uc($compare) eq uc($mac)){
            $device_manufacturer = "Manufacturer: ".(substr $info,9,-1);
        }
    }
    return $device_manufacturer;
}

sub mac_parse {
    my @str_list = split //,$_[0];
    my $index = 0;
    my $str = "";
    foreach my $char (@str_list) {
        if($index % 2 == 0 && $index > 0){
            $str .= ":";
        }
        $str .= $char;
        $index += 1
    }
    return $str;
}

sub syn_packets {
    my ( $user_data, $header, $packet ) = @_;
    my $eth_obj = NetPacket::Ethernet->decode($packet);
    my $eth_type = $eth_obj->{'type'};
    my $arp_obj = NetPacket::ARP->decode($eth_obj->{data}, $eth_obj);
    my $source_addr = $arp_obj->{'sha'};
    my $dest_addr = $arp_obj->{'tha'};

    my $src_mac = $eth_obj->{'src_mac'};
    print "x=$eth_type dest=$dest_addr src=$src_mac\n" if exists $opts{'v'} || exists $opts{'V'};
    if ( exists $opts{'V'} && $eth_obj->{data} =~ /$opts{'V'}/i && exists $attackers{$src_mac} && $attackers{$src_mac} > 5){
        print $eth_obj->{data} ."\n";
    }
    if($dest_addr eq $opts{'c'}){
        if( exists $attackers{$src_mac}){
            if(time ge $time){
                $attackers{$src_mac} = 0;
                $time = time + 30;
            } elsif($attackers{$src_mac} eq 10){
                my $parsed_mac = mac_parse($src_mac);
                my $substr = substr $parsed_mac,0,8;
                my $man = oui($substr);
                print("Attacker identified ($parsed_mac) [$man]\n")
            } else {
                $attackers{$src_mac} += 1;
            }
        } else {
            $attackers{$src_mac} = 1;
        }
    }
}

sub start_on_iface {
    my $limit = 10;
    my $type = 'DLT_IEEE802_11';
    my $dev  = find_device($_[0]);
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
}

sub usage {
    print "Usage: ArpAntispoof.pl -i <interface(s)> -c <mac_to_protect>\n".
        "\n\t-i : Listen on specific network interface e.g wlan0. Or 'all' to listen on all interfaces".
        "\n\t-c : Mac address of device to protect without ':' e.g 909090909090".
        "\n\t-v : Show packet metadata".
        "\n\t-V : Show packet metadata and data with optional filter\n";
}

intro("blue");
if (! exists $opts{'c'}){
    usage();
    exit();
}

if (exists $opts{'i'} && $opts{'i'} eq "all"){
    foreach my $iface ( $sock->if_list ) {
        if($iface ne "lo"){
            # Async->new(\&start_on_iface($iface));
            $|++;
            forkfunc(\&start_on_iface,$iface);
        }
    }
    sleep();
} elsif(exists $opts{'h'}){
    usage();
} elsif (exists $opts{'i'}) {
    start_on_iface($opts{'i'});
} else {
    usage();
}