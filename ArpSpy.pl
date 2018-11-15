#!/usr/bin/perl 

use feature "say";
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
our $sock = IO::Socket::INET->new( 'Proto' => 'tcp' );
our $OUTPUT = '';
getopts("i:m:h:d:o:D",\%opts);

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
    print color($_[0],'bold'),"\t\t\t***Arming script-kiddies*******\n";
    print color($_[0],'bold'),"\t\t\t**********Since 2018***********\n";
    print color($_[0],'bold'),"\t\t\t*******************************\n";
    print color($_[0],'bold'),"\t\t\t***Neutrino2211****************\n";
    print color($_[0],'bold'),"\t\t\t*****Information Gathering*****\n";
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

sub mac_parse2 {
    my @str_list = split ":",$_[0];
    my $str = "";
    foreach my $char (@str_list) {
        if(length $char == 1){
            $str .= "0".$char;
        } else {
            $str .= $char;
        }
        $str .= ":";
    }
    return substr $str,0,17;
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

sub debug {
    if(exists $opts{'D'}){
        print @_;
    }
}

sub end {
    print "Done\n";
}

sub syn_packets {
    my ( $user_data, $header, $packet ) = @_;
    my $eth_obj = NetPacket::Ethernet->decode($packet);
    my $eth_type = $eth_obj->{'type'};
    my $arp_obj = NetPacket::ARP->decode($eth_obj->{data}, $eth_obj);
    my $source_addr = $arp_obj->{'sha'};
    my $dest_addr = $arp_obj->{'tha'};
    my $src_mac = $eth_obj->{'src_mac'};
    my $dest_mac = $eth_obj->{'dest_mac'};
    my $parsed_mac = mac_parse2($src_mac);
    if (exists $opts{'o'}){
        open(my $file,">>",$opts{'o'}) || die "Can't open $opts{'o'}";
        say $file "$src_mac -> $dest_mac\n";
        close $file;
    }
    debug(lc(mac_parse($src_mac))," - ",lc($opts{'m'})," - ",lc(mac_parse($dest_mac))."\n");
    if(lc(mac_parse($src_mac)) eq lc($opts{'m'}) || lc(mac_parse($dest_mac)) eq lc($opts{'m'})){
        if(exists $opts{'d'} && $eth_obj->{data} =~ /$opts{'d'}/i){
            print STDOUT $eth_obj->{data}."\n";
        } elsif(! exists $opts{'d'}) {
            print STDOUT $eth_obj->{data}."\n";
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
    print "Usage: ArpSpy.pl -i <interface(s)> -m <mac_to_attack>\n".
        "\n\t-i : Listen on specific network interface e.g wlan0. Or 'all' to listen on all interfaces".
        "\n\t-m : Mac address of device to eavesdrop on e.g 90:90:90:90:90:90".
        "\n\t-d : Regex of data to log".
        "\n\t-o : File to output data\n";
}

intro("green");
if (! exists $opts{'m'}){
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
    $SIG{INT} = \&end;
    sleep();
} elsif(exists $opts{'h'}){
    usage();
} elsif (exists $opts{'i'}) {
    start_on_iface($opts{'i'});
} else {
    usage();
}