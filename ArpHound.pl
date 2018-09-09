use strict;
use warnings;
use feature 'say';
use Net::ARP;
use Getopt::Std;
use Term::ANSIColor;
use Net::Address::IP::Local;
use Net::Frame::Device;
use Net::Frame::Dump::Online;
use Net::Frame::Simple;
use Net::Netmask;
use Net::Pcap();
use Path::Tiny;

my %opts;
getopts('p:m:d:ip:s',\%opts);
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
  print color($_[0],'bold'),"\t\t\t*****Information Gathering*****\n";
  print color($_[0],'bold'),"\t\t\t*******************************\n";
  print "\n\n\n";
  say "\t\t\tArp tools by neutrino2211\n\n\n";
}
use LWP;
if(exists $opts{'p'}){
  intro('red');
  say "\t\t\t Feeling Evil huh ? ;)";
  sleep (1);
}else{
  intro("yellow");
}
my $target = "ff:ff:ff:ff:ff:ff";
if(exists $opts{'m'}){
  $target = $opts{'m'};
}
my $poison;
my $network_device_name = Net::Pcap::pcap_lookupdev(\my $error_msg);
die "pcap device lookup failed " . ($error_msg || '')
  if $error_msg || not defined $network_device_name;

my $device = Net::Frame::Device->new(dev => $network_device_name);

my $pcap = Net::Frame::Dump::Online->new(
  dev => $network_device_name,
  filter => 'arp and dst host ' . $device->ip,
  promisc => 0,
  unlinkOnStop => 1,
  timeoutOnNext => 10
);
my $dollar = $device->gatewayIp;
print color('white','bold'),"Gateway IP: $dollar  \nStarting scan\n";

$pcap->start;
# say $target;
for my $ip_address (Net::Netmask->new($device->subnet)->enumerate)
{
  Net::ARP::send_packet(
    $network_device_name,
    $device->ip,
    $ip_address,
    $device->mac,
    $target, # broadcast
    "request",
  );
  if(exists $opts{'p'} ){
    $poison = 1;
    my $i = 1;
    for (;;){
        Net::ARP::send_packet(
                            $network_device_name,                       # Device
                            $device->ip,               # Source IP (my +gateway)
                            $ip_address,             # Destination IP
                            $device->mac,,          # Source MAC
                            'ff:ff:ff:ff:ff:ff',          # Destinaton MAC
                            'reply'                       # ARP operation
        );
        my $iterations = $opts{'p'};
        print color('red'),"sent $i packets out of $iterations"."\n";
        if($i == $opts{'p'}){ exit 0; }
        $i = $i+1;
    }
  }
}
my $dest = path('./')->child('Machines.cap');
my $w = $dest->openw_utf8();
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
# say $opts{'d'};
until ($pcap->timeout)
{
  if ((my $next = $pcap->next) && !$poison)
  {
    my $frame = Net::Frame::Simple->newFromDump($next);
    my $local_ip = Net::Address::IP::Local->public;
    my $frame_ip = $frame->ref->{ARP}->srcIp;
    my $frame_mac = $frame->ref->{ARP}->src;
    my $mac = substr $frame_mac,0,8;
    my $manufacturer = oui($mac);
    if(exists $opts{'ip'} && $ARGV[0] eq $frame_ip){
      $w->write("". ($local_ip eq $frame_ip ? "" : "$frame_ip $frame_mac $manufacturer\n"));
      print "". ($local_ip eq $frame_ip ? "" : "$frame_ip $frame_mac $manufacturer\n"),color('blue');
      exit 0;
    }
    elsif((index lc($manufacturer),lc($ARGV[0]||'cisco')) != -1 && exists $opts{'d'}){
      $w->write("". ($local_ip eq $frame_ip ? "" : "$frame_ip $frame_mac $manufacturer\n"));
      print "". ($local_ip eq $frame_ip ? "" : "$frame_ip $frame_mac $manufacturer\n"),color('green');
      exit 0;
    }
    else{
      $w->write("". ($local_ip eq $frame_ip ? "" : "$frame_ip $frame_mac $manufacturer\n"));
      print "". ($local_ip eq $frame_ip ? "" : "$frame_ip $frame_mac $manufacturer\n"),color('white');
    }
  }
}
END { say "Exiting."; if(!$poison&&!$!){$w->close();}$pcap->stop; }