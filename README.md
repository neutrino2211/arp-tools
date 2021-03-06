# arp-tools

## ArpAntispoof.pl
Now works to detect [bettercap](http://github.com/bettercap/bettercap)
### Usage

```bash
Usage: ArpAntispoof.pl -i <interface(s)> -c <mac_to_protect>

        -i : Listen on specific network interface e.g wlan0. Or 'all' to listen on all interfaces
        -c : Mac address of device to protect e.g 90:90:90:90:90:90
        -v : Show packet metadata
        -V : Show packet metadata and data with optional filter
```

### To test it run

```bash
arpspoof -i wlan0 -t <your-gateway> <your-ip>
```

then

```bash
perl ArpAntispoof.pl -i <interface> -c <mac_to_protect>
```

## ArpHound.pl

### Usage

```bash
Usage: ArpHound.pl
```

### To test it run

```bash
perl ArpHound.pl
```

## ArpSpy.pl

### Usage

```bash
Usage: ArpSpy.pl -i <interface(s)> -m <mac_to_attack>

        -i : Listen on specific network interface e.g wlan0. Or 'all' to listen on all interfaces
        -m : Mac address of device to eavesdrop on e.g 90:90:90:90:90:90
        -d : Regex of data to log
        -o : File to output data
```

### To test it run

```bash
ArpSpy.pl -i <interface(s)> -m <mac_to_attack>
```