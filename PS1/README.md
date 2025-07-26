# Problem statement 1: Drop packets using eBPF
Write an eBPF code to drop the TCP packets on a port (def: 4040). Additionally, if you can make the port number configurable from the userspace, that will be a big plus.


## Description
PS1 implements an XDP program that filters TCP packets at the network interface level. It can drop packets destined for specific ports and maintain statistics of dropped packets.

### Features
- **Interface-level filtering**: Operates at the XDP hook for maximum performance
- **Configurable port filtering**: Drop TCP packets targeting specified ports (default: 4040)
- **Packet statistics**: Real-time monitoring of dropped packet counts
- **Multiple variants**: Different implementation approaches available

## Usage
```bash
cd PS1
go generate  # Generate Go bindings from eBPF C code
go build -o packet-dropper
sudo ./packet-dropper <interface_name> [port]
```

**Examples:**
```bash
# Drop TCP packets on port 4040 (default) for lo interface
sudo ./packet-dropper lo

# Drop TCP packets on port 8080 for eth0 interface
sudo ./packet-dropper lo 8080
```

## Implementation Details
- **XDP Hook**: Attaches to network interface for early packet processing
- **Map Types**: Uses BPF_MAP_TYPE_ARRAY for configuration and statistics
- **Protocol Filtering**: Filters IPv4 TCP packets based on destination port

## Testing
```bash
# Terminal 1: Start the XDP program (for e.g. port = 8745, interface = lo)
sudo ./packet-dropper lo 8745

# Terminal 2: Send traffic to that port
sudo hping3 -S -p 8745 localhost

```
