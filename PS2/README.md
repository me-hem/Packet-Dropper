# Problem statement 2: Drop packets only for a given process
Write an eBPF code to allow traffic only at a specific TCP port (default 4040) for a given process name (for e.g, "myprocess"). All the traffic to all other ports for only that process should be dropped.


## Description
PS2 implements a cgroup-based eBPF program that allow traffic only at a specific TCP port for a specific process.

## Features
- **Process-aware filtering**: Filters connections based on process name (e.g., "myprocess")
- **cgroup integration**: Uses cgroup v2 for process management
- **Connection statistics**: Tracks dropped connection attempts


## Usage
```bash
cd PS2
go generate  # Generate Go bindings from eBPF C code
go build -o packet-dropper
sudo ./packet-dropper <interface_name>
```

## Implementation Details
- **cgroup Hook**: Attaches to `cgroup/connect4` hook
- **Process Identification**: Uses `bpf_get_current_comm()` to identify processes
- **Allowed Port**: Only permits connections to port 4040 for target process

## Testing
```bash
# Terminal 1: Start the XDP program (for e.g. interface = lo)
sudo ./packet-dropper lo

# Terminal 2: Send traffic to that process
cp $(which curl) <process_name>    #create dummy process
sudo ./<process_name> http://localhost:<port>

```
