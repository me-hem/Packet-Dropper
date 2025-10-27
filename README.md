# eBPF-based Network Filtering

This repository contains two eBPF programs that demonstrate different approaches to network traffic filtering using the Extended Berkeley Packet Filter (eBPF) framework.

## Overview

- **PS1**: Drop packets using eBPF - XDP (eXpress Data Path) packet filtering at the network interface level
- **PS2**: Drop packets only for a given process - cgroup-based connection filtering at the socket level

Both programs use the Cilium eBPF library for Go and demonstrate practical network security implementations.

## Project Structure

```
.
├── PS1/                   
│   ├── main.go            # Go application for XDP program
│   ├── xdp.c              # eBPF XDP program in C
│   ├── variants/          
│   │   ├── xdp(0)         # Basic TCP packet dropping
│   │   └── xdp(1)         # Port-specific filtering
│   ├── go.mod             
│   ├── go.sum             
│   └── README.md          # PS1-Solution
├── PS2/                   
│   ├── main.go            # Go application for cgroup program
│   ├── cgroup_connect4.c  # eBPF cgroup program in C
│   ├── go.mod             
│   ├── go.sum             
│   └── README.md          # PS2-Solution
├── PS3/                   
│   └── README.md          # PS3-Solution
└── README.md              # Main project documentation
