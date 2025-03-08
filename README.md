# XDP vs. TCP 

Repository for comparing XDP and TC eBPF performance

Run HTTP server using:
```
python3 -m http.server 8080
```

Install `bpftop`: 
```
curl -fLJ https://github.com/Netflix/bpftop/releases/latest/download/bpftop-x86_64-unknown-linux-gnu -o bpftop && chmod +x bpftop
```

Run eBPF program:
```
sudo ./drop [-i] [net-interface]
```
**NOTE**: Find the network interface to attach to using `ìp a`. By default it attaches to `lo` (localhost).
