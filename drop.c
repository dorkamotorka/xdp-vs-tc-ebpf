//go:build ignore
/* XDP and TC eBPF programs to drop packets on port 8080 */
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "parse_helpers.h"

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define DROP_PORT 8080

SEC("xdp") 
int xdp_drop_port_8080(struct xdp_md *ctx) {
	void *data_end = (void *)(unsigned long long)ctx->data_end;
	void *data = (void *)(unsigned long long)ctx->data;
	int ip_type;
	int tcp_type;
	struct hdr_cursor nh;
	struct iphdr *ip;
	struct ipv6hdr *ipv6;
	struct tcphdr *tcp;
	nh.pos = data;

	// Parse Ethernet and IP headers
	struct ethhdr *eth;
	int eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) { 
		ip_type = parse_iphdr(&nh, data_end, &ip);
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6);
	} else {
		// Default action, pass it up the GNU/Linux network stack to be handled
		return XDP_PASS;
	}

	// If not TCP Protocol -> XDP_PASS
	if (ip_type != IPPROTO_TCP) {
		return XDP_PASS;
	}
 
	// Parse TCP header
	tcp_type = parse_tcphdr(&nh, data_end, &tcp);
	if ((void*)(tcp + 1) > data_end) {
		return XDP_PASS;
	}

	// Drop all packets on port 8080
  	if (bpf_ntohs(tcp->dest) == DROP_PORT) {
		bpf_printk("Dropping packets on TCP port 8080 using XDP!");
		return XDP_DROP;
	}

	return XDP_PASS;
}

SEC("tc") 
int tc_drop_port_8080(struct __sk_buff *ctx) {
	void *data_end = (void *)(unsigned long long)ctx->data_end;
	void *data = (void *)(unsigned long long)ctx->data;
	int ip_type;
	int tcp_type;
	struct hdr_cursor nh;
	struct iphdr *ip;
	struct ipv6hdr *ipv6;
	struct tcphdr *tcp;
	nh.pos = data;

	// Parse Ethernet and IP headers
	struct ethhdr *eth;
	int eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &ip);
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6);
	} else {
		// Default action, pass it up the GNU/Linux network stack to be handled
		return TC_ACT_OK;
	}

	// If not TCP Protocol -> TC_ACT_OK 
	if (ip_type != IPPROTO_TCP) {
		return TC_ACT_OK;
	}

	if ((void*)(ip + 1) > data_end) {
		return TC_ACT_OK;
	}

	tcp_type = parse_tcphdr(&nh, data_end, &tcp);
	if ((void*)(tcp + 1) > data_end) {
		return TC_ACT_OK;
	}

	if (bpf_ntohs(tcp->dest) == DROP_PORT) {
		bpf_printk("Dropping packets on TCP port 8080 using TC!");
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
