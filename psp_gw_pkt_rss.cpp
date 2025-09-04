/*
 * Copyright (c) 2024 NVIDIA CORPORATION AND AFFILIATES.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright notice, this list of
 *       conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice, this list of
 *       conditions and the following disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 *     * Neither the name of the NVIDIA CORPORATION nor the names of its contributors may be used
 *       to endorse or promote products derived from this software without specific prior written
 *       permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL NVIDIA CORPORATION BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TOR (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <doca_log.h>

#include <psp_gw_config.h>
#include <psp_gw_flows.h>
#include <psp_gw_pkt_rss.h>
#include <psp_gw_svc_impl.h>

DOCA_LOG_REGISTER(PSP_RSS);

#define MAX_RX_BURST_SIZE 256

static uint16_t max_tx_retries = 10;

/**
 * @brief High-level Rx Queue packet handler routine
 * Optionally logs the packet to the console.
 * Passes the packet to the PSP Service so it can decide whether to
 * negotiate a new tunnel.
 *
 * @params [in]: the parameters to the lcore routines
 * @port_id [in]: the port_id from which the packet was received
 * @queue_id [in]: the queue index from which the packet was received
 * @packet [in]: the received packet buffer
 */
static void handle_packet(struct lcore_params *params, uint16_t port_id, uint16_t queue_id, struct rte_mbuf *packet)
{
	uint32_t pkt_meta = rte_flow_dynf_metadata_get(packet);
	bool is_ingress_sampled = pkt_meta == params->config->ingress_sample_meta_indicator;
	bool is_egress_sampled = pkt_meta == params->config->egress_sample_meta_indicator;
	if (is_ingress_sampled || is_egress_sampled) {
		if (params->config->show_sampled_packets) {
			DOCA_LOG_INFO("SAMPLED PACKET: port %d, queue_id %d, pkt_meta 0x%x, %s",
				      port_id,
				      queue_id,
				      pkt_meta,
				      is_ingress_sampled ? "INGRESS" : "EGRESS");
			rte_pktmbuf_dump(stdout, packet, packet->data_len);
		}
		// sampled packets are NOT sent to the rpc service
	} else {
		if (params->config->show_rss_rx_packets) {
			DOCA_LOG_INFO("RSS: Received port %d, queue_id %d, pkt_meta 0x%x", port_id, queue_id, pkt_meta);
			rte_pktmbuf_dump(stdout, packet, packet->data_len);
		}

		struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(packet, struct rte_ether_hdr *);
		uint16_t ether_type = htons(eth_hdr->ether_type);
		if (ether_type == DOCA_FLOW_ETHER_TYPE_ARP) {
			handle_arp(params->config->dpdk_config.mbuf_pool, port_id, queue_id, packet, 0);
		} else {
			doca_error_t result = params->psp_svc->handle_miss_packet(packet);
			if (result == DOCA_SUCCESS)
				reinject_packet(packet, port_id);

		}
	}
}

int lcore_pkt_proc_func(void *lcore_args)
{
	auto *params = (struct lcore_params *)lcore_args;

	uint32_t lcore_id = rte_lcore_id();

	// Note lcore_id==0 is reserved for main()
	if (lcore_id == 0) {
		rte_exit(EXIT_FAILURE, "Unexpectedly entered RSS handler from main thread\n");
	}

	uint16_t queue_id = lcore_id - 1;
	uint16_t nb_nics = params->pf_port_id_list.size();
	struct rte_mbuf *rx_packets[nb_nics][MAX_RX_BURST_SIZE];


	double tsc_to_seconds = 1.0 / (double)rte_get_timer_hz();

	DOCA_LOG_INFO("L-Core %d polling queue %d (all ports)", lcore_id, queue_id);

	while (!*params->force_quit) {
		uint64_t t_start = rte_rdtsc();

		// handle high-rate tasks:
		params->psp_svc->lcore_callback();

		for(int port_id = 0; port_id < nb_nics; port_id++) {
			uint16_t nb_rx_packets = rte_eth_rx_burst(params->pf_port_id_list[port_id], queue_id, rx_packets[port_id], MAX_RX_BURST_SIZE);
			for (int i = 0; i < nb_rx_packets && !*params->force_quit; i++) {
				handle_packet(params, params->pf_port_id_list[port_id], queue_id, rx_packets[port_id][i]);
			}

			if (nb_rx_packets) {
				DOCA_LOG_INFO("%d packets on port id %d", nb_rx_packets, params->pf_port_id_list[port_id]);
				rte_pktmbuf_free_bulk(rx_packets[port_id], nb_rx_packets);
			}
			if (nb_rx_packets && params->config->show_rss_durations) {
				double sec = (double)(rte_rdtsc() - t_start) * tsc_to_seconds;
				DOCA_LOG_INFO("L-Core %d port %d: processed %d packets in %f seconds",
						lcore_id,
						params->pf_port_id_list[port_id],
						nb_rx_packets,
						sec);
			}
		}
	}

	return 0;
}

bool reinject_packet(struct rte_mbuf *packet, uint16_t port_id)
{
	uint32_t lcore_id = rte_lcore_id();
	if (lcore_id == 0) {
		DOCA_LOG_ERR("Cannot reinject packet from core 0");
		return false;
	}
	uint16_t queue_id = lcore_id - 1;

	uint16_t nsent = 0;
	for (uint16_t i = 0; i < max_tx_retries && nsent < 1; i++) {
		nsent = rte_eth_tx_burst(port_id, queue_id, &packet, 1);
	}
	DOCA_LOG_DBG("Reinjected packet on port %d", port_id);
	return nsent == 1;
}

uint16_t handle_arp(struct rte_mempool *mpool,
		    uint16_t port_id,
		    uint16_t queue_id,
		    const struct rte_mbuf *request_pkt,
		    uint32_t arp_response_meta_flag)
{
	const struct rte_ether_hdr *request_eth_hdr = rte_pktmbuf_mtod(request_pkt, struct rte_ether_hdr *);
	const struct rte_arp_hdr *request_arp_hdr = (rte_arp_hdr *)&request_eth_hdr[1];

	uint16_t arp_op = RTE_BE16(request_arp_hdr->arp_opcode);
	if (arp_op != RTE_ARP_OP_REQUEST) {
		DOCA_LOG_ERR("RSS ARP Handler: expected op %d, got %d", RTE_ARP_OP_REQUEST, arp_op);
		return 0;
	}

	struct rte_mbuf *response_pkt = rte_pktmbuf_alloc(mpool);
	if (!response_pkt) {
		DOCA_LOG_ERR("Out of memory for ARP response packets; exiting");
		return ENOMEM;
	}

	*RTE_MBUF_DYNFIELD(response_pkt, rte_flow_dynf_metadata_offs, uint32_t *) = arp_response_meta_flag;
	response_pkt->ol_flags |= rte_flow_dynf_metadata_mask;

	uint32_t pkt_size = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
	response_pkt->data_len = pkt_size;
	response_pkt->pkt_len = pkt_size;

	struct rte_ether_hdr *response_eth_hdr = rte_pktmbuf_mtod(response_pkt, struct rte_ether_hdr *);
	struct rte_arp_hdr *response_arp_hdr = (rte_arp_hdr *)&response_eth_hdr[1];

	rte_eth_macaddr_get(port_id, &response_eth_hdr->src_addr);
	response_eth_hdr->dst_addr = request_eth_hdr->src_addr;
	response_eth_hdr->ether_type = RTE_BE16(DOCA_FLOW_ETHER_TYPE_ARP);

	response_arp_hdr->arp_hardware = RTE_BE16(RTE_ARP_HRD_ETHER);
	response_arp_hdr->arp_protocol = RTE_BE16(RTE_ETHER_TYPE_IPV4);
	response_arp_hdr->arp_hlen = RTE_ETHER_ADDR_LEN;
	response_arp_hdr->arp_plen = sizeof(uint32_t);
	response_arp_hdr->arp_opcode = RTE_BE16(RTE_ARP_OP_REPLY);
	rte_eth_macaddr_get(port_id, &response_arp_hdr->arp_data.arp_sha);
	response_arp_hdr->arp_data.arp_tha = request_arp_hdr->arp_data.arp_sha;
	response_arp_hdr->arp_data.arp_sip = request_arp_hdr->arp_data.arp_tip;
	response_arp_hdr->arp_data.arp_tip = request_arp_hdr->arp_data.arp_sip;

	uint16_t nb_tx_packets = 0;
	while (nb_tx_packets < 1) {
		// This ARP reply will go to the empty pipe.
		nb_tx_packets = rte_eth_tx_burst(port_id, queue_id, &response_pkt, 1);
		if (nb_tx_packets != 1) {
			DOCA_LOG_WARN("ARP reinject: rte_eth_tx_burst returned %d", nb_tx_packets);
		}
	}

	char ip_addr_str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &request_arp_hdr->arp_data.arp_tip, ip_addr_str, INET_ADDRSTRLEN);
	DOCA_LOG_DBG("Port %d replied to ARP request for IP %s", port_id, ip_addr_str);

	return 1;
}
