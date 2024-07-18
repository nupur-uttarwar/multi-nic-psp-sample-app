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

#include <string>
#include <vector>

#include <doca_flow.h>
#include <doca_flow_crypto.h>
#include <doca_dev.h>
#include <doca_log.h>
#include <doca_dpdk.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <samples/common.h>
#include <rte_ip.h>

#include "psp_gw_config.h"
#include "psp_gw_flows.h"
#include "psp_gw_utils.h"

DOCA_LOG_REGISTER(PSP_GATEWAY);

static const uint32_t DEFAULT_TIMEOUT_US = 10000; /* default timeout for processing entries */
static const uint32_t PSP_ICV_SIZE = 16;


/**
 * @brief packet header structure to simplify populating the encap_data array for encap ipv6 data
 */
struct eth_ipv6_psp_tunnel_hdr {
	// encapped Ethernet header contents.
	rte_ether_hdr eth;

	// encapped IP header contents (extension header not supported)
	rte_ipv6_hdr ip;

	rte_udp_hdr udp;

	// encapped PSP header contents.
	rte_psp_base_hdr psp;
	rte_be64_t psp_virt_cookie;

} __rte_packed __rte_aligned(2);

/**
 * @brief packet header structure to simplify populating the encap_data array for encap ipv4 data
 */
struct eth_ipv4_psp_tunnel_hdr {
	// encapped Ethernet header contents.
	rte_ether_hdr eth;

	// encapped IP header contents (extension header not supported)
	rte_ipv4_hdr ip;

	rte_udp_hdr udp;

	// encapped PSP header contents.
	rte_psp_base_hdr psp;
	rte_be64_t psp_virt_cookie;

} __rte_packed __rte_aligned(2);

const uint8_t PSP_SAMPLE_ENABLE = 1 << 7;

PSP_GatewayFlows::PSP_GatewayFlows(std::string pf_pci, std::string pf_repr_indices, psp_gw_app_config *app_config)
	: app_config(app_config),
	  pf_pci(pf_pci),
	  pf_repr_indices(pf_repr_indices)
{
	monitor_count.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
}

PSP_GatewayFlows::~PSP_GatewayFlows()
{
	DOCA_LOG_INFO("Destroying PSP Gateway Flows");
}

doca_error_t PSP_GatewayFlows::init_dev(void)
{
	doca_error_t result = DOCA_SUCCESS;

	std::string dev_probe_str = std::string("dv_flow_en=2,"	 // hardware steering
		"dv_xmeta_en=4,"	 // extended flow metadata support
		"fdb_def_rule_en=0," // disable default root flow table rule
		"vport_match=1,"
		"repr_matching_en=0,"
		"representor=") +
		pf_repr_indices; // indicate which representors to probe

	IF_SUCCESS(result, open_doca_device_with_pci(pf_pci.c_str(), nullptr, &pf_dev.dev));
	IF_SUCCESS(result, doca_dpdk_port_probe(pf_dev.dev, dev_probe_str.c_str()));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to probe device %s: %s", pf_pci.c_str(), doca_error_get_descr(result));
		return result;
	}

	pf_dev.pf_port_id = 0;
	pf_dev.vf_port_id = pf_dev.pf_port_id + 1;

	rte_eth_macaddr_get(pf_dev.pf_port_id, &pf_dev.pf_mac);
	pf_dev.pf_mac_str = mac_to_string(pf_dev.pf_mac);

	rte_eth_macaddr_get(pf_dev.vf_port_id, &pf_dev.vf_mac);
	pf_dev.vf_mac_str = mac_to_string(pf_dev.vf_mac);

	if (app_config->outer == DOCA_FLOW_L3_TYPE_IP4) {
		pf_dev.local_pip.type = DOCA_FLOW_L3_TYPE_IP4;
		result = doca_devinfo_get_ipv4_addr(doca_dev_as_devinfo(pf_dev.dev),
						    (uint8_t *)&pf_dev.local_pip.ipv4_addr,
						    DOCA_DEVINFO_IPV4_ADDR_SIZE);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to find IPv4 addr for PF: %s", doca_error_get_descr(result));
			return result;
		}
		pf_dev.local_pip_str = ipv4_to_string(pf_dev.local_pip.ipv4_addr);
	} else {
		pf_dev.local_pip.type = DOCA_FLOW_L3_TYPE_IP6;
		result = doca_devinfo_get_ipv6_addr(doca_dev_as_devinfo(pf_dev.dev),
						    (uint8_t *)pf_dev.local_pip.ipv6_addr,
						    DOCA_DEVINFO_IPV6_ADDR_SIZE);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to find IPv6 addr for PF: %s", doca_error_get_descr(result));
			return result;
		}
		pf_dev.local_pip_str = ipv6_to_string(pf_dev.local_pip.ipv6_addr);
	}

	DOCA_LOG_INFO("Probed PF %s, VF %s on PCI %s", pf_dev.pf_mac_str.c_str(), pf_dev.vf_mac_str.c_str(), pf_pci.c_str());

	return result;
}

doca_error_t PSP_GatewayFlows::init_flows(void)
{
	doca_error_t result = DOCA_SUCCESS;

	DOCA_LOG_INFO("Initializing PSP Gateway Flows on port %d", pf_dev.pf_port_id);

	return result;
}

doca_error_t rotate_master_key(void) {
	DOCA_LOG_INFO("Rotating master key");

	return DOCA_SUCCESS;
}

std::vector<doca_error_t> PSP_GatewayFlows::update_ingress_paths(
	const std::vector<psp_session_desc_t> &sessions,
	const std::vector<spi_key_t> &spi_keys)
{
	DOCA_LOG_INFO("Updating ingress paths");

	std::vector<doca_error_t> result;

	// Read current sessions, update them

	return result;
}


std::vector<doca_error_t> PSP_GatewayFlows::create_ingress_paths(
	const std::vector<psp_session_desc_t> &sessions,
	const std::vector<spi_key_t> &spi_keys)
{
	DOCA_LOG_INFO("Creating ingress paths");

	std::vector<doca_error_t> result;
	for(auto &session : sessions) {
		assert(!(session.local_vip.empty() || session.remote_vip.empty() || session.remote_pip.empty()));

		result.push_back(DOCA_SUCCESS);
	}

	return result;
}

std::vector<doca_error_t> PSP_GatewayFlows::delete_ingress_paths(
	const std::vector<psp_session_desc_t> &sessions)
{
	DOCA_LOG_INFO("Deleting ingress paths");

	std::vector<doca_error_t> result;
	for(auto &session : sessions) {
		assert(!(session.local_vip.empty() || session.remote_vip.empty() || session.remote_pip.empty()));

		result.push_back(DOCA_SUCCESS);
	}

	return result;
}

std::vector<doca_error_t> PSP_GatewayFlows::set_egress_paths(
	const std::vector<psp_session_desc_t> &sessions,
	const std::vector<spi_key_t> &spi_keys)
{
	DOCA_LOG_INFO("Setting egress paths");

	std::vector<doca_error_t> result;
	for(auto &session : sessions) {
		assert(!(session.local_vip.empty() || session.remote_vip.empty() || session.remote_pip.empty()));

		result.push_back(DOCA_SUCCESS);
	}

	return result;
}

doca_error_t PSP_GatewayFlows::start_port(uint16_t port_id, doca_dev *port_dev, doca_flow_port **port)
{
	doca_flow_port_cfg *port_cfg;
	doca_error_t result = DOCA_SUCCESS;

	IF_SUCCESS(result, doca_flow_port_cfg_create(&port_cfg));

	std::string port_id_str = std::to_string(port_id); // note that set_devargs() clones the string contents
	IF_SUCCESS(result, doca_flow_port_cfg_set_devargs(port_cfg, port_id_str.c_str()));
	IF_SUCCESS(result, doca_flow_port_cfg_set_dev(port_cfg, port_dev));
	IF_SUCCESS(result, doca_flow_port_start(port_cfg, port));

	if (result == DOCA_SUCCESS) {
		rte_ether_addr port_mac_addr;
		rte_eth_macaddr_get(port_id, &port_mac_addr);
		DOCA_LOG_INFO("Started port_id %d, mac-addr: %s", port_id, mac_to_string(port_mac_addr).c_str());
	}

	if (port_cfg) {
		doca_flow_port_cfg_destroy(port_cfg);
	}
	return result;
}

