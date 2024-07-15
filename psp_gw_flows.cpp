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
#include <doca_log.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>

#include "psp_gw_config.h"
#include "psp_gw_flows.h"
#include "psp_gw_utils.h"

#define IF_SUCCESS(result, expr) \
	if (result == DOCA_SUCCESS) { \
		result = expr; \
		if (likely(result == DOCA_SUCCESS)) { \
			DOCA_LOG_DBG("Success: %s", #expr); \
		} else { \
			DOCA_LOG_ERR("Error: %s: %s", #expr, doca_error_get_descr(result)); \
		} \
	} else { /* skip this expr */ \
	}

DOCA_LOG_REGISTER(PSP_GATEWAY);

static const uint32_t DEFAULT_TIMEOUT_US = 10000; /* default timeout for processing entries */
static const uint32_t PSP_ICV_SIZE = 16;

/**
 * @brief user context struct that will be used in entries process callback
 */
struct entries_status {
	bool failure;	      /* will be set to true if some entry status will not be success */
	int nb_processed;     /* number of entries that was already processed */
	int entries_in_queue; /* number of entries in queue that is waiting to process */
};

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

PSP_GatewayFlows::PSP_GatewayFlows(std::string pf_pci, psp_gw_app_config *app_config)
	: app_config(app_config),
	  pf_pci(pf_pci)
{
	monitor_count.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
}

PSP_GatewayFlows::~PSP_GatewayFlows()
{
	DOCA_LOG_INFO("Destroying PSP Gateway Flows");
}

doca_error_t PSP_GatewayFlows::init(void)
{
	doca_error_t result = DOCA_SUCCESS;

	DOCA_LOG_INFO("Initializing PSP Gateway Flows");

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
