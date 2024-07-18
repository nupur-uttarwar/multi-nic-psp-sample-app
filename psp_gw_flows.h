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

#ifndef FLOWS_H_
#define FLOWS_H_

#include <netinet/in.h>
#include <rte_ether.h>
#include <string>
#include <unordered_map>

#include <doca_flow.h>
#include <doca_dev.h>

#include "psp_gw_config.h"

static const int NUM_OF_PSP_SYNDROMES = 4; // None, ICV Fail, Bad Trailer

struct psp_gw_app_config;

/**
 * @brief Maintains the state of the host PF
 */
struct psp_pf_dev {
	struct doca_dev *dev;

	uint16_t pf_port_id;
	struct doca_flow_port *pf_port;
	struct rte_ether_addr pf_mac;
	std::string pf_mac_str;

	uint16_t vf_port_id;
	struct doca_flow_port *vf_port;
	struct rte_ether_addr vf_mac;
	std::string vf_mac_str;

	struct doca_flow_ip_addr local_pip; // Physical/Outer IP addr
	std::string local_pip_str;

};

struct psp_session_desc_t {
	std::string local_vip;
	std::string remote_vip;
	std::string remote_pip;
};

/**
 * @brief describes a PSP tunnel connection to a single address
 *        on a remote host
 */
struct psp_session_egress_t {
	struct psp_session_desc_t key;

	uint32_t spi_egress;  //!< Security Parameter Index on the wire - host-to-net
	uint32_t crypto_id;   //!< Internal shared-resource index
	uint64_t vc;		//!< Virtualization cookie, if enabled

	doca_flow_pipe_entry *encap_encrypt_entry;
	uint64_t pkt_count_egress;
};

/**
 * @brief describes a PSP tunnel connection from a single address
 *        on a remote host
 */
struct psp_session_ingress_t {
	struct psp_session_desc_t key;

	uint32_t spi_ingress; //!< Security Parameter Index on the wire - net-to-host

	struct doca_flow_pipe_entry *ingress_acl_entry;
	uint64_t pkt_count_ingress;
};


struct spi_key_t {
	uint64_t spi;
	void *key;
};

/**
 * @brief The entity which owns all the doca flow shared
 *        resources and flow pipes (but not sessions).
 */
class PSP_GatewayFlows {
public:
	/**
	 * @brief Constructs the object. This operation cannot fail.
	 * @param [in] pf_pci The PCI address of the PF device
	 * @param [in] pf_repr_indices The indices of the PF device representors
	 * @param [in] app_config The application configuration
	 */
	PSP_GatewayFlows(std::string pf_pci, std::string pf_repr_indices, psp_gw_app_config *app_config);

	/**
	 * Deallocates all associated DOCA objects.
	 * In case of failure, an error is logged and progress continues.
	 */
	virtual ~PSP_GatewayFlows(void);

	/**
	 * @brief Probes the PF device and its representors.
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t init_dev(void);

	/**
	 * @brief Initialized the DOCA resources.
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t init_flows(void);

	/**
	 * @brief Rotate the master key.
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t rotate_master_key(void);

	/**
	 * @brief Re-generate all current ingress paths with new SPIs and keys.
	 * @param [out] sessions The sessions which were successfully updated
	 * @param [out] spi_keys The SPIs and keys to use for each session. Invalid if
	 * 	  the return value is DOCA_ERROR.
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	std::vector<doca_error_t> update_ingress_paths(
		const std::vector<psp_session_desc_t> &sessions,
		const std::vector<struct spi_key_t> &spi_keys
	);

	/**
	 * @brief Create new ingress paths.
	 * @param [in] sessions The sessions to update
	 * @param [out] spi_keys The SPIs and keys to use for each session. Invalid if
	 * 	  the return value is DOCA_ERROR.
	 *
	 * @return: vector of DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	std::vector<doca_error_t> create_ingress_paths(
		const std::vector<struct psp_session_desc_t> &sessions,
		const std::vector<struct spi_key_t> &spi_keys
	);

	/**
	 * @brief Delete the indicated ingress paths.
	 * @param [in] sessions The sessions to delete
	 *
	 * @return: vector of DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	std::vector<doca_error_t> delete_ingress_paths(
		const std::vector<psp_session_desc_t> &sessions
	);

	/**
	 * @brief Set the egress path for sessions[i] to use spi[i] and key[i]
	 * @param [in] sessions The sessions to update
	 * @param [in] spi_keys The SPIs and keys to use for each session.
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	std::vector<doca_error_t> set_egress_paths(
		const std::vector<psp_session_desc_t> &sessions,
		const std::vector<struct spi_key_t> &spi_keys
	);

private:

	bool sampling_enabled (void) {
		return app_config->log2_sample_rate > 0;
	}

	// Input during init
	psp_gw_app_config *app_config{};
	std::string pf_pci;
	std::string pf_repr_indices;

	// Queried state during init
	psp_pf_dev pf_dev{};


	struct doca_flow_monitor monitor_count{};
};

#endif /* FLOWS_H_ */
