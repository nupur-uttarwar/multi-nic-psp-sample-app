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

#include <arpa/inet.h>
#include <doca_log.h>
#include <doca_flow_crypto.h>

#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>

#include <psp_gw_svc_impl.h>
#include <psp_gw_config.h>
#include <psp_gw_flows.h>
#include <psp_gw_pkt_rss.h>
#include <psp_gw_utils.h>

DOCA_LOG_REGISTER(PSP_GW_SVC);

PSP_GatewayImpl::PSP_GatewayImpl(psp_gw_app_config *config, std::string pf_pci, std::string repr_indices)
	: config(config)
{
	psp_flows = std::make_unique<PSP_GatewayFlows>(pf_pci, repr_indices, config);
}

doca_error_t PSP_GatewayImpl::handle_miss_packet(struct rte_mbuf *packet)
{
	if (config->create_tunnels_at_startup)
		return DOCA_SUCCESS; // no action; tunnels to be created by the main loop

	const auto *eth_hdr = rte_pktmbuf_mtod(packet, struct rte_ether_hdr *);
	if (eth_hdr->ether_type != RTE_BE16(RTE_ETHER_TYPE_IPV4))
		return DOCA_SUCCESS; // no action

	const auto *ipv4_hdr = rte_pktmbuf_mtod_offset(packet, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
	std::string dst_vip = ipv4_to_string(ipv4_hdr->dst_addr);

	DOCA_LOG_INFO("Handling miss packet to %s", dst_vip.c_str());
	return DOCA_SUCCESS;
}


::grpc::Status PSP_GatewayImpl::RequestMultipleTunnelParams(::grpc::ServerContext *context,
							    const ::psp_gateway::MultiTunnelRequest *request,
							    ::psp_gateway::MultiTunnelResponse *response)
{
	return ::grpc::Status::OK;
}


::grpc::Status PSP_GatewayImpl::RequestKeyRotation(::grpc::ServerContext *context,
						   const ::psp_gateway::KeyRotationRequest *request,
						   ::psp_gateway::KeyRotationResponse *response)
{
	(void)context;
	DOCA_LOG_DBG("Received PSP Master Key Rotation Request");

	response->set_request_id(request->request_id());

	if (request->issue_new_keys()) {
		return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "Re-key not implemented");
	}

	// doca_error_t result = doca_flow_crypto_psp_master_key_rotate(pf->port_obj);
	// if (result != DOCA_SUCCESS) {
	// 	return ::grpc::Status(::grpc::StatusCode::UNKNOWN, "Key Rotation Failed");
	// }

	return ::grpc::Status::OK;
}

size_t PSP_GatewayImpl::try_connect(std::vector<psp_gw_host> &hosts, rte_be32_t local_vf_addr)
{
	size_t num_connected = 0;
	// for (auto host_iter = hosts.begin(); host_iter != hosts.end(); /* increment below */) {
	// 	doca_error_t result = request_tunnel_to_host(&*host_iter, local_vf_addr, 0, false, true, false);
	// 	if (result == DOCA_SUCCESS) {
	// 		++num_connected;
	// 		host_iter = hosts.erase(host_iter);
	// 	} else {
	// 		++host_iter;
	// 	}
	// }
	return num_connected;
}

doca_error_t PSP_GatewayImpl::show_flow_counts(void)
{
	// for (auto &session : sessions) {
	// 	psp_flows->show_session_flow_count(session.first, session.second);
	// }
	return DOCA_SUCCESS;
}


::psp_gateway::PSP_Gateway::Stub *PSP_GatewayImpl::get_stub(const std::string &remote_host_ip)
{
	auto stubs_iter = stubs.find(remote_host_ip);
	if (stubs_iter != stubs.end()) {
		return stubs_iter->second.get();
	}

	std::string remote_host_addr = remote_host_ip;
	if (remote_host_addr.find(":") == std::string::npos) {
		remote_host_addr += ":" + std::to_string(DEFAULT_HTTP_PORT_NUM);
	}
	auto channel = grpc::CreateChannel(remote_host_addr, grpc::InsecureChannelCredentials());
	stubs_iter = stubs.emplace(remote_host_ip, psp_gateway::PSP_Gateway::NewStub(channel)).first;

	DOCA_LOG_INFO("Created gRPC stub for remote host %s", remote_host_addr.c_str());

	return stubs_iter->second.get();
}

doca_error_t PSP_GatewayImpl::init_devs(void) {
	doca_error_t result = DOCA_SUCCESS;
	DOCA_LOG_INFO("Initializing PSP Gateway Devices");

	IF_SUCCESS(result, psp_flows->init_dev());

	return result;
}

doca_error_t PSP_GatewayImpl::init_flows(void) {
	doca_error_t result = DOCA_SUCCESS;
	DOCA_LOG_INFO("Initializing PSP Gateway Flows");

	IF_SUCCESS(result, init_doca_flow());
	IF_SUCCESS(result, psp_flows->init_flows());

	return result;
}

doca_error_t PSP_GatewayImpl::init_doca_flow(void)
{
	doca_error_t result = DOCA_SUCCESS;
	uint16_t nb_queues = config->dpdk_config.port_config.nb_queues;

	uint16_t rss_queues[nb_queues];
	for (int i = 0; i < nb_queues; i++)
		rss_queues[i] = i;

	struct doca_flow_resource_rss_cfg rss_config = {};
	rss_config.nr_queues = nb_queues;
	rss_config.queues_array = rss_queues;

	/* init doca flow with crypto shared resources */
	struct doca_flow_cfg *flow_cfg;
	IF_SUCCESS(result, doca_flow_cfg_create(&flow_cfg));
	IF_SUCCESS(result, doca_flow_cfg_set_pipe_queues(flow_cfg, nb_queues));
	IF_SUCCESS(result, doca_flow_cfg_set_nr_counters(flow_cfg, config->max_tunnels * NUM_OF_PSP_SYNDROMES + 10));
	IF_SUCCESS(result, doca_flow_cfg_set_mode_args(flow_cfg, "switch,hws,isolated,expert"));
	IF_SUCCESS(result, doca_flow_cfg_set_cb_entry_process(flow_cfg, PSP_GatewayImpl::check_for_valid_entry));
	IF_SUCCESS(result, doca_flow_cfg_set_default_rss(flow_cfg, &rss_config));
	IF_SUCCESS(result,
		   doca_flow_cfg_set_nr_shared_resource(flow_cfg,
							config->max_tunnels + 1,
							DOCA_FLOW_SHARED_RESOURCE_PSP));
	IF_SUCCESS(result, doca_flow_cfg_set_nr_shared_resource(flow_cfg, 4, DOCA_FLOW_SHARED_RESOURCE_MIRROR));
	IF_SUCCESS(result, doca_flow_init(flow_cfg));

	if (result == DOCA_SUCCESS)
		DOCA_LOG_INFO("Initialized DOCA Flow for a max of %d tunnels", config->max_tunnels);

	if (flow_cfg)
		doca_flow_cfg_destroy(flow_cfg);
	return result;
}

void PSP_GatewayImpl::launch_lcores(volatile bool *force_quit) {
	struct lcore_params lcore_params = {
		force_quit,
		config,
		0,
		this,
	};

	uint32_t lcore_id;
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		rte_eal_remote_launch(lcore_pkt_proc_func, &lcore_params, lcore_id);
	}

}

void PSP_GatewayImpl::kill_lcores() {
	uint32_t lcore_id;

	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		DOCA_LOG_INFO("Stopping L-Core %d", lcore_id);
		rte_eal_wait_lcore(lcore_id);
	}
}

/*
 * Entry processing callback
 *
 * @entry [in]: entry pointer
 * @pipe_queue [in]: queue identifier
 * @status [in]: DOCA Flow entry status
 * @op [in]: DOCA Flow entry operation
 * @user_ctx [out]: user context
 */
void PSP_GatewayImpl::check_for_valid_entry(doca_flow_pipe_entry *entry,
					     uint16_t pipe_queue,
					     enum doca_flow_entry_status status,
					     enum doca_flow_entry_op op,
					     void *user_ctx)
{
	(void)entry;
	(void)op;
	(void)pipe_queue;

	auto *entry_status = (entries_status *)user_ctx;

	if (entry_status == NULL || op != DOCA_FLOW_ENTRY_OP_ADD)
		return;

	if (status != DOCA_FLOW_ENTRY_STATUS_SUCCESS)
		entry_status->failure = true; /* set failure to true if processing failed */

	entry_status->nb_processed++;
	entry_status->entries_in_queue--;
}