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

PSP_GatewayImpl::PSP_GatewayImpl(psp_gw_app_config *config, PSP_GatewayFlows *psp_flows)
	: config(config),
	  psp_flows(psp_flows)
{
	return;
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
