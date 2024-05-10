/*
 * Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

// system headers
#include <signal.h>
#include <fcntl.h>
#include <memory>

// dpdk
#include <rte_ethdev.h>

// doca
#include <dpdk_utils.h>
#include <doca_argp.h>
#include <doca_dev.h>
#include <doca_flow.h>
#include <doca_log.h>
#include <doca_dpdk.h>
#include <samples/common.h>

#include <google/protobuf/util/json_util.h>
#include <grpcpp/server_builder.h>

// application
#include <psp_gw_config.h>
#include <psp_gw_bench.h>
#include <psp_gw_flows.h>
#include <psp_gw_svc_impl.h>
#include <psp_gw_params.h>
#include <psp_gw_pkt_rss.h>
#include <psp_gw_utils.h>

DOCA_LOG_REGISTER(PSP_GATEWAY);

volatile bool force_quit; // Set when signal is received

/**
 * @brief Signal handler function (SIGINT and SIGTERM signals)
 *
 * @signum [in]: signal number
 */
static void signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		DOCA_LOG_INFO("Signal %d received, preparing to exit", signum);
		force_quit = true;
	}
}

/*
 * @brief PSP Gateway application main function
 *
 * @argc [in]: command line arguments size
 * @argv [in]: array of command line arguments
 * @return: EXIT_SUCCESS on success and EXIT_FAILURE otherwise
 */
int main(int argc, char **argv)
{
	doca_error_t result;
	int nb_ports = 2;
	int exit_status = EXIT_SUCCESS;

	struct psp_gw_app_config app_config = {};
	app_config.dpdk_config.port_config.nb_ports = nb_ports;
	app_config.dpdk_config.port_config.nb_queues = 2;
	app_config.dpdk_config.port_config.switch_mode = true;
	app_config.dpdk_config.port_config.enable_mbuf_metadata = true;
	app_config.dpdk_config.port_config.isolated_mode = true;
	app_config.dpdk_config.reserve_main_thread = true;
	app_config.pf_repr_indices = strdup("[0]");
	app_config.core_mask = strdup("0x3");
	app_config.max_tunnels = 128;
	app_config.net_config.vc_enabled = false;
	app_config.net_config.crypt_offset = UINT32_MAX;
	app_config.net_config.default_psp_proto_ver = UINT32_MAX;
	app_config.log2_sample_rate = 0;
	app_config.ingress_sample_meta_indicator = 0x65656565; // arbitrary pkt_meta flag value
	app_config.egress_sample_meta_indicator = 0x43434343;
	app_config.show_sampled_packets = true;
	app_config.show_rss_rx_packets = false;
	app_config.show_rss_durations = false;

	struct psp_pf_dev pf_dev = {};
	uint16_t vf_port_id;
	std::string dev_probe_str;

	struct doca_log_backend *sdk_log;

	// Register a logger backend
	result = doca_log_backend_create_standard();
	if (result != DOCA_SUCCESS)
		return EXIT_FAILURE;

	// Register a logger backend for internal SDK errors and warnings
	result = doca_log_backend_create_with_file_sdk(stdout, &sdk_log);
	if (result != DOCA_SUCCESS)
		return EXIT_FAILURE;

	result = doca_log_backend_set_sdk_level(sdk_log, DOCA_LOG_LEVEL_WARNING);
	if (result != DOCA_SUCCESS)
		return EXIT_FAILURE;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	result = psp_gw_argp_exec(argc, argv, &app_config);
	if (result != DOCA_SUCCESS) {
		return EXIT_FAILURE;
	}

	if (app_config.net_config.crypt_offset == UINT32_MAX) {
		// If not specified by argp, select a default crypt_offset
		app_config.net_config.crypt_offset =
			app_config.net_config.vc_enabled ? DEFAULT_CRYPT_OFFSET_VC_ENABLED : DEFAULT_CRYPT_OFFSET;
		DOCA_LOG_INFO("Selected crypt_offset of %d", app_config.net_config.crypt_offset);
	}

	if (app_config.net_config.default_psp_proto_ver == UINT32_MAX) {
		// If not specified by argp, select a default PSP protocol version
		app_config.net_config.default_psp_proto_ver = DEFAULT_PSP_VERSION;
		DOCA_LOG_INFO("Selected psp_ver %d", app_config.net_config.default_psp_proto_ver);
	}

	// init devices
	result = open_doca_device_with_pci(app_config.pf_pcie_addr.c_str(), nullptr, &pf_dev.dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open device %s: %s",
			     app_config.pf_pcie_addr.c_str(),
			     doca_error_get_descr(result));
		doca_argp_destroy();
		return EXIT_FAILURE;
	}

	dev_probe_str = std::string("dv_flow_en=2,"	 // hardware steering
				    "dv_xmeta_en=4,"	 // extended flow metadata support
				    "fdb_def_rule_en=0," // disable default root flow table rule
				    "vport_match=1,"
				    "repr_matching_en=0,"
				    "representor=") +
			app_config.pf_repr_indices; // indicate which representors to probe

	result = doca_dpdk_port_probe(pf_dev.dev, dev_probe_str.c_str());
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to probe dpdk port for secured port: %s", doca_error_get_descr(result));
		return result;
	}
	DOCA_LOG_INFO("Probed %s,%s", app_config.pf_pcie_addr.c_str(), dev_probe_str.c_str());

	pf_dev.port_id = 0;

	app_config.dpdk_config.port_config.nb_ports = rte_eth_dev_count_avail();

	rte_eth_macaddr_get(pf_dev.port_id, &pf_dev.src_mac);
	result = doca_devinfo_get_ipv6_addr(doca_dev_as_devinfo(pf_dev.dev),
					    pf_dev.src_pip,
					    DOCA_DEVINFO_IPV6_ADDR_SIZE);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to find IPv6 addr for PF: %s", doca_error_get_descr(result));
		return result;
	}

	pf_dev.src_mac_str = mac_to_string(pf_dev.src_mac);
	pf_dev.src_pip_str = ipv6_to_string(pf_dev.src_pip);
	DOCA_LOG_INFO("Port %d: Detected PF mac addr: %s, IPv6 addr: %s, total ports: %d",
		      pf_dev.port_id,
		      pf_dev.src_mac_str.c_str(),
		      pf_dev.src_pip_str.c_str(),
		      app_config.dpdk_config.port_config.nb_ports);

	vf_port_id = pf_dev.port_id + 1;

	if (app_config.nexthop_enable && !app_config.nexthop_dmac_lookup.empty()) {
		bool my_pf_found = false;
		for (const auto &pf_nh_pair : app_config.nexthop_dmac_lookup) {
			rte_ether_addr pf_mac;
			(void)rte_ether_unformat_addr(pf_nh_pair.first.c_str(), &pf_mac);
			if (rte_is_same_ether_addr(&pf_mac, &pf_dev.src_mac)) {
				(void)rte_ether_unformat_addr(pf_nh_pair.second.c_str(), &app_config.nexthop_dmac);
				my_pf_found = true;
				DOCA_LOG_INFO("Selected next-hop %s", pf_nh_pair.second.c_str());
				break;
			}
		}
		if (!my_pf_found) {
			DOCA_LOG_ERR("A next-hop file was specified, but my PF MAC (%s) was not found",
				     pf_dev.src_mac_str.c_str());
			return result;
		}
	}

	// Update queues and ports
	result = dpdk_queues_and_ports_init(&app_config.dpdk_config);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to update application ports and queues: %s", doca_error_get_descr(result));
		exit_status = EXIT_FAILURE;
		goto dpdk_destroy;
	}

	if (app_config.run_benchmarks_and_exit) {
		app_config.max_tunnels = 64 * 1024;
		doca_log_level_set_global_lower_limit(DOCA_LOG_LEVEL_WARNING);

		PSP_GatewayFlows psp_flows(&pf_dev, vf_port_id, &app_config);

		result = psp_flows.init();
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to create flow pipes");
			exit_status = EXIT_FAILURE;
			goto dpdk_destroy;
		}

		if (app_config.run_benchmarks_and_exit) {
			psp_gw_run_benchmarks(&psp_flows);
		}
	} else {
		PSP_GatewayFlows psp_flows(&pf_dev, vf_port_id, &app_config);

		result = psp_flows.init();
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to create flow pipes");
			exit_status = EXIT_FAILURE;
			goto dpdk_destroy;
		}

		PSP_GatewayImpl psp_svc(&app_config, &psp_flows);

		struct lcore_params lcore_params = {
			&force_quit,
			&app_config,
			&pf_dev,
			&psp_flows,
			&psp_svc,
		};

		uint32_t lcore_id;
		RTE_LCORE_FOREACH_WORKER(lcore_id)
		{
			rte_eal_remote_launch(lcore_pkt_proc_func, &lcore_params, lcore_id);
		}

		std::string server_address = app_config.local_svc_addr;
		if (server_address.empty()) {
			server_address = "0.0.0.0";
		}
		if (server_address.find(":") == std::string::npos) {
			server_address += ":" + std::to_string(PSP_GatewayImpl::DEFAULT_HTTP_PORT_NUM);
		}
		grpc::ServerBuilder builder;
		builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
		builder.RegisterService(&psp_svc);
		auto server_instance = builder.BuildAndStart();
		std::cout << "Server listening on " << server_address << std::endl;

		// If configured to create all tunnels at startup, create a list of
		// pending tunnels here. Each invocation of try_connect will
		// remove entries from the list as tunnels are created.
		// Otherwise, this list will be left empty and tunnels will be created
		// on demand via the miss path.
		rte_be32_t local_vf_addr = 0;
		if (inet_pton(AF_INET, app_config.local_vf_addr.c_str(), &local_vf_addr) != 1) {
			DOCA_LOG_ERR("Invalid local_vf_addr: %s", app_config.local_vf_addr.c_str());
			exit_status = EXIT_FAILURE;
			goto dpdk_destroy;
		}

		std::vector<psp_gw_host> remotes_to_connect;
		if (app_config.create_tunnels_at_startup) {
			remotes_to_connect = app_config.net_config.hosts;
		}

		while (!force_quit) {
			psp_svc.try_connect(remotes_to_connect, local_vf_addr);
			sleep(1);

			psp_flows.show_static_flow_counts();
			psp_svc.show_flow_counts();
		}

		DOCA_LOG_INFO("Shutting down");

		server_instance->Shutdown();
		server_instance.reset();

		RTE_LCORE_FOREACH_WORKER(lcore_id)
		{
			DOCA_LOG_INFO("Stopping L-Core %d", lcore_id);
			rte_eal_wait_lcore(lcore_id);
		}
	}

	// flow cleanup
	dpdk_queues_and_ports_fini(&app_config.dpdk_config);

dpdk_destroy:
	dpdk_fini();
	doca_argp_destroy();

	return exit_status;
}
