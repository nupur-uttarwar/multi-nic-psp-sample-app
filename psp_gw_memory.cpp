#include <unistd.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <sys/types.h>

#include <doca_log.h>

#include "psp_gw_memory.h"

DOCA_LOG_REGISTER(PSP_GW_Memory);

PSPMemoryTracker::PSPMemoryTracker(struct psp_gw_app_config *app_config) : app_config_(app_config)
{
}

PSPMemoryTracker::~PSPMemoryTracker()
{
}

doca_error_t PSPMemoryTracker::init()
{
	if (!app_config_->memory_tracking_enabled) {
		return DOCA_SUCCESS;
	}

	log_file_.open(app_config_->memory_log_path);
	if (!log_file_.is_open()) {
		DOCA_LOG_ERR("Failed to open memory log file: %s", app_config_->memory_log_path.c_str());
		return DOCA_ERROR_IO_FAILED;
	}

	// Write header
	log_file_ << "Timestamp,RSS(bytes)";
	for (const auto &nic : app_config_->net_config.local_nics) {
		log_file_ << ",FW_Pages(" << nic.pci << ")";
	}
	log_file_ << ",Message\n";
	log_file_.flush();

	return DOCA_SUCCESS;
}

doca_error_t PSPMemoryTracker::get_process_rss(uint64_t &rss) const
{
	const char *status_file_path = "/proc/self/status";
	std::ifstream status_file(status_file_path);
	if (!status_file.is_open()) {
		DOCA_LOG_ERR("Failed to open %s", status_file_path);
		return DOCA_ERROR_IO_FAILED;
	}

	std::string line;
	constexpr std::string_view vmrss = "VmRSS:";
	while (std::getline(status_file, line)) {
		if (line.find(vmrss) == 0) {
			// Find position after "VmRSS:" and skip any whitespace
			size_t pos = line.find_first_not_of(" \t", vmrss.length());
			if (pos == std::string::npos) {
				DOCA_LOG_ERR("Malformed VmRSS line in %s", status_file_path);
				return DOCA_ERROR_INVALID_VALUE;
			}

			try {
				uint64_t kb = std::stoull(line.substr(pos));
				rss = kb * 1024; // Convert KB to bytes
				return DOCA_SUCCESS;
			} catch (const std::exception &e) {
				DOCA_LOG_ERR("Failed to parse VmRSS value: %s", e.what());
				return DOCA_ERROR_INVALID_VALUE;
			}
		}
	}

	DOCA_LOG_ERR("VmRSS not found in %s", status_file_path);
	return DOCA_ERROR_NOT_FOUND;
}

doca_error_t PSPMemoryTracker::get_nic_fw_pages(const std::string &pci_addr, uint64_t &pages) const
{
	std::string path = "/sys/kernel/debug/mlx5/" + pci_addr + "/pages/fw_pages_total";

	std::ifstream fw_pages_file(path);
	if (!fw_pages_file.is_open()) {
		DOCA_LOG_ERR("Failed to open %s", path.c_str());
		return DOCA_ERROR_IO_FAILED;
	}

	if (!(fw_pages_file >> pages)) {
		DOCA_LOG_ERR("Failed to read fw_pages from %s", path.c_str());
		return DOCA_ERROR_INVALID_VALUE;
	}

	return DOCA_SUCCESS;
}

std::string PSPMemoryTracker::get_timestamp() const
{
	auto now = std::time(nullptr);
	auto tm = *std::localtime(&now);
	std::stringstream ss;
	ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
	return ss.str();
}

doca_error_t PSPMemoryTracker::log_stats(const std::string &message)
{
	if (!app_config_->memory_tracking_enabled) {
		return DOCA_SUCCESS;
	}

	if (!log_file_.is_open()) {
		return DOCA_ERROR_IO_FAILED;
	}

	// Get RSS memory
	uint64_t rss = 0;
	doca_error_t err = get_process_rss(rss);
	if (err != DOCA_SUCCESS) {
		return err;
	}

	// Write timestamp and RSS
	log_file_ << get_timestamp() << "," << rss;

	// Get and write NIC firmware pages for each local NIC
	for (const auto &nic : app_config_->net_config.local_nics) {
		uint64_t fw_pages = 0;
		err = get_nic_fw_pages(nic.pci, fw_pages);
		if (err != DOCA_SUCCESS) {
			return err;
		}
		log_file_ << "," << fw_pages;
	}

	// Write message and newline
	log_file_ << "," << message << "\n";
	log_file_.flush();

	return DOCA_SUCCESS;
}