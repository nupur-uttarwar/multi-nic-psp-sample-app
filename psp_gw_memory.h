#ifndef _PSP_GW_MEMORY_H_
#define _PSP_GW_MEMORY_H_

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <fstream>

#include "psp_gw_config.h"

/**
 * @brief Class to handle memory tracking and logging
 */
class PSPMemoryTracker {
public:
    /**
     * @brief Constructor
     * 
     * @param app_config [in]: Application configuration
     */
    explicit PSPMemoryTracker(struct psp_gw_app_config *app_config);

    /**
     * @brief Destructor - ensures log file is closed
     */
    ~PSPMemoryTracker();

    /**
     * @brief Initialize the memory tracker
     * 
     * @return DOCA_SUCCESS on success, DOCA_ERROR otherwise
     */
    doca_error_t init();

    /**
     * @brief Log current memory statistics with a message
     * 
     * @param message [in]: Message to include with the memory stats
     * @return DOCA_SUCCESS on success, DOCA_ERROR otherwise
     */
    doca_error_t log_stats(const std::string &message);

    /**
     * @brief Get the current process RSS memory in bytes
     * 
     * @param rss [out]: RSS memory in bytes
     * @return DOCA_SUCCESS on success, DOCA_ERROR otherwise
     */
    doca_error_t get_process_rss(uint64_t &rss) const;

    /**
     * @brief Get NIC firmware pages for a given PCI device
     * 
     * @param pci_addr [in]: PCI address string
     * @param pages [out]: Number of pages
     * @return DOCA_SUCCESS on success, DOCA_ERROR otherwise
     */
    doca_error_t get_nic_fw_pages(const std::string &pci_addr, uint64_t &pages) const;

private:
    /**
     * @brief Get current timestamp as string
     */
    std::string get_timestamp() const;

private:
    struct psp_gw_app_config *app_config_;
    std::ofstream log_file_;  // Output stream for memory tracking log
};

#endif // _PSP_GW_MEMORY_H_