/**
 * @file multiparty_psi.h
 * @brief Multi-party Private Set Intersection
 * 
 * @details PSI protocol for 3+ participants
 * 
 * Protocols Implemented:
 * 1. Star Topology: Central coordinator, O(n·|S|) communication
 * 2. Ring Topology: Sequential pairwise PSI, O(n²·|S|) communication
 * 3. Tree Topology: Hierarchical aggregation, O(n·log(n)·|S|) communication
 * 
 * Security:
 * - Semi-honest security (default)
 * - Malicious security (with consistency checks)
 * - Threshold corruption model (t-out-of-n)
 * 
 * Use Cases:
 * - Multi-organization threat intelligence sharing
 * - Collaborative fraud detection
 * - Privacy-preserving contact tracing
 * 
 * @author kn1ghtc
 * @version 4.14.0
 * @date 2026-01-25
 * 
 * @copyright Copyright (c) 2019-2026 knightc. Licensed under Apache 2.0
 */

#ifndef KCTSB_ADVANCED_MULTIPARTY_PSI_H
#define KCTSB_ADVANCED_MULTIPARTY_PSI_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
#include <functional>
#include <memory>
#include <string>
#include <vector>
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ============================================================================ */

/** Maximum number of parties */
#define KCTSB_MPSI_MAX_PARTIES 256

/** Default hash output size (bytes) */
#define KCTSB_MPSI_HASH_SIZE 32

/* ============================================================================
 * Multi-party PSI Configuration
 * ============================================================================ */

/**
 * @brief MPSI topology selection
 */
typedef enum {
    KCTSB_MPSI_STAR,     /**< Central coordinator (fastest for small n) */
    KCTSB_MPSI_RING,     /**< Sequential pairwise (no coordinator) */
    KCTSB_MPSI_TREE      /**< Hierarchical tree (balanced load) */
} kctsb_mpsi_topology_t;

/**
 * @brief MPSI security model
 */
typedef enum {
    KCTSB_MPSI_SEMI_HONEST,  /**< Semi-honest security */
    KCTSB_MPSI_MALICIOUS     /**< Malicious security */
} kctsb_mpsi_security_t;

/**
 * @brief Party role in MPSI
 */
typedef enum {
    KCTSB_MPSI_COORDINATOR,  /**< Central coordinator (star topology) */
    KCTSB_MPSI_PARTICIPANT   /**< Regular participant */
} kctsb_mpsi_role_t;

/**
 * @brief MPSI configuration
 */
typedef struct {
    size_t party_id;                 /**< This party's ID (0 to num_parties-1) */
    size_t num_parties;              /**< Total number of parties */
    kctsb_mpsi_topology_t topology;  /**< Network topology */
    kctsb_mpsi_security_t security;  /**< Security model */
    kctsb_mpsi_role_t role;          /**< Party role */
    size_t max_set_size;             /**< Maximum set size per party */
    size_t threshold;                /**< Corruption threshold (t-out-of-n) */
    bool learn_intersection;         /**< Does this party learn result? */
    size_t security_parameter;       /**< Security parameter (128/192/256) */
} kctsb_mpsi_config_t;

/**
 * @brief MPSI result
 */
typedef struct {
    size_t intersection_size;        /**< Intersection cardinality */
    int64_t* intersection_elements;  /**< Intersection elements (if learned) */
    size_t num_parties_participated; /**< Parties that completed protocol */
    double setup_time_ms;            /**< Setup phase time */
    double compute_time_ms;          /**< Computation time */
    double total_time_ms;            /**< Total execution time */
    size_t communication_bytes;      /**< Total communication */
    size_t rounds;                   /**< Communication rounds */
    bool success;                    /**< Operation success */
    char error_message[256];         /**< Error description */
} kctsb_mpsi_result_t;

/**
 * @brief Message for inter-party communication
 */
typedef struct {
    size_t from_party;               /**< Sender party ID */
    size_t to_party;                 /**< Receiver party ID */
    size_t round;                    /**< Protocol round number */
    uint8_t* data;                   /**< Message data */
    size_t data_size;                /**< Data size in bytes */
    uint8_t tag[16];                 /**< Authentication tag */
} kctsb_mpsi_message_t;

/**
 * @brief Opaque MPSI context
 */
typedef struct kctsb_mpsi_ctx kctsb_mpsi_ctx_t;

/* ============================================================================
 * Callback Types for Network Communication
 * ============================================================================ */

/**
 * @brief Send message callback
 * @param message Message to send
 * @param user_data User context
 * @return 0 on success
 */
typedef int (*kctsb_mpsi_send_fn)(const kctsb_mpsi_message_t* message, void* user_data);

/**
 * @brief Receive message callback (blocking)
 * @param from_party Expected sender (-1 for any)
 * @param message Output message
 * @param timeout_ms Timeout in milliseconds
 * @param user_data User context
 * @return 0 on success, timeout error on timeout
 */
typedef int (*kctsb_mpsi_recv_fn)(int from_party, kctsb_mpsi_message_t* message,
                                  int timeout_ms, void* user_data);

/* ============================================================================
 * C API Functions
 * ============================================================================ */

/**
 * @brief Initialize MPSI configuration
 * @param config Configuration to initialize
 * @param party_id This party's ID
 * @param num_parties Total parties
 * @param topology Network topology
 */
void kctsb_mpsi_config_init(
    kctsb_mpsi_config_t* config,
    size_t party_id,
    size_t num_parties,
    kctsb_mpsi_topology_t topology
);

/**
 * @brief Create MPSI context
 * @param config Configuration
 * @return Context or NULL on failure
 */
kctsb_mpsi_ctx_t* kctsb_mpsi_create(const kctsb_mpsi_config_t* config);

/**
 * @brief Set network callbacks
 * @param ctx MPSI context
 * @param send_fn Send callback
 * @param recv_fn Receive callback
 * @param user_data User context for callbacks
 * @return 0 on success
 */
int kctsb_mpsi_set_network(
    kctsb_mpsi_ctx_t* ctx,
    kctsb_mpsi_send_fn send_fn,
    kctsb_mpsi_recv_fn recv_fn,
    void* user_data
);

/**
 * @brief Execute MPSI protocol
 * @param ctx MPSI context
 * @param local_set This party's input set
 * @param set_size Set size
 * @param result Output result
 * @return 0 on success
 */
int kctsb_mpsi_compute(
    kctsb_mpsi_ctx_t* ctx,
    const int64_t* local_set,
    size_t set_size,
    kctsb_mpsi_result_t* result
);

/**
 * @brief Execute MPSI in local simulation mode (for testing)
 * @param config Base configuration
 * @param all_sets Array of all parties' sets
 * @param set_sizes Size of each party's set
 * @param num_parties Number of parties
 * @param result Output result
 * @return 0 on success
 */
int kctsb_mpsi_compute_local(
    const kctsb_mpsi_config_t* config,
    const int64_t** all_sets,
    const size_t* set_sizes,
    size_t num_parties,
    kctsb_mpsi_result_t* result
);

/**
 * @brief Destroy MPSI context
 * @param ctx Context to destroy
 */
void kctsb_mpsi_destroy(kctsb_mpsi_ctx_t* ctx);

/**
 * @brief Free MPSI result
 * @param result Result to free
 */
void kctsb_mpsi_result_free(kctsb_mpsi_result_t* result);

/**
 * @brief Free MPSI message
 * @param message Message to free
 */
void kctsb_mpsi_message_free(kctsb_mpsi_message_t* message);

#ifdef __cplusplus
}

/* ============================================================================
 * C++ Wrapper Classes
 * ============================================================================ */

namespace kctsb {
namespace psi {

/**
 * @brief MPSI configuration
 */
struct MPSIConfig {
    size_t party_id = 0;
    size_t num_parties = 3;
    kctsb_mpsi_topology_t topology = KCTSB_MPSI_STAR;
    kctsb_mpsi_security_t security = KCTSB_MPSI_SEMI_HONEST;
    kctsb_mpsi_role_t role = KCTSB_MPSI_PARTICIPANT;
    size_t max_set_size = 1000000;
    size_t threshold = 0;  // No threshold (honest majority)
    bool learn_intersection = true;
    size_t security_parameter = 128;
};

/**
 * @brief MPSI result
 */
struct MPSIResult {
    size_t intersection_size = 0;
    std::vector<int64_t> intersection_elements;
    size_t num_parties_participated = 0;
    double setup_time_ms = 0;
    double compute_time_ms = 0;
    double total_time_ms = 0;
    size_t communication_bytes = 0;
    size_t rounds = 0;
    bool success = false;
    std::string error_message;
};

/**
 * @brief Network message
 */
struct MPSIMessage {
    size_t from_party;
    size_t to_party;
    size_t round;
    std::vector<uint8_t> data;
    std::array<uint8_t, 16> tag;
};

/**
 * @brief Network interface for MPSI
 */
class MPSINetwork {
public:
    virtual ~MPSINetwork() = default;
    
    /**
     * @brief Send message to party
     */
    virtual int send(const MPSIMessage& message) = 0;
    
    /**
     * @brief Receive message from party
     * @param from_party -1 for any party
     * @param timeout_ms Timeout (-1 for infinite)
     */
    virtual std::pair<int, MPSIMessage> receive(int from_party = -1, 
                                                 int timeout_ms = -1) = 0;
    
    /**
     * @brief Broadcast message to all parties
     */
    virtual int broadcast(const std::vector<uint8_t>& data, size_t round) = 0;
};

/**
 * @brief Local simulation network (for testing)
 */
class MPSILocalNetwork : public MPSINetwork {
public:
    explicit MPSILocalNetwork(size_t party_id, size_t num_parties);
    ~MPSILocalNetwork() override;
    
    int send(const MPSIMessage& message) override;
    std::pair<int, MPSIMessage> receive(int from_party, int timeout_ms) override;
    int broadcast(const std::vector<uint8_t>& data, size_t round) override;
    
    /**
     * @brief Link this network to other party's network (for simulation)
     */
    static void link_networks(std::vector<MPSILocalNetwork*>& networks);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief Multi-party PSI Protocol
 */
class MultipartyPSI {
public:
    explicit MultipartyPSI(const MPSIConfig& config);
    ~MultipartyPSI();

    MultipartyPSI(const MultipartyPSI&) = delete;
    MultipartyPSI& operator=(const MultipartyPSI&) = delete;
    MultipartyPSI(MultipartyPSI&&) noexcept;
    MultipartyPSI& operator=(MultipartyPSI&&) noexcept;

    /**
     * @brief Set network interface
     */
    void set_network(std::shared_ptr<MPSINetwork> network);

    /**
     * @brief Execute MPSI with distributed parties
     * @param local_set This party's input set
     * @return MPSI result (intersection if this party should learn it)
     */
    MPSIResult compute(const std::vector<int64_t>& local_set);

    /**
     * @brief Execute MPSI in local simulation (all parties in same process)
     * @param all_sets All parties' sets
     * @return MPSI result
     */
    static MPSIResult compute_local(
        const MPSIConfig& config,
        const std::vector<std::vector<int64_t>>& all_sets);

    /**
     * @brief Get configuration
     */
    const MPSIConfig& config() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace psi
} // namespace kctsb

#endif // __cplusplus

#endif // KCTSB_ADVANCED_MULTIPARTY_PSI_H
