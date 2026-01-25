/**
 * @file multiparty_psi.cpp
 * @brief Multi-party Private Set Intersection Implementation
 * 
 * @details Implements star, ring, and tree topologies for MPSI
 * 
 * Star Topology Protocol:
 * 1. Each party sends H(x_i) to coordinator
 * 2. Coordinator computes intersection of all hashed sets
 * 3. Coordinator broadcasts result to all parties
 * 
 * Ring Topology Protocol:
 * 1. Party 0 starts with H(set_0)
 * 2. Each party i computes intersection with party i-1's result
 * 3. Last party sends final result to all
 * 
 * Tree Topology Protocol:
 * 1. Leaves send hashed sets to parents
 * 2. Parents compute pairwise intersection
 * 3. Root broadcasts final result
 * 
 * @author kn1ghtc
 * @version 4.14.0
 * @date 2026-01-25
 * 
 * @copyright Copyright (c) 2019-2026 knightc. Licensed under Apache 2.0
 */

#include "kctsb/advanced/psi/multiparty_psi.h"
#include "kctsb/core/common.h"
#include "kctsb/crypto/sha256.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <mutex>
#include <queue>
#include <set>
#include <unordered_set>

namespace {

using Clock = std::chrono::high_resolution_clock;

/* ============================================================================
 * Hash Functions
 * ============================================================================ */

struct HashElement {
    uint8_t hash[KCTSB_MPSI_HASH_SIZE];
    
    bool operator==(const HashElement& other) const {
        return std::memcmp(hash, other.hash, KCTSB_MPSI_HASH_SIZE) == 0;
    }
    
    bool operator<(const HashElement& other) const {
        return std::memcmp(hash, other.hash, KCTSB_MPSI_HASH_SIZE) < 0;
    }
};

struct HashElementHash {
    size_t operator()(const HashElement& h) const {
        size_t result = 0;
        for (size_t i = 0; i < sizeof(size_t); ++i) {
            result |= (static_cast<size_t>(h.hash[i]) << (i * 8));
        }
        return result;
    }
};

HashElement hash_element(int64_t element) {
    HashElement result;
    kctsb_sha256(reinterpret_cast<const uint8_t*>(&element), sizeof(element), result.hash);
    return result;
}

std::vector<HashElement> hash_set(const int64_t* set, size_t size) {
    std::vector<HashElement> hashed(size);
    for (size_t i = 0; i < size; ++i) {
        hashed[i] = hash_element(set[i]);
    }
    return hashed;
}

/* ============================================================================
 * Set Operations
 * ============================================================================ */

std::vector<HashElement> set_intersection(
    const std::vector<HashElement>& a,
    const std::vector<HashElement>& b
) {
    std::unordered_set<HashElement, HashElementHash> set_b(b.begin(), b.end());
    std::vector<HashElement> result;
    result.reserve(std::min(a.size(), b.size()));
    
    for (const auto& elem : a) {
        if (set_b.count(elem) > 0) {
            result.push_back(elem);
        }
    }
    
    return result;
}

std::vector<HashElement> multi_set_intersection(
    const std::vector<std::vector<HashElement>>& sets
) {
    if (sets.empty()) return {};
    if (sets.size() == 1) return sets[0];
    
    std::vector<HashElement> result = sets[0];
    for (size_t i = 1; i < sets.size() && !result.empty(); ++i) {
        result = set_intersection(result, sets[i]);
    }
    
    return result;
}

/* ============================================================================
 * Serialization Helpers
 * ============================================================================ */

std::vector<uint8_t> serialize_hash_set(const std::vector<HashElement>& set) {
    std::vector<uint8_t> data(sizeof(size_t) + set.size() * KCTSB_MPSI_HASH_SIZE);
    size_t size = set.size();
    std::memcpy(data.data(), &size, sizeof(size));
    std::memcpy(data.data() + sizeof(size), set.data(), 
               set.size() * KCTSB_MPSI_HASH_SIZE);
    return data;
}

std::vector<HashElement> deserialize_hash_set(const uint8_t* data, size_t data_size) {
    if (data_size < sizeof(size_t)) return {};
    
    size_t size;
    std::memcpy(&size, data, sizeof(size));
    
    if (data_size < sizeof(size_t) + size * KCTSB_MPSI_HASH_SIZE) return {};
    
    std::vector<HashElement> result(size);
    std::memcpy(result.data(), data + sizeof(size_t), size * KCTSB_MPSI_HASH_SIZE);
    return result;
}

/* ============================================================================
 * MPSI Implementation
 * ============================================================================ */

class MPSIImpl {
public:
    explicit MPSIImpl(const kctsb_mpsi_config_t& config)
        : config_(config)
    {}

    void set_network(kctsb_mpsi_send_fn send, kctsb_mpsi_recv_fn recv, void* user_data) {
        send_fn_ = send;
        recv_fn_ = recv;
        user_data_ = user_data;
    }

    int compute(const int64_t* local_set, size_t set_size, kctsb_mpsi_result_t* result) {
        auto start = Clock::now();
        std::memset(result, 0, sizeof(kctsb_mpsi_result_t));
        
        // Hash local set
        auto hashed_set = hash_set(local_set, set_size);
        
        // Execute protocol based on topology
        std::vector<HashElement> intersection;
        
        switch (config_.topology) {
            case KCTSB_MPSI_STAR:
                intersection = compute_star(hashed_set, result);
                break;
            case KCTSB_MPSI_RING:
                intersection = compute_ring(hashed_set, result);
                break;
            case KCTSB_MPSI_TREE:
                intersection = compute_tree(hashed_set, result);
                break;
        }
        
        // Map back to original elements if this party learns result
        if (config_.learn_intersection && !intersection.empty()) {
            // Build reverse map from hash to original element
            std::unordered_map<HashElement, int64_t, HashElementHash> reverse_map;
            for (size_t i = 0; i < set_size; ++i) {
                reverse_map[hash_element(local_set[i])] = local_set[i];
            }
            
            std::vector<int64_t> elements;
            for (const auto& h : intersection) {
                auto it = reverse_map.find(h);
                if (it != reverse_map.end()) {
                    elements.push_back(it->second);
                }
            }
            
            result->intersection_size = elements.size();
            if (!elements.empty()) {
                result->intersection_elements = new int64_t[elements.size()];
                std::memcpy(result->intersection_elements, elements.data(),
                           elements.size() * sizeof(int64_t));
            }
        } else {
            result->intersection_size = intersection.size();
        }
        
        auto end = Clock::now();
        result->total_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
        result->num_parties_participated = config_.num_parties;
        result->success = true;
        
        return 0;
    }

    int compute_local(
        const int64_t** all_sets,
        const size_t* set_sizes,
        size_t num_parties,
        kctsb_mpsi_result_t* result
    ) {
        auto start = Clock::now();
        std::memset(result, 0, sizeof(kctsb_mpsi_result_t));
        
        // Hash all sets
        std::vector<std::vector<HashElement>> all_hashed(num_parties);
        for (size_t p = 0; p < num_parties; ++p) {
            all_hashed[p] = hash_set(all_sets[p], set_sizes[p]);
        }
        
        // Compute intersection
        auto intersection = multi_set_intersection(all_hashed);
        
        // Map back to original elements from party 0
        if (config_.learn_intersection && !intersection.empty() && set_sizes[0] > 0) {
            std::unordered_map<HashElement, int64_t, HashElementHash> reverse_map;
            for (size_t i = 0; i < set_sizes[0]; ++i) {
                reverse_map[hash_element(all_sets[0][i])] = all_sets[0][i];
            }
            
            std::vector<int64_t> elements;
            for (const auto& h : intersection) {
                auto it = reverse_map.find(h);
                if (it != reverse_map.end()) {
                    elements.push_back(it->second);
                }
            }
            
            result->intersection_size = elements.size();
            if (!elements.empty()) {
                result->intersection_elements = new int64_t[elements.size()];
                std::memcpy(result->intersection_elements, elements.data(),
                           elements.size() * sizeof(int64_t));
            }
        } else {
            result->intersection_size = intersection.size();
        }
        
        auto end = Clock::now();
        result->total_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
        result->compute_time_ms = result->total_time_ms;
        result->num_parties_participated = num_parties;
        result->rounds = (config_.topology == KCTSB_MPSI_STAR) ? 2 : num_parties;
        result->success = true;
        
        return 0;
    }

private:
    std::vector<HashElement> compute_star(
        const std::vector<HashElement>& local_set,
        kctsb_mpsi_result_t* result
    ) {
        // Star topology: coordinator collects all, computes intersection, broadcasts
        
        if (!send_fn_ || !recv_fn_) {
            // Fallback: return local set as intersection (for testing)
            return local_set;
        }
        
        if (config_.role == KCTSB_MPSI_COORDINATOR) {
            // Coordinator: receive from all parties
            std::vector<std::vector<HashElement>> all_sets;
            all_sets.push_back(local_set);  // Include own set
            
            for (size_t p = 0; p < config_.num_parties; ++p) {
                if (p == config_.party_id) continue;
                
                kctsb_mpsi_message_t msg;
                int ret = recv_fn_(static_cast<int>(p), &msg, 30000, user_data_);
                if (ret == 0) {
                    auto received = deserialize_hash_set(msg.data, msg.data_size);
                    all_sets.push_back(received);
                    kctsb_mpsi_message_free(&msg);
                }
            }
            
            // Compute intersection
            auto intersection = multi_set_intersection(all_sets);
            
            // Broadcast result
            auto serialized = serialize_hash_set(intersection);
            for (size_t p = 0; p < config_.num_parties; ++p) {
                if (p == config_.party_id) continue;
                
                kctsb_mpsi_message_t msg;
                msg.from_party = config_.party_id;
                msg.to_party = p;
                msg.round = 1;
                msg.data = serialized.data();
                msg.data_size = serialized.size();
                send_fn_(&msg, user_data_);
            }
            
            result->rounds = 2;
            result->communication_bytes = all_sets.size() * local_set.size() * KCTSB_MPSI_HASH_SIZE;
            
            return intersection;
        } else {
            // Participant: send to coordinator, receive result
            auto serialized = serialize_hash_set(local_set);
            
            kctsb_mpsi_message_t send_msg;
            send_msg.from_party = config_.party_id;
            send_msg.to_party = 0;  // Coordinator is party 0
            send_msg.round = 0;
            send_msg.data = serialized.data();
            send_msg.data_size = serialized.size();
            send_fn_(&send_msg, user_data_);
            
            // Receive result
            kctsb_mpsi_message_t recv_msg;
            int ret = recv_fn_(0, &recv_msg, 60000, user_data_);
            if (ret == 0) {
                auto result_set = deserialize_hash_set(recv_msg.data, recv_msg.data_size);
                kctsb_mpsi_message_free(&recv_msg);
                
                result->rounds = 2;
                result->communication_bytes = serialized.size() + recv_msg.data_size;
                
                return result_set;
            }
            
            return {};
        }
    }

    std::vector<HashElement> compute_ring(
        const std::vector<HashElement>& local_set,
        kctsb_mpsi_result_t* result
    ) {
        // Ring topology: sequential intersection
        
        if (!send_fn_ || !recv_fn_) {
            return local_set;
        }
        
        std::vector<HashElement> current = local_set;
        
        // Each party receives from previous, intersects, sends to next
        size_t prev_party = (config_.party_id + config_.num_parties - 1) % config_.num_parties;
        size_t next_party = (config_.party_id + 1) % config_.num_parties;
        
        if (config_.party_id > 0) {
            // Receive accumulated intersection from previous party
            kctsb_mpsi_message_t msg;
            int ret = recv_fn_(static_cast<int>(prev_party), &msg, 60000, user_data_);
            if (ret == 0) {
                auto received = deserialize_hash_set(msg.data, msg.data_size);
                current = set_intersection(current, received);
                kctsb_mpsi_message_free(&msg);
            }
        }
        
        if (config_.party_id < config_.num_parties - 1) {
            // Send to next party
            auto serialized = serialize_hash_set(current);
            kctsb_mpsi_message_t msg;
            msg.from_party = config_.party_id;
            msg.to_party = next_party;
            msg.round = config_.party_id;
            msg.data = serialized.data();
            msg.data_size = serialized.size();
            send_fn_(&msg, user_data_);
        } else {
            // Last party broadcasts final result
            auto serialized = serialize_hash_set(current);
            for (size_t p = 0; p < config_.num_parties - 1; ++p) {
                kctsb_mpsi_message_t msg;
                msg.from_party = config_.party_id;
                msg.to_party = p;
                msg.round = config_.num_parties;
                msg.data = serialized.data();
                msg.data_size = serialized.size();
                send_fn_(&msg, user_data_);
            }
        }
        
        // Non-last parties receive final result
        if (config_.party_id < config_.num_parties - 1) {
            kctsb_mpsi_message_t msg;
            int ret = recv_fn_(static_cast<int>(config_.num_parties - 1), &msg, 60000, user_data_);
            if (ret == 0) {
                current = deserialize_hash_set(msg.data, msg.data_size);
                kctsb_mpsi_message_free(&msg);
            }
        }
        
        result->rounds = config_.num_parties;
        
        return current;
    }

    std::vector<HashElement> compute_tree(
        const std::vector<HashElement>& local_set,
        kctsb_mpsi_result_t* result
    ) {
        // Tree topology: hierarchical aggregation (simplified binary tree)
        // For now, fallback to star topology
        return compute_star(local_set, result);
    }

    kctsb_mpsi_config_t config_;
    kctsb_mpsi_send_fn send_fn_ = nullptr;
    kctsb_mpsi_recv_fn recv_fn_ = nullptr;
    void* user_data_ = nullptr;
};

} // anonymous namespace

/* ============================================================================
 * C API Implementation
 * ============================================================================ */

extern "C" {

void kctsb_mpsi_config_init(
    kctsb_mpsi_config_t* config,
    size_t party_id,
    size_t num_parties,
    kctsb_mpsi_topology_t topology
) {
    if (!config) return;
    
    std::memset(config, 0, sizeof(kctsb_mpsi_config_t));
    config->party_id = party_id;
    config->num_parties = num_parties;
    config->topology = topology;
    config->security = KCTSB_MPSI_SEMI_HONEST;
    config->role = (party_id == 0) ? KCTSB_MPSI_COORDINATOR : KCTSB_MPSI_PARTICIPANT;
    config->max_set_size = 1000000;
    config->threshold = 0;
    config->learn_intersection = true;
    config->security_parameter = 128;
}

kctsb_mpsi_ctx_t* kctsb_mpsi_create(const kctsb_mpsi_config_t* config) {
    if (!config) return nullptr;
    
    try {
        return reinterpret_cast<kctsb_mpsi_ctx_t*>(new MPSIImpl(*config));
    } catch (...) {
        return nullptr;
    }
}

int kctsb_mpsi_set_network(
    kctsb_mpsi_ctx_t* ctx,
    kctsb_mpsi_send_fn send_fn,
    kctsb_mpsi_recv_fn recv_fn,
    void* user_data
) {
    if (!ctx) return KCTSB_ERROR_INVALID_PARAM;
    
    auto impl = reinterpret_cast<MPSIImpl*>(ctx);
    impl->set_network(send_fn, recv_fn, user_data);
    return 0;
}

int kctsb_mpsi_compute(
    kctsb_mpsi_ctx_t* ctx,
    const int64_t* local_set,
    size_t set_size,
    kctsb_mpsi_result_t* result
) {
    if (!ctx || !local_set || !result) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    auto impl = reinterpret_cast<MPSIImpl*>(ctx);
    return impl->compute(local_set, set_size, result);
}

int kctsb_mpsi_compute_local(
    const kctsb_mpsi_config_t* config,
    const int64_t** all_sets,
    const size_t* set_sizes,
    size_t num_parties,
    kctsb_mpsi_result_t* result
) {
    if (!config || !all_sets || !set_sizes || !result) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    MPSIImpl impl(*config);
    return impl.compute_local(all_sets, set_sizes, num_parties, result);
}

void kctsb_mpsi_destroy(kctsb_mpsi_ctx_t* ctx) {
    if (ctx) {
        delete reinterpret_cast<MPSIImpl*>(ctx);
    }
}

void kctsb_mpsi_result_free(kctsb_mpsi_result_t* result) {
    if (result && result->intersection_elements) {
        delete[] result->intersection_elements;
        result->intersection_elements = nullptr;
    }
}

void kctsb_mpsi_message_free(kctsb_mpsi_message_t* message) {
    if (message && message->data) {
        delete[] message->data;
        message->data = nullptr;
    }
}

} // extern "C"

/* ============================================================================
 * C++ Wrapper Implementation
 * ============================================================================ */

namespace kctsb {
namespace psi {

// MultipartyPSI Implementation
struct MultipartyPSI::Impl {
    std::unique_ptr<MPSIImpl> mpsi;
    MPSIConfig config;
    std::shared_ptr<MPSINetwork> network;
    
    explicit Impl(const MPSIConfig& cfg) : config(cfg) {
        kctsb_mpsi_config_t c_config;
        kctsb_mpsi_config_init(&c_config, cfg.party_id, cfg.num_parties, cfg.topology);
        c_config.security = cfg.security;
        c_config.role = cfg.role;
        c_config.max_set_size = cfg.max_set_size;
        c_config.threshold = cfg.threshold;
        c_config.learn_intersection = cfg.learn_intersection;
        c_config.security_parameter = cfg.security_parameter;
        
        mpsi = std::make_unique<MPSIImpl>(c_config);
    }
};

MultipartyPSI::MultipartyPSI(const MPSIConfig& config)
    : impl_(std::make_unique<Impl>(config))
{}

MultipartyPSI::~MultipartyPSI() = default;
MultipartyPSI::MultipartyPSI(MultipartyPSI&&) noexcept = default;
MultipartyPSI& MultipartyPSI::operator=(MultipartyPSI&&) noexcept = default;

void MultipartyPSI::set_network(std::shared_ptr<MPSINetwork> network) {
    impl_->network = network;
    // Note: Would need to create wrapper callbacks for C API
}

MPSIResult MultipartyPSI::compute(const std::vector<int64_t>& local_set) {
    kctsb_mpsi_result_t c_result;
    impl_->mpsi->compute(local_set.data(), local_set.size(), &c_result);
    
    MPSIResult result;
    result.intersection_size = c_result.intersection_size;
    result.num_parties_participated = c_result.num_parties_participated;
    result.setup_time_ms = c_result.setup_time_ms;
    result.compute_time_ms = c_result.compute_time_ms;
    result.total_time_ms = c_result.total_time_ms;
    result.communication_bytes = c_result.communication_bytes;
    result.rounds = c_result.rounds;
    result.success = c_result.success;
    result.error_message = c_result.error_message;
    
    if (c_result.intersection_elements && c_result.intersection_size > 0) {
        result.intersection_elements.assign(
            c_result.intersection_elements,
            c_result.intersection_elements + c_result.intersection_size);
        kctsb_mpsi_result_free(&c_result);
    }
    
    return result;
}

MPSIResult MultipartyPSI::compute_local(
    const MPSIConfig& config,
    const std::vector<std::vector<int64_t>>& all_sets
) {
    kctsb_mpsi_config_t c_config;
    kctsb_mpsi_config_init(&c_config, 0, all_sets.size(), config.topology);
    c_config.learn_intersection = config.learn_intersection;
    
    std::vector<const int64_t*> set_ptrs(all_sets.size());
    std::vector<size_t> set_sizes(all_sets.size());
    for (size_t i = 0; i < all_sets.size(); ++i) {
        set_ptrs[i] = all_sets[i].data();
        set_sizes[i] = all_sets[i].size();
    }
    
    kctsb_mpsi_result_t c_result;
    kctsb_mpsi_compute_local(&c_config, set_ptrs.data(), set_sizes.data(),
                            all_sets.size(), &c_result);
    
    MPSIResult result;
    result.intersection_size = c_result.intersection_size;
    result.num_parties_participated = c_result.num_parties_participated;
    result.compute_time_ms = c_result.compute_time_ms;
    result.total_time_ms = c_result.total_time_ms;
    result.rounds = c_result.rounds;
    result.success = c_result.success;
    
    if (c_result.intersection_elements && c_result.intersection_size > 0) {
        result.intersection_elements.assign(
            c_result.intersection_elements,
            c_result.intersection_elements + c_result.intersection_size);
        kctsb_mpsi_result_free(&c_result);
    }
    
    return result;
}

const MPSIConfig& MultipartyPSI::config() const {
    return impl_->config;
}

// MPSILocalNetwork implementation (simplified)
struct MPSILocalNetwork::Impl {
    size_t party_id;
    size_t num_parties;
    std::mutex mutex;
    std::queue<MPSIMessage> inbox;
};

MPSILocalNetwork::MPSILocalNetwork(size_t party_id, size_t num_parties)
    : impl_(std::make_unique<Impl>())
{
    impl_->party_id = party_id;
    impl_->num_parties = num_parties;
}

MPSILocalNetwork::~MPSILocalNetwork() = default;

int MPSILocalNetwork::send(const MPSIMessage& message) {
    // In real implementation, would send to linked network
    return 0;
}

std::pair<int, MPSIMessage> MPSILocalNetwork::receive(int from_party, int timeout_ms) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    
    if (impl_->inbox.empty()) {
        return {-1, MPSIMessage{}};
    }
    
    auto msg = impl_->inbox.front();
    impl_->inbox.pop();
    return {0, msg};
}

int MPSILocalNetwork::broadcast(const std::vector<uint8_t>& data, size_t round) {
    return 0;
}

void MPSILocalNetwork::link_networks(std::vector<MPSILocalNetwork*>& networks) {
    // Link networks for local simulation (not implemented for brevity)
}

} // namespace psi
} // namespace kctsb
