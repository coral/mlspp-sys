#include "wrapper.h"

#include <cstring>
#include <exception>
#include <memory>
#include <string>
#include <vector>

#include <mls/common.h>
#include <mls/core_types.h>
#include <mls/credential.h>
#include <mls/crypto.h>
#include <mls/messages.h>
#include <mls/session.h>
#include <mls/state.h>
#include <mls/treekem.h>
#include <namespace.h>
#include <tls/tls_syntax.h>

namespace ns = MLS_NAMESPACE;

/* ========================================================================
 * Thread-local error handling
 * ======================================================================== */

static thread_local std::string g_last_error;

static void set_error(const char* msg) {
    g_last_error = msg;
}

static void set_error(const std::string& msg) {
    g_last_error = msg;
}

static void clear_error() {
    g_last_error.clear();
}

extern "C" const char* mlspp_last_error(void) {
    if (g_last_error.empty()) {
        return nullptr;
    }
    return g_last_error.c_str();
}

/* ========================================================================
 * Helpers
 * ======================================================================== */

using bytes = ns::bytes_ns::bytes;

static bytes to_bytes(const uint8_t* data, size_t len) {
    if (data == nullptr || len == 0) {
        return {};
    }
    return std::vector<uint8_t>(data, data + len);
}

static mlspp_bytes_t to_mlspp_bytes(const bytes& b) {
    if (b.empty()) {
        return { nullptr, 0 };
    }
    auto* copy = new uint8_t[b.size()];
    std::memcpy(copy, b.data(), b.size());
    return { copy, b.size() };
}

/* ========================================================================
 * Buffer type
 * ======================================================================== */

extern "C" mlspp_bytes_t mlspp_bytes_copy(const uint8_t* data, size_t len) {
    if (data == nullptr || len == 0) {
        return { nullptr, 0 };
    }
    auto* copy = new uint8_t[len];
    std::memcpy(copy, data, len);
    return { copy, len };
}

extern "C" void mlspp_bytes_free(mlspp_bytes_t buf) {
    delete[] buf.data;
}

/* ========================================================================
 * Opaque wrapper structs
 * ======================================================================== */

struct mlspp_cipher_suite_t {
    ns::CipherSuite inner;
};

struct mlspp_hpke_private_key_t {
    ns::HPKEPrivateKey inner;
};

struct mlspp_hpke_public_key_t {
    ns::HPKEPublicKey inner;
};

struct mlspp_signature_private_key_t {
    ns::SignaturePrivateKey inner;
};

struct mlspp_signature_public_key_t {
    ns::SignaturePublicKey inner;
};

struct mlspp_credential_t {
    ns::Credential inner;
};

struct mlspp_leaf_node_t {
    ns::LeafNode inner;
};

struct mlspp_key_package_t {
    ns::KeyPackage inner;
};

struct mlspp_extension_list_t {
    ns::ExtensionList inner;
};

struct mlspp_capabilities_t {
    ns::Capabilities inner;
};

struct mlspp_lifetime_t {
    ns::Lifetime inner;
};

struct mlspp_mls_message_t {
    ns::MLSMessage inner;
};

struct mlspp_group_info_t {
    ns::GroupInfo inner;
};

struct mlspp_welcome_t {
    ns::Welcome inner;
};

struct mlspp_state_t {
    ns::State inner;
};

struct mlspp_client_t {
    ns::Client inner;
};

struct mlspp_pending_join_t {
    ns::PendingJoin inner;
};

struct mlspp_session_t {
    ns::Session inner;
};

/* ========================================================================
 * CipherSuite
 * ======================================================================== */

extern "C" mlspp_cipher_suite_t* mlspp_cipher_suite_create(uint16_t id) {
    clear_error();
    try {
        auto suite = ns::CipherSuite{ static_cast<ns::CipherSuite::ID>(id) };
        return new mlspp_cipher_suite_t{ suite };
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

extern "C" void mlspp_cipher_suite_free(mlspp_cipher_suite_t* cs) {
    if (!cs) return;
    delete cs;
}

extern "C" uint16_t mlspp_cipher_suite_id(const mlspp_cipher_suite_t* cs) {
    if (!cs) return 0;
    return static_cast<uint16_t>(cs->inner.cipher_suite());
}

extern "C" uint16_t mlspp_cipher_suite_signature_scheme(const mlspp_cipher_suite_t* cs) {
    if (!cs) return 0;
    return static_cast<uint16_t>(cs->inner.signature_scheme());
}

extern "C" size_t mlspp_cipher_suite_secret_size(const mlspp_cipher_suite_t* cs) {
    if (!cs) return 0;
    return cs->inner.secret_size();
}

extern "C" size_t mlspp_cipher_suite_key_size(const mlspp_cipher_suite_t* cs) {
    if (!cs) return 0;
    return cs->inner.key_size();
}

extern "C" size_t mlspp_cipher_suite_nonce_size(const mlspp_cipher_suite_t* cs) {
    if (!cs) return 0;
    return cs->inner.nonce_size();
}

/* ========================================================================
 * HPKEPrivateKey
 * ======================================================================== */

extern "C" mlspp_hpke_private_key_t* mlspp_hpke_private_key_generate(
    const mlspp_cipher_suite_t* cs) {
    clear_error();
    try {
        auto key = ns::HPKEPrivateKey::generate(cs->inner);
        return new mlspp_hpke_private_key_t{ std::move(key) };
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

extern "C" mlspp_hpke_private_key_t* mlspp_hpke_private_key_derive(
    const mlspp_cipher_suite_t* cs,
    const uint8_t* secret, size_t secret_len) {
    clear_error();
    try {
        auto key = ns::HPKEPrivateKey::derive(cs->inner, to_bytes(secret, secret_len));
        return new mlspp_hpke_private_key_t{ std::move(key) };
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

extern "C" mlspp_hpke_private_key_t* mlspp_hpke_private_key_parse(
    const mlspp_cipher_suite_t* cs,
    const uint8_t* data, size_t data_len) {
    clear_error();
    try {
        auto key = ns::HPKEPrivateKey::parse(cs->inner, to_bytes(data, data_len));
        return new mlspp_hpke_private_key_t{ std::move(key) };
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

extern "C" void mlspp_hpke_private_key_free(mlspp_hpke_private_key_t* key) {
    if (!key) return;
    delete key;
}

extern "C" mlspp_bytes_t mlspp_hpke_private_key_data(
    const mlspp_hpke_private_key_t* key) {
    if (!key) return { nullptr, 0 };
    return to_mlspp_bytes(key->inner.data);
}

extern "C" mlspp_hpke_public_key_t* mlspp_hpke_private_key_public_key(
    const mlspp_hpke_private_key_t* key) {
    if (!key) return nullptr;
    return new mlspp_hpke_public_key_t{ key->inner.public_key };
}

extern "C" mlspp_bytes_t mlspp_hpke_private_key_decrypt(
    const mlspp_hpke_private_key_t* key,
    const mlspp_cipher_suite_t* cs,
    const char* label,
    const uint8_t* context, size_t context_len,
    const uint8_t* kem_output, size_t kem_output_len,
    const uint8_t* ciphertext, size_t ciphertext_len) {
    clear_error();
    try {
        ns::HPKECiphertext ct;
        ct.kem_output = to_bytes(kem_output, kem_output_len);
        ct.ciphertext = to_bytes(ciphertext, ciphertext_len);
        auto result = key->inner.decrypt(
            cs->inner, std::string(label),
            to_bytes(context, context_len), ct);
        return to_mlspp_bytes(result);
    } catch (const std::exception& e) {
        set_error(e.what());
        return { nullptr, 0 };
    }
}

/* ========================================================================
 * HPKEPublicKey
 * ======================================================================== */

extern "C" mlspp_hpke_public_key_t* mlspp_hpke_public_key_from_data(
    const uint8_t* data, size_t data_len) {
    ns::HPKEPublicKey pk;
    pk.data = to_bytes(data, data_len);
    return new mlspp_hpke_public_key_t{ std::move(pk) };
}

extern "C" void mlspp_hpke_public_key_free(mlspp_hpke_public_key_t* key) {
    if (!key) return;
    delete key;
}

extern "C" mlspp_bytes_t mlspp_hpke_public_key_data(
    const mlspp_hpke_public_key_t* key) {
    if (!key) return { nullptr, 0 };
    return to_mlspp_bytes(key->inner.data);
}

extern "C" int mlspp_hpke_public_key_encrypt(
    const mlspp_hpke_public_key_t* key,
    const mlspp_cipher_suite_t* cs,
    const char* label,
    const uint8_t* context, size_t context_len,
    const uint8_t* plaintext, size_t plaintext_len,
    mlspp_bytes_t* out_kem_output,
    mlspp_bytes_t* out_ciphertext) {
    clear_error();
    try {
        auto ct = key->inner.encrypt(
            cs->inner, std::string(label),
            to_bytes(context, context_len),
            to_bytes(plaintext, plaintext_len));
        *out_kem_output = to_mlspp_bytes(ct.kem_output);
        *out_ciphertext = to_mlspp_bytes(ct.ciphertext);
        return 0;
    } catch (const std::exception& e) {
        set_error(e.what());
        return -1;
    }
}

/* ========================================================================
 * SignaturePrivateKey
 * ======================================================================== */

extern "C" mlspp_signature_private_key_t* mlspp_signature_private_key_generate(
    const mlspp_cipher_suite_t* cs) {
    clear_error();
    try {
        auto key = ns::SignaturePrivateKey::generate(cs->inner);
        return new mlspp_signature_private_key_t{ std::move(key) };
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

extern "C" mlspp_signature_private_key_t* mlspp_signature_private_key_derive(
    const mlspp_cipher_suite_t* cs,
    const uint8_t* secret, size_t secret_len) {
    clear_error();
    try {
        auto key = ns::SignaturePrivateKey::derive(
            cs->inner, to_bytes(secret, secret_len));
        return new mlspp_signature_private_key_t{ std::move(key) };
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

extern "C" mlspp_signature_private_key_t* mlspp_signature_private_key_parse(
    const mlspp_cipher_suite_t* cs,
    const uint8_t* data, size_t data_len) {
    clear_error();
    try {
        auto key = ns::SignaturePrivateKey::parse(
            cs->inner, to_bytes(data, data_len));
        return new mlspp_signature_private_key_t{ std::move(key) };
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

extern "C" void mlspp_signature_private_key_free(
    mlspp_signature_private_key_t* key) {
    if (!key) return;
    delete key;
}

extern "C" mlspp_bytes_t mlspp_signature_private_key_data(
    const mlspp_signature_private_key_t* key) {
    if (!key) return { nullptr, 0 };
    return to_mlspp_bytes(key->inner.data);
}

extern "C" mlspp_signature_public_key_t* mlspp_signature_private_key_public_key(
    const mlspp_signature_private_key_t* key) {
    if (!key) return nullptr;
    return new mlspp_signature_public_key_t{ key->inner.public_key };
}

extern "C" mlspp_bytes_t mlspp_signature_private_key_sign(
    const mlspp_signature_private_key_t* key,
    const mlspp_cipher_suite_t* cs,
    const char* label,
    const uint8_t* message, size_t message_len) {
    clear_error();
    try {
        auto sig = key->inner.sign(
            cs->inner, std::string(label),
            to_bytes(message, message_len));
        return to_mlspp_bytes(sig);
    } catch (const std::exception& e) {
        set_error(e.what());
        return { nullptr, 0 };
    }
}

/* ========================================================================
 * SignaturePublicKey
 * ======================================================================== */

extern "C" mlspp_signature_public_key_t* mlspp_signature_public_key_from_data(
    const uint8_t* data, size_t data_len) {
    ns::SignaturePublicKey pk;
    pk.data = to_bytes(data, data_len);
    return new mlspp_signature_public_key_t{ std::move(pk) };
}

extern "C" void mlspp_signature_public_key_free(
    mlspp_signature_public_key_t* key) {
    if (!key) return;
    delete key;
}

extern "C" mlspp_bytes_t mlspp_signature_public_key_data(
    const mlspp_signature_public_key_t* key) {
    if (!key) return { nullptr, 0 };
    return to_mlspp_bytes(key->inner.data);
}

extern "C" int mlspp_signature_public_key_verify(
    const mlspp_signature_public_key_t* key,
    const mlspp_cipher_suite_t* cs,
    const char* label,
    const uint8_t* message, size_t message_len,
    const uint8_t* signature, size_t signature_len) {
    clear_error();
    try {
        bool ok = key->inner.verify(
            cs->inner, std::string(label),
            to_bytes(message, message_len),
            to_bytes(signature, signature_len));
        return ok ? 1 : 0;
    } catch (const std::exception& e) {
        set_error(e.what());
        return -1;
    }
}

/* ========================================================================
 * Credential
 * ======================================================================== */

extern "C" mlspp_credential_t* mlspp_credential_basic(
    const uint8_t* identity, size_t identity_len) {
    clear_error();
    try {
        auto cred = ns::Credential::basic(to_bytes(identity, identity_len));
        return new mlspp_credential_t{ std::move(cred) };
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

extern "C" mlspp_credential_t* mlspp_credential_x509(
    const uint8_t* const* der_chain, const size_t* der_chain_lens,
    size_t chain_count) {
    clear_error();
    try {
        std::vector<bytes> chain;
        chain.reserve(chain_count);
        for (size_t i = 0; i < chain_count; i++) {
            chain.push_back(to_bytes(der_chain[i], der_chain_lens[i]));
        }
        auto cred = ns::Credential::x509(chain);
        return new mlspp_credential_t{ std::move(cred) };
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

extern "C" void mlspp_credential_free(mlspp_credential_t* cred) {
    if (!cred) return;
    delete cred;
}

extern "C" uint16_t mlspp_credential_type(const mlspp_credential_t* cred) {
    if (!cred) return 0;
    return static_cast<uint16_t>(cred->inner.type());
}

/* ========================================================================
 * Capabilities
 * ======================================================================== */

extern "C" mlspp_capabilities_t* mlspp_capabilities_create_default(void) {
    return new mlspp_capabilities_t{ ns::Capabilities::create_default() };
}

extern "C" void mlspp_capabilities_free(mlspp_capabilities_t* caps) {
    if (!caps) return;
    delete caps;
}

/* ========================================================================
 * Lifetime
 * ======================================================================== */

extern "C" mlspp_lifetime_t* mlspp_lifetime_create_default(void) {
    return new mlspp_lifetime_t{ ns::Lifetime::create_default() };
}

extern "C" mlspp_lifetime_t* mlspp_lifetime_create(
    uint64_t not_before, uint64_t not_after) {
    ns::Lifetime lt;
    lt.not_before = not_before;
    lt.not_after = not_after;
    return new mlspp_lifetime_t{ lt };
}

extern "C" void mlspp_lifetime_free(mlspp_lifetime_t* lt) {
    if (!lt) return;
    delete lt;
}

/* ========================================================================
 * ExtensionList
 * ======================================================================== */

extern "C" mlspp_extension_list_t* mlspp_extension_list_create(void) {
    return new mlspp_extension_list_t{};
}

extern "C" void mlspp_extension_list_free(mlspp_extension_list_t* exts) {
    if (!exts) return;
    delete exts;
}

extern "C" int mlspp_extension_list_add(
    mlspp_extension_list_t* exts,
    uint16_t ext_type,
    const uint8_t* data, size_t data_len) {
    clear_error();
    try {
        exts->inner.add(
            static_cast<ns::Extension::Type>(ext_type),
            to_bytes(data, data_len));
        return 0;
    } catch (const std::exception& e) {
        set_error(e.what());
        return -1;
    }
}

extern "C" int mlspp_extension_list_has(
    const mlspp_extension_list_t* exts, uint16_t ext_type) {
    if (!exts) return 0;
    return exts->inner.has(static_cast<ns::Extension::Type>(ext_type)) ? 1 : 0;
}

/* ========================================================================
 * LeafNode
 * ======================================================================== */

extern "C" mlspp_leaf_node_t* mlspp_leaf_node_create(
    const mlspp_cipher_suite_t* cs,
    const mlspp_hpke_public_key_t* enc_key,
    const mlspp_signature_public_key_t* sig_key,
    const mlspp_credential_t* cred,
    const mlspp_capabilities_t* caps,
    const mlspp_lifetime_t* lifetime,
    const mlspp_extension_list_t* exts,
    const mlspp_signature_private_key_t* sig_priv) {
    clear_error();
    try {
        auto ln = ns::LeafNode(
            cs->inner,
            enc_key->inner,
            sig_key->inner,
            cred->inner,
            caps->inner,
            lifetime->inner,
            exts->inner,
            sig_priv->inner);
        return new mlspp_leaf_node_t{ std::move(ln) };
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

extern "C" void mlspp_leaf_node_free(mlspp_leaf_node_t* ln) {
    if (!ln) return;
    delete ln;
}

extern "C" mlspp_credential_t* mlspp_leaf_node_credential(
    const mlspp_leaf_node_t* ln) {
    if (!ln) return nullptr;
    return new mlspp_credential_t{ ln->inner.credential };
}

extern "C" mlspp_signature_public_key_t* mlspp_leaf_node_signature_key(
    const mlspp_leaf_node_t* ln) {
    if (!ln) return nullptr;
    return new mlspp_signature_public_key_t{ ln->inner.signature_key };
}

extern "C" mlspp_hpke_public_key_t* mlspp_leaf_node_encryption_key(
    const mlspp_leaf_node_t* ln) {
    if (!ln) return nullptr;
    return new mlspp_hpke_public_key_t{ ln->inner.encryption_key };
}

/* ========================================================================
 * KeyPackage
 * ======================================================================== */

extern "C" mlspp_key_package_t* mlspp_key_package_create(
    const mlspp_cipher_suite_t* cs,
    const mlspp_hpke_public_key_t* init_key,
    const mlspp_leaf_node_t* leaf_node,
    const mlspp_extension_list_t* exts,
    const mlspp_signature_private_key_t* sig_priv) {
    clear_error();
    try {
        auto kp = ns::KeyPackage(
            cs->inner,
            init_key->inner,
            leaf_node->inner,
            exts->inner,
            sig_priv->inner);
        return new mlspp_key_package_t{ std::move(kp) };
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

extern "C" void mlspp_key_package_free(mlspp_key_package_t* kp) {
    if (!kp) return;
    delete kp;
}

extern "C" int mlspp_key_package_verify(const mlspp_key_package_t* kp) {
    clear_error();
    try {
        return kp->inner.verify() ? 1 : 0;
    } catch (const std::exception& e) {
        set_error(e.what());
        return 0;
    }
}

extern "C" mlspp_bytes_t mlspp_key_package_ref(const mlspp_key_package_t* kp) {
    clear_error();
    try {
        return to_mlspp_bytes(kp->inner.ref());
    } catch (const std::exception& e) {
        set_error(e.what());
        return { nullptr, 0 };
    }
}

extern "C" mlspp_cipher_suite_t* mlspp_key_package_cipher_suite(
    const mlspp_key_package_t* kp) {
    if (!kp) return nullptr;
    return new mlspp_cipher_suite_t{ kp->inner.cipher_suite };
}

extern "C" mlspp_leaf_node_t* mlspp_key_package_leaf_node(
    const mlspp_key_package_t* kp) {
    if (!kp) return nullptr;
    return new mlspp_leaf_node_t{ kp->inner.leaf_node };
}

/* ========================================================================
 * MLSMessage
 * ======================================================================== */

extern "C" void mlspp_mls_message_free(mlspp_mls_message_t* msg) {
    if (!msg) return;
    delete msg;
}

extern "C" mlspp_bytes_t mlspp_mls_message_group_id(
    const mlspp_mls_message_t* msg) {
    clear_error();
    try {
        return to_mlspp_bytes(msg->inner.group_id());
    } catch (const std::exception& e) {
        set_error(e.what());
        return { nullptr, 0 };
    }
}

extern "C" uint64_t mlspp_mls_message_epoch(const mlspp_mls_message_t* msg) {
    clear_error();
    try {
        return msg->inner.epoch();
    } catch (const std::exception& e) {
        set_error(e.what());
        return 0;
    }
}

extern "C" uint16_t mlspp_mls_message_wire_format(
    const mlspp_mls_message_t* msg) {
    if (!msg) return 0;
    return static_cast<uint16_t>(msg->inner.wire_format());
}

/* ========================================================================
 * Welcome / GroupInfo free
 * ======================================================================== */

extern "C" void mlspp_welcome_free(mlspp_welcome_t* w) {
    if (!w) return;
    delete w;
}

extern "C" void mlspp_group_info_free(mlspp_group_info_t* gi) {
    if (!gi) return;
    delete gi;
}

/* ========================================================================
 * State (low-level API)
 * ======================================================================== */

extern "C" mlspp_state_t* mlspp_state_create_new_group(
    const uint8_t* group_id, size_t group_id_len,
    const mlspp_cipher_suite_t* cs,
    const mlspp_hpke_private_key_t* enc_priv,
    const mlspp_signature_private_key_t* sig_priv,
    const mlspp_leaf_node_t* leaf_node,
    const mlspp_extension_list_t* exts) {
    clear_error();
    try {
        auto state = ns::State(
            to_bytes(group_id, group_id_len),
            cs->inner,
            enc_priv->inner,
            sig_priv->inner,
            leaf_node->inner,
            exts->inner);
        return new mlspp_state_t{ std::move(state) };
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

extern "C" mlspp_state_t* mlspp_state_create_from_welcome(
    const mlspp_hpke_private_key_t* init_priv,
    const mlspp_hpke_private_key_t* leaf_priv,
    const mlspp_signature_private_key_t* sig_priv,
    const mlspp_key_package_t* key_package,
    const mlspp_welcome_t* welcome) {
    clear_error();
    try {
        auto state = ns::State(
            init_priv->inner,
            leaf_priv->inner,
            sig_priv->inner,
            key_package->inner,
            welcome->inner,
            std::nullopt, /* tree */
            {} /* psks */);
        return new mlspp_state_t{ std::move(state) };
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

extern "C" void mlspp_state_free(mlspp_state_t* state) {
    if (!state) return;
    delete state;
}

/* --- Accessors --- */

extern "C" mlspp_bytes_t mlspp_state_group_id(const mlspp_state_t* state) {
    if (!state) return { nullptr, 0 };
    return to_mlspp_bytes(state->inner.group_id());
}

extern "C" uint64_t mlspp_state_epoch(const mlspp_state_t* state) {
    if (!state) return 0;
    return state->inner.epoch();
}

extern "C" uint32_t mlspp_state_index(const mlspp_state_t* state) {
    if (!state) return 0;
    return state->inner.index().val;
}

extern "C" mlspp_cipher_suite_t* mlspp_state_cipher_suite(
    const mlspp_state_t* state) {
    if (!state) return nullptr;
    return new mlspp_cipher_suite_t{ state->inner.cipher_suite() };
}

extern "C" mlspp_bytes_t mlspp_state_do_export(
    const mlspp_state_t* state,
    const char* label,
    const uint8_t* context, size_t context_len,
    size_t size) {
    clear_error();
    try {
        auto result = state->inner.do_export(
            std::string(label),
            to_bytes(context, context_len),
            size);
        return to_mlspp_bytes(result);
    } catch (const std::exception& e) {
        set_error(e.what());
        return { nullptr, 0 };
    }
}

extern "C" mlspp_bytes_t mlspp_state_epoch_authenticator(
    const mlspp_state_t* state) {
    if (!state) return { nullptr, 0 };
    return to_mlspp_bytes(state->inner.epoch_authenticator());
}

extern "C" mlspp_group_info_t* mlspp_state_group_info(
    const mlspp_state_t* state, int inline_tree) {
    clear_error();
    try {
        auto gi = state->inner.group_info(inline_tree != 0);
        return new mlspp_group_info_t{ std::move(gi) };
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

/* --- Proposal factories --- */

extern "C" mlspp_mls_message_t* mlspp_state_add(
    mlspp_state_t* state,
    const mlspp_key_package_t* key_package,
    int msg_opts_encrypt,
    const uint8_t* authenticated_data, size_t authenticated_data_len,
    size_t padding_size) {
    clear_error();
    try {
        ns::MessageOpts opts;
        opts.encrypt = (msg_opts_encrypt != 0);
        opts.authenticated_data = to_bytes(authenticated_data, authenticated_data_len);
        opts.padding_size = padding_size;
        auto msg = state->inner.add(key_package->inner, opts);
        return new mlspp_mls_message_t{ std::move(msg) };
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

extern "C" mlspp_mls_message_t* mlspp_state_remove(
    mlspp_state_t* state,
    uint32_t removed_index,
    int msg_opts_encrypt,
    const uint8_t* authenticated_data, size_t authenticated_data_len,
    size_t padding_size) {
    clear_error();
    try {
        ns::MessageOpts opts;
        opts.encrypt = (msg_opts_encrypt != 0);
        opts.authenticated_data = to_bytes(authenticated_data, authenticated_data_len);
        opts.padding_size = padding_size;
        auto msg = state->inner.remove(
            ns::LeafIndex(removed_index), opts);
        return new mlspp_mls_message_t{ std::move(msg) };
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

/* --- Commit --- */

extern "C" mlspp_mls_message_t* mlspp_state_commit(
    mlspp_state_t* state,
    const uint8_t* leaf_secret, size_t leaf_secret_len,
    int force_path,
    int inline_tree,
    int msg_opts_encrypt,
    const uint8_t* authenticated_data, size_t authenticated_data_len,
    size_t padding_size,
    mlspp_welcome_t** out_welcome,
    mlspp_state_t** out_new_state) {
    clear_error();
    try {
        ns::CommitOpts commit_opts;
        commit_opts.force_path = (force_path != 0);
        commit_opts.inline_tree = (inline_tree != 0);

        ns::MessageOpts msg_opts;
        msg_opts.encrypt = (msg_opts_encrypt != 0);
        msg_opts.authenticated_data = to_bytes(authenticated_data, authenticated_data_len);
        msg_opts.padding_size = padding_size;

        auto [commit_msg, welcome, new_state] = state->inner.commit(
            to_bytes(leaf_secret, leaf_secret_len),
            commit_opts, msg_opts);

        if (out_welcome) {
            *out_welcome = new mlspp_welcome_t{ std::move(welcome) };
        }
        if (out_new_state) {
            *out_new_state = new mlspp_state_t{ std::move(new_state) };
        }
        return new mlspp_mls_message_t{ std::move(commit_msg) };
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

/* --- Message handling --- */

extern "C" mlspp_state_t* mlspp_state_handle(
    mlspp_state_t* state,
    const mlspp_mls_message_t* msg) {
    clear_error();
    try {
        auto result = state->inner.handle(msg->inner);
        if (result) {
            return new mlspp_state_t{ std::move(*result) };
        }
        // Proposal was cached successfully. Error stays cleared so callers
        // can distinguish this from a failure (where mlspp_last_error != NULL).
        return nullptr;
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

/* --- Application data protection --- */

extern "C" mlspp_mls_message_t* mlspp_state_protect(
    mlspp_state_t* state,
    const uint8_t* authenticated_data, size_t authenticated_data_len,
    const uint8_t* plaintext, size_t plaintext_len,
    size_t padding_size) {
    clear_error();
    try {
        auto msg = state->inner.protect(
            to_bytes(authenticated_data, authenticated_data_len),
            to_bytes(plaintext, plaintext_len),
            padding_size);
        return new mlspp_mls_message_t{ std::move(msg) };
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

extern "C" mlspp_bytes_t mlspp_state_unprotect(
    mlspp_state_t* state,
    const mlspp_mls_message_t* ct,
    mlspp_bytes_t* out_authenticated_data) {
    clear_error();
    try {
        auto [aad, pt] = state->inner.unprotect(ct->inner);
        if (out_authenticated_data) {
            *out_authenticated_data = to_mlspp_bytes(aad);
        }
        return to_mlspp_bytes(pt);
    } catch (const std::exception& e) {
        set_error(e.what());
        return { nullptr, 0 };
    }
}

/* --- PSK management --- */

extern "C" void mlspp_state_add_external_psk(
    mlspp_state_t* state,
    const uint8_t* id, size_t id_len,
    const uint8_t* secret, size_t secret_len) {
    if (!state) return;
    state->inner.add_external_psk(
        to_bytes(id, id_len), to_bytes(secret, secret_len));
}

extern "C" void mlspp_state_remove_external_psk(
    mlspp_state_t* state,
    const uint8_t* id, size_t id_len) {
    if (!state) return;
    state->inner.remove_external_psk(to_bytes(id, id_len));
}

/* ========================================================================
 * Client (high-level API)
 * ======================================================================== */

extern "C" mlspp_client_t* mlspp_client_create(
    const mlspp_cipher_suite_t* cs,
    const mlspp_signature_private_key_t* sig_priv,
    const mlspp_credential_t* cred) {
    clear_error();
    try {
        auto client = ns::Client(cs->inner, sig_priv->inner, cred->inner);
        return new mlspp_client_t{ std::move(client) };
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

extern "C" void mlspp_client_free(mlspp_client_t* client) {
    if (!client) return;
    delete client;
}

extern "C" mlspp_session_t* mlspp_client_begin_session(
    const mlspp_client_t* client,
    const uint8_t* group_id, size_t group_id_len) {
    clear_error();
    try {
        auto session = client->inner.begin_session(
            to_bytes(group_id, group_id_len));
        return new mlspp_session_t{ std::move(session) };
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

extern "C" mlspp_pending_join_t* mlspp_client_start_join(
    const mlspp_client_t* client) {
    clear_error();
    try {
        auto pj = client->inner.start_join();
        return new mlspp_pending_join_t{ std::move(pj) };
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

/* ========================================================================
 * PendingJoin
 * ======================================================================== */

extern "C" void mlspp_pending_join_free(mlspp_pending_join_t* pj) {
    if (!pj) return;
    delete pj;
}

extern "C" mlspp_bytes_t mlspp_pending_join_key_package(
    const mlspp_pending_join_t* pj) {
    clear_error();
    try {
        return to_mlspp_bytes(pj->inner.key_package());
    } catch (const std::exception& e) {
        set_error(e.what());
        return { nullptr, 0 };
    }
}

extern "C" mlspp_session_t* mlspp_pending_join_complete(
    const mlspp_pending_join_t* pj,
    const uint8_t* welcome_data, size_t welcome_data_len) {
    clear_error();
    try {
        auto session = pj->inner.complete(
            to_bytes(welcome_data, welcome_data_len));
        return new mlspp_session_t{ std::move(session) };
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

/* ========================================================================
 * Session
 * ======================================================================== */

extern "C" void mlspp_session_free(mlspp_session_t* session) {
    if (!session) return;
    delete session;
}

extern "C" void mlspp_session_encrypt_handshake(
    mlspp_session_t* session, int enabled) {
    if (!session) return;
    session->inner.encrypt_handshake(enabled != 0);
}

extern "C" mlspp_bytes_t mlspp_session_add(
    mlspp_session_t* session,
    const uint8_t* key_package_data, size_t key_package_data_len) {
    clear_error();
    try {
        auto result = session->inner.add(
            to_bytes(key_package_data, key_package_data_len));
        return to_mlspp_bytes(result);
    } catch (const std::exception& e) {
        set_error(e.what());
        return { nullptr, 0 };
    }
}

extern "C" mlspp_bytes_t mlspp_session_update(mlspp_session_t* session) {
    clear_error();
    try {
        auto result = session->inner.update();
        return to_mlspp_bytes(result);
    } catch (const std::exception& e) {
        set_error(e.what());
        return { nullptr, 0 };
    }
}

extern "C" mlspp_bytes_t mlspp_session_remove(
    mlspp_session_t* session, uint32_t index) {
    clear_error();
    try {
        auto result = session->inner.remove(index);
        return to_mlspp_bytes(result);
    } catch (const std::exception& e) {
        set_error(e.what());
        return { nullptr, 0 };
    }
}

extern "C" mlspp_bytes_t mlspp_session_commit_proposal(
    mlspp_session_t* session,
    const uint8_t* proposal_data, size_t proposal_data_len,
    mlspp_bytes_t* out_welcome) {
    clear_error();
    try {
        auto [commit, welcome] = session->inner.commit(
            to_bytes(proposal_data, proposal_data_len));
        if (out_welcome) {
            *out_welcome = to_mlspp_bytes(welcome);
        }
        return to_mlspp_bytes(commit);
    } catch (const std::exception& e) {
        set_error(e.what());
        return { nullptr, 0 };
    }
}

extern "C" mlspp_bytes_t mlspp_session_commit_proposals(
    mlspp_session_t* session,
    const mlspp_bytes_t* proposals, size_t proposals_count,
    mlspp_bytes_t* out_welcome) {
    clear_error();
    try {
        std::vector<bytes> props;
        props.reserve(proposals_count);
        for (size_t i = 0; i < proposals_count; i++) {
            props.push_back(to_bytes(proposals[i].data, proposals[i].len));
        }
        auto [commit, welcome] = session->inner.commit(props);
        if (out_welcome) {
            *out_welcome = to_mlspp_bytes(welcome);
        }
        return to_mlspp_bytes(commit);
    } catch (const std::exception& e) {
        set_error(e.what());
        return { nullptr, 0 };
    }
}

extern "C" mlspp_bytes_t mlspp_session_commit_empty(
    mlspp_session_t* session,
    mlspp_bytes_t* out_welcome) {
    clear_error();
    try {
        auto [commit, welcome] = session->inner.commit();
        if (out_welcome) {
            *out_welcome = to_mlspp_bytes(welcome);
        }
        return to_mlspp_bytes(commit);
    } catch (const std::exception& e) {
        set_error(e.what());
        return { nullptr, 0 };
    }
}

extern "C" int mlspp_session_handle(
    mlspp_session_t* session,
    const uint8_t* handshake_data, size_t handshake_data_len) {
    clear_error();
    try {
        return session->inner.handle(
            to_bytes(handshake_data, handshake_data_len)) ? 1 : 0;
    } catch (const std::exception& e) {
        set_error(e.what());
        return -1;
    }
}

extern "C" mlspp_bytes_t mlspp_session_protect(
    mlspp_session_t* session,
    const uint8_t* plaintext, size_t plaintext_len) {
    clear_error();
    try {
        auto result = session->inner.protect(
            to_bytes(plaintext, plaintext_len));
        return to_mlspp_bytes(result);
    } catch (const std::exception& e) {
        set_error(e.what());
        return { nullptr, 0 };
    }
}

extern "C" mlspp_bytes_t mlspp_session_unprotect(
    mlspp_session_t* session,
    const uint8_t* ciphertext, size_t ciphertext_len) {
    clear_error();
    try {
        auto result = session->inner.unprotect(
            to_bytes(ciphertext, ciphertext_len));
        return to_mlspp_bytes(result);
    } catch (const std::exception& e) {
        set_error(e.what());
        return { nullptr, 0 };
    }
}

extern "C" uint64_t mlspp_session_epoch(const mlspp_session_t* session) {
    if (!session) return 0;
    return session->inner.epoch();
}

extern "C" uint32_t mlspp_session_index(const mlspp_session_t* session) {
    if (!session) return 0;
    return session->inner.index().val;
}

extern "C" uint16_t mlspp_session_cipher_suite(
    const mlspp_session_t* session) {
    if (!session) return 0;
    return static_cast<uint16_t>(session->inner.cipher_suite().cipher_suite());
}

extern "C" mlspp_bytes_t mlspp_session_do_export(
    const mlspp_session_t* session,
    const char* label,
    const uint8_t* context, size_t context_len,
    size_t size) {
    clear_error();
    try {
        auto result = session->inner.do_export(
            std::string(label),
            to_bytes(context, context_len),
            size);
        return to_mlspp_bytes(result);
    } catch (const std::exception& e) {
        set_error(e.what());
        return { nullptr, 0 };
    }
}

extern "C" mlspp_bytes_t mlspp_session_epoch_authenticator(
    const mlspp_session_t* session) {
    if (!session) return { nullptr, 0 };
    return to_mlspp_bytes(session->inner.epoch_authenticator());
}

/* ========================================================================
 * TLS serialization helpers
 * ======================================================================== */

extern "C" mlspp_bytes_t mlspp_group_info_serialize(
    const mlspp_group_info_t* gi) {
    clear_error();
    try {
        auto data = ns::tls::marshal(gi->inner);
        return to_mlspp_bytes(data);
    } catch (const std::exception& e) {
        set_error(e.what());
        return { nullptr, 0 };
    }
}

extern "C" mlspp_group_info_t* mlspp_group_info_deserialize(
    const uint8_t* data, size_t data_len) {
    clear_error();
    try {
        auto b = to_bytes(data, data_len);
        auto gi = ns::tls::get<ns::GroupInfo>(b);
        return new mlspp_group_info_t{ std::move(gi) };
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

extern "C" mlspp_bytes_t mlspp_key_package_serialize(
    const mlspp_key_package_t* kp) {
    clear_error();
    try {
        auto data = ns::tls::marshal(kp->inner);
        return to_mlspp_bytes(data);
    } catch (const std::exception& e) {
        set_error(e.what());
        return { nullptr, 0 };
    }
}

extern "C" mlspp_key_package_t* mlspp_key_package_deserialize(
    const uint8_t* data, size_t data_len) {
    clear_error();
    try {
        auto b = to_bytes(data, data_len);
        auto kp = ns::tls::get<ns::KeyPackage>(b);
        return new mlspp_key_package_t{ std::move(kp) };
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

extern "C" mlspp_bytes_t mlspp_mls_message_serialize(
    const mlspp_mls_message_t* msg) {
    clear_error();
    try {
        auto data = ns::tls::marshal(msg->inner);
        return to_mlspp_bytes(data);
    } catch (const std::exception& e) {
        set_error(e.what());
        return { nullptr, 0 };
    }
}

extern "C" mlspp_mls_message_t* mlspp_mls_message_deserialize(
    const uint8_t* data, size_t data_len) {
    clear_error();
    try {
        auto b = to_bytes(data, data_len);
        auto msg = ns::tls::get<ns::MLSMessage>(b);
        return new mlspp_mls_message_t{ std::move(msg) };
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

extern "C" mlspp_bytes_t mlspp_welcome_serialize(const mlspp_welcome_t* w) {
    clear_error();
    try {
        auto data = ns::tls::marshal(w->inner);
        return to_mlspp_bytes(data);
    } catch (const std::exception& e) {
        set_error(e.what());
        return { nullptr, 0 };
    }
}

extern "C" mlspp_welcome_t* mlspp_welcome_deserialize(
    const uint8_t* data, size_t data_len) {
    clear_error();
    try {
        auto b = to_bytes(data, data_len);
        auto w = ns::tls::get<ns::Welcome>(b);
        return new mlspp_welcome_t{ std::move(w) };
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}
