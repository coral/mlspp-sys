#ifndef MLSPP_SYS_WRAPPER_H
#define MLSPP_SYS_WRAPPER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Error handling
 * ======================================================================== */

/** Returns the last error message, or NULL if no error. Thread-local. */
const char* mlspp_last_error(void);

/* ========================================================================
 * Buffer type
 * ======================================================================== */

typedef struct {
    const uint8_t* data;
    size_t len;
} mlspp_bytes_t;

/** Create a bytes buffer by copying data. Free with mlspp_bytes_free. */
mlspp_bytes_t mlspp_bytes_copy(const uint8_t* data, size_t len);

/** Free a bytes buffer returned from mlspp functions. */
void mlspp_bytes_free(mlspp_bytes_t buf);

/* ========================================================================
 * Opaque handle types
 * ======================================================================== */

typedef struct mlspp_cipher_suite_t mlspp_cipher_suite_t;
typedef struct mlspp_hpke_private_key_t mlspp_hpke_private_key_t;
typedef struct mlspp_hpke_public_key_t mlspp_hpke_public_key_t;
typedef struct mlspp_signature_private_key_t mlspp_signature_private_key_t;
typedef struct mlspp_signature_public_key_t mlspp_signature_public_key_t;
typedef struct mlspp_credential_t mlspp_credential_t;
typedef struct mlspp_leaf_node_t mlspp_leaf_node_t;
typedef struct mlspp_key_package_t mlspp_key_package_t;
typedef struct mlspp_extension_list_t mlspp_extension_list_t;
typedef struct mlspp_capabilities_t mlspp_capabilities_t;
typedef struct mlspp_lifetime_t mlspp_lifetime_t;
typedef struct mlspp_mls_message_t mlspp_mls_message_t;
typedef struct mlspp_group_info_t mlspp_group_info_t;
typedef struct mlspp_welcome_t mlspp_welcome_t;
typedef struct mlspp_state_t mlspp_state_t;
typedef struct mlspp_client_t mlspp_client_t;
typedef struct mlspp_pending_join_t mlspp_pending_join_t;
typedef struct mlspp_session_t mlspp_session_t;

/* ========================================================================
 * CipherSuite
 * ======================================================================== */

/** Create a CipherSuite from its numeric ID. Returns NULL on failure. */
mlspp_cipher_suite_t* mlspp_cipher_suite_create(uint16_t id);
/** Free a CipherSuite handle. */
void mlspp_cipher_suite_free(mlspp_cipher_suite_t* cs);

/** Get the numeric ID of this cipher suite. */
uint16_t mlspp_cipher_suite_id(const mlspp_cipher_suite_t* cs);

/** Get the signature scheme associated with this cipher suite. */
uint16_t mlspp_cipher_suite_signature_scheme(const mlspp_cipher_suite_t* cs);

/** Get the secret size in bytes for this cipher suite. */
size_t mlspp_cipher_suite_secret_size(const mlspp_cipher_suite_t* cs);

/** Get the key size in bytes for this cipher suite. */
size_t mlspp_cipher_suite_key_size(const mlspp_cipher_suite_t* cs);

/** Get the nonce size in bytes for this cipher suite. */
size_t mlspp_cipher_suite_nonce_size(const mlspp_cipher_suite_t* cs);

/* ========================================================================
 * HPKEPrivateKey
 * ======================================================================== */

/** Generate a new random HPKE private key. Returns NULL on failure. */
mlspp_hpke_private_key_t* mlspp_hpke_private_key_generate(
    const mlspp_cipher_suite_t* cs);

/** Derive an HPKE private key from a secret. Returns NULL on failure. */
mlspp_hpke_private_key_t* mlspp_hpke_private_key_derive(
    const mlspp_cipher_suite_t* cs, const uint8_t* secret, size_t secret_len);

/** Parse an HPKE private key from raw bytes. Returns NULL on failure. */
mlspp_hpke_private_key_t* mlspp_hpke_private_key_parse(
    const mlspp_cipher_suite_t* cs, const uint8_t* data, size_t data_len);

/** Free an HPKE private key handle. */
void mlspp_hpke_private_key_free(mlspp_hpke_private_key_t* key);

/** Get the raw private key data. Caller must free result with mlspp_bytes_free. */
mlspp_bytes_t mlspp_hpke_private_key_data(const mlspp_hpke_private_key_t* key);

/** Get the associated public key. Caller must free result. */
mlspp_hpke_public_key_t* mlspp_hpke_private_key_public_key(
    const mlspp_hpke_private_key_t* key);

/** Decrypt an HPKE ciphertext. Returns decrypted data or {NULL,0} on failure. */
mlspp_bytes_t mlspp_hpke_private_key_decrypt(
    const mlspp_hpke_private_key_t* key,
    const mlspp_cipher_suite_t* cs,
    const char* label,
    const uint8_t* context, size_t context_len,
    const uint8_t* kem_output, size_t kem_output_len,
    const uint8_t* ciphertext, size_t ciphertext_len);

/* ========================================================================
 * HPKEPublicKey
 * ======================================================================== */

/** Create an HPKE public key from raw bytes. Returns NULL on failure. */
mlspp_hpke_public_key_t* mlspp_hpke_public_key_from_data(
    const uint8_t* data, size_t data_len);

/** Free an HPKE public key handle. */
void mlspp_hpke_public_key_free(mlspp_hpke_public_key_t* key);

/** Get the raw public key data. Caller must free result with mlspp_bytes_free. */
mlspp_bytes_t mlspp_hpke_public_key_data(const mlspp_hpke_public_key_t* key);

/**
 * Encrypt data with this public key.
 * out_kem_output and out_ciphertext must be freed with mlspp_bytes_free.
 * Returns 0 on success, -1 on failure.
 */
int mlspp_hpke_public_key_encrypt(
    const mlspp_hpke_public_key_t* key,
    const mlspp_cipher_suite_t* cs,
    const char* label,
    const uint8_t* context, size_t context_len,
    const uint8_t* plaintext, size_t plaintext_len,
    mlspp_bytes_t* out_kem_output,
    mlspp_bytes_t* out_ciphertext);

/* ========================================================================
 * SignaturePrivateKey
 * ======================================================================== */

/** Generate a new random signature private key. Returns NULL on failure. */
mlspp_signature_private_key_t* mlspp_signature_private_key_generate(
    const mlspp_cipher_suite_t* cs);

/** Derive a signature private key from a secret. Returns NULL on failure. */
mlspp_signature_private_key_t* mlspp_signature_private_key_derive(
    const mlspp_cipher_suite_t* cs, const uint8_t* secret, size_t secret_len);

/** Parse a signature private key from raw bytes. Returns NULL on failure. */
mlspp_signature_private_key_t* mlspp_signature_private_key_parse(
    const mlspp_cipher_suite_t* cs, const uint8_t* data, size_t data_len);

/** Free a signature private key handle. */
void mlspp_signature_private_key_free(mlspp_signature_private_key_t* key);

/** Get the raw private key data. Caller must free result with mlspp_bytes_free. */
mlspp_bytes_t mlspp_signature_private_key_data(
    const mlspp_signature_private_key_t* key);

/** Get the associated public key. Caller must free result. */
mlspp_signature_public_key_t* mlspp_signature_private_key_public_key(
    const mlspp_signature_private_key_t* key);

/** Sign a message. Returns signature bytes or {NULL,0} on failure. */
mlspp_bytes_t mlspp_signature_private_key_sign(
    const mlspp_signature_private_key_t* key,
    const mlspp_cipher_suite_t* cs,
    const char* label,
    const uint8_t* message, size_t message_len);

/* ========================================================================
 * SignaturePublicKey
 * ======================================================================== */

/** Create a signature public key from raw bytes. Returns NULL on failure. */
mlspp_signature_public_key_t* mlspp_signature_public_key_from_data(
    const uint8_t* data, size_t data_len);

/** Free a signature public key handle. */
void mlspp_signature_public_key_free(mlspp_signature_public_key_t* key);

/** Get the raw public key data. Caller must free result with mlspp_bytes_free. */
mlspp_bytes_t mlspp_signature_public_key_data(
    const mlspp_signature_public_key_t* key);

/** Verify a signature. Returns 1 if valid, 0 if invalid, -1 on error. */
int mlspp_signature_public_key_verify(
    const mlspp_signature_public_key_t* key,
    const mlspp_cipher_suite_t* cs,
    const char* label,
    const uint8_t* message, size_t message_len,
    const uint8_t* signature, size_t signature_len);

/* ========================================================================
 * Credential
 * ======================================================================== */

/** Create a basic credential from an identity byte string. Returns NULL on failure. */
mlspp_credential_t* mlspp_credential_basic(
    const uint8_t* identity, size_t identity_len);

/** Create an X.509 credential from a DER certificate chain. Returns NULL on failure. */
mlspp_credential_t* mlspp_credential_x509(
    const uint8_t* const* der_chain, const size_t* der_chain_lens,
    size_t chain_count);

/** Free a credential handle. */
void mlspp_credential_free(mlspp_credential_t* cred);

/** Returns the credential type (1=basic, 2=x509). */
uint16_t mlspp_credential_type(const mlspp_credential_t* cred);

/* ========================================================================
 * Capabilities
 * ======================================================================== */

/** Create default capabilities. */
mlspp_capabilities_t* mlspp_capabilities_create_default(void);
/** Free a capabilities handle. */
void mlspp_capabilities_free(mlspp_capabilities_t* caps);

/* ========================================================================
 * Lifetime
 * ======================================================================== */

/** Create default lifetime. */
mlspp_lifetime_t* mlspp_lifetime_create_default(void);

/** Create lifetime with explicit bounds. */
mlspp_lifetime_t* mlspp_lifetime_create(uint64_t not_before, uint64_t not_after);
/** Free a lifetime handle. */
void mlspp_lifetime_free(mlspp_lifetime_t* lt);

/* ========================================================================
 * ExtensionList
 * ======================================================================== */

/** Create an empty extension list. */
mlspp_extension_list_t* mlspp_extension_list_create(void);
/** Free an extension list handle. */
void mlspp_extension_list_free(mlspp_extension_list_t* exts);

/** Add a raw extension. */
int mlspp_extension_list_add(
    mlspp_extension_list_t* exts,
    uint16_t ext_type,
    const uint8_t* data, size_t data_len);

/** Check if extension type is present. Returns 1 if present, 0 if not. */
int mlspp_extension_list_has(
    const mlspp_extension_list_t* exts, uint16_t ext_type);

/* ========================================================================
 * LeafNode
 * ======================================================================== */

/**
 * Create a new LeafNode for key_package source.
 * Returns NULL on failure.
 */
mlspp_leaf_node_t* mlspp_leaf_node_create(
    const mlspp_cipher_suite_t* cs,
    const mlspp_hpke_public_key_t* enc_key,
    const mlspp_signature_public_key_t* sig_key,
    const mlspp_credential_t* cred,
    const mlspp_capabilities_t* caps,
    const mlspp_lifetime_t* lifetime,
    const mlspp_extension_list_t* exts,
    const mlspp_signature_private_key_t* sig_priv);
/** Free a leaf node handle. */
void mlspp_leaf_node_free(mlspp_leaf_node_t* ln);

/** Get the credential from a leaf node. Caller must free. */
mlspp_credential_t* mlspp_leaf_node_credential(const mlspp_leaf_node_t* ln);

/** Get the signature public key from a leaf node. Caller must free. */
mlspp_signature_public_key_t* mlspp_leaf_node_signature_key(
    const mlspp_leaf_node_t* ln);

/** Get the HPKE public key from a leaf node. Caller must free. */
mlspp_hpke_public_key_t* mlspp_leaf_node_encryption_key(
    const mlspp_leaf_node_t* ln);

/* ========================================================================
 * KeyPackage
 * ======================================================================== */

/**
 * Create a new KeyPackage.
 * Returns NULL on failure.
 */
mlspp_key_package_t* mlspp_key_package_create(
    const mlspp_cipher_suite_t* cs,
    const mlspp_hpke_public_key_t* init_key,
    const mlspp_leaf_node_t* leaf_node,
    const mlspp_extension_list_t* exts,
    const mlspp_signature_private_key_t* sig_priv);
/** Free a key package handle. */
void mlspp_key_package_free(mlspp_key_package_t* kp);

/** Verify the key package signatures. Returns 1 if valid, 0 if not. */
int mlspp_key_package_verify(const mlspp_key_package_t* kp);

/** Get the ref (hash) of the key package. Caller must free bytes. */
mlspp_bytes_t mlspp_key_package_ref(const mlspp_key_package_t* kp);

/** Get the cipher suite from the key package. Caller must free. */
mlspp_cipher_suite_t* mlspp_key_package_cipher_suite(
    const mlspp_key_package_t* kp);

/** Get the leaf node from the key package. Caller must free. */
mlspp_leaf_node_t* mlspp_key_package_leaf_node(const mlspp_key_package_t* kp);

/* ========================================================================
 * MLSMessage
 * ======================================================================== */

/** Free an MLS message handle. */
void mlspp_mls_message_free(mlspp_mls_message_t* msg);

/** Get the group_id from an MLSMessage. Caller must free bytes. */
mlspp_bytes_t mlspp_mls_message_group_id(const mlspp_mls_message_t* msg);

/** Get the epoch from an MLSMessage. */
uint64_t mlspp_mls_message_epoch(const mlspp_mls_message_t* msg);

/** Get the wire format. */
uint16_t mlspp_mls_message_wire_format(const mlspp_mls_message_t* msg);

/* ========================================================================
 * Welcome
 * ======================================================================== */

/** Free a Welcome message handle. */
void mlspp_welcome_free(mlspp_welcome_t* w);

/* ========================================================================
 * GroupInfo
 * ======================================================================== */

/** Free a GroupInfo handle. */
void mlspp_group_info_free(mlspp_group_info_t* gi);

/* ========================================================================
 * State (low-level API)
 * ======================================================================== */

/**
 * Create a new group (empty state).
 * Returns NULL on failure.
 */
mlspp_state_t* mlspp_state_create_new_group(
    const uint8_t* group_id, size_t group_id_len,
    const mlspp_cipher_suite_t* cs,
    const mlspp_hpke_private_key_t* enc_priv,
    const mlspp_signature_private_key_t* sig_priv,
    const mlspp_leaf_node_t* leaf_node,
    const mlspp_extension_list_t* exts);

/**
 * Join from a Welcome message.
 * Returns NULL on failure.
 */
mlspp_state_t* mlspp_state_create_from_welcome(
    const mlspp_hpke_private_key_t* init_priv,
    const mlspp_hpke_private_key_t* leaf_priv,
    const mlspp_signature_private_key_t* sig_priv,
    const mlspp_key_package_t* key_package,
    const mlspp_welcome_t* welcome);

/** Free a State handle. */
void mlspp_state_free(mlspp_state_t* state);

/* --- Accessors --- */

/** Get the group ID. Caller must free returned bytes with mlspp_bytes_free. */
mlspp_bytes_t mlspp_state_group_id(const mlspp_state_t* state);

/** Get the current epoch number. */
uint64_t mlspp_state_epoch(const mlspp_state_t* state);

/** Get this member's leaf index in the group. */
uint32_t mlspp_state_index(const mlspp_state_t* state);

/** Get the cipher suite used by this group. Caller must free result. */
mlspp_cipher_suite_t* mlspp_state_cipher_suite(const mlspp_state_t* state);

/** Export a secret. Caller must free returned bytes. */
mlspp_bytes_t mlspp_state_do_export(
    const mlspp_state_t* state,
    const char* label,
    const uint8_t* context, size_t context_len,
    size_t size);

/** Get epoch authenticator. Caller must free returned bytes. */
mlspp_bytes_t mlspp_state_epoch_authenticator(const mlspp_state_t* state);

/** Get group info. Caller must free. */
mlspp_group_info_t* mlspp_state_group_info(
    const mlspp_state_t* state, int inline_tree);

/* --- Proposal factories --- */

/**
 * Create an Add proposal MLSMessage.
 * msg_opts_encrypt: 0=public, 1=encrypted
 */
mlspp_mls_message_t* mlspp_state_add(
    mlspp_state_t* state,
    const mlspp_key_package_t* key_package,
    int msg_opts_encrypt,
    const uint8_t* authenticated_data, size_t authenticated_data_len,
    size_t padding_size);

/** Create a Remove proposal MLSMessage by leaf index. */
mlspp_mls_message_t* mlspp_state_remove(
    mlspp_state_t* state,
    uint32_t removed_index,
    int msg_opts_encrypt,
    const uint8_t* authenticated_data, size_t authenticated_data_len,
    size_t padding_size);

/* --- Commit --- */

/**
 * Commit pending proposals.
 * out_welcome may be set to a new Welcome (caller must free), or NULL.
 * out_new_state is the post-commit state (caller must free).
 * Returns the commit MLSMessage, or NULL on failure.
 */
mlspp_mls_message_t* mlspp_state_commit(
    mlspp_state_t* state,
    const uint8_t* leaf_secret, size_t leaf_secret_len,
    int force_path,
    int inline_tree,
    int msg_opts_encrypt,
    const uint8_t* authenticated_data, size_t authenticated_data_len,
    size_t padding_size,
    mlspp_welcome_t** out_welcome,
    mlspp_state_t** out_new_state);

/* --- Message handling --- */

/**
 * Handle an incoming MLS message.
 * Returns a new State if the message causes a state transition (e.g. commit),
 * or NULL if it's a proposal (cached internally) or on error.
 * On success (including cached proposal), mlspp_last_error() returns NULL.
 * On failure, mlspp_last_error() returns a non-NULL error string.
 */
mlspp_state_t* mlspp_state_handle(
    mlspp_state_t* state,
    const mlspp_mls_message_t* msg);

/* --- Application data protection --- */

/** Encrypt application data. Returns MLSMessage or NULL on failure. */
mlspp_mls_message_t* mlspp_state_protect(
    mlspp_state_t* state,
    const uint8_t* authenticated_data, size_t authenticated_data_len,
    const uint8_t* plaintext, size_t plaintext_len,
    size_t padding_size);

/**
 * Decrypt application data.
 * out_authenticated_data: authenticated data from the message (caller frees).
 * Returns plaintext bytes, or {NULL,0} on failure.
 */
mlspp_bytes_t mlspp_state_unprotect(
    mlspp_state_t* state,
    const mlspp_mls_message_t* ct,
    mlspp_bytes_t* out_authenticated_data);

/* --- PSK management --- */

/** Register an external PSK with the group state. */
void mlspp_state_add_external_psk(
    mlspp_state_t* state,
    const uint8_t* id, size_t id_len,
    const uint8_t* secret, size_t secret_len);

/** Remove a previously registered external PSK by ID. */
void mlspp_state_remove_external_psk(
    mlspp_state_t* state,
    const uint8_t* id, size_t id_len);

/* ========================================================================
 * Client / Session (high-level API)
 * ======================================================================== */

/** Create a new Client with the given cipher suite, signing key, and credential. Returns NULL on failure. */
mlspp_client_t* mlspp_client_create(
    const mlspp_cipher_suite_t* cs,
    const mlspp_signature_private_key_t* sig_priv,
    const mlspp_credential_t* cred);

/** Free a Client handle. */
void mlspp_client_free(mlspp_client_t* client);

/** Begin a new session (create a group). Caller must free returned session. */
mlspp_session_t* mlspp_client_begin_session(
    const mlspp_client_t* client,
    const uint8_t* group_id, size_t group_id_len);

/** Start joining a group. Caller must free returned PendingJoin. */
mlspp_pending_join_t* mlspp_client_start_join(const mlspp_client_t* client);

/* --- PendingJoin --- */

/** Free a PendingJoin handle. */
void mlspp_pending_join_free(mlspp_pending_join_t* pj);

/** Get the serialized key package. Caller must free bytes. */
mlspp_bytes_t mlspp_pending_join_key_package(const mlspp_pending_join_t* pj);

/** Complete the join with a Welcome message. Caller must free returned session. */
mlspp_session_t* mlspp_pending_join_complete(
    const mlspp_pending_join_t* pj,
    const uint8_t* welcome_data, size_t welcome_data_len);

/* --- Session --- */

/** Free a Session handle. */
void mlspp_session_free(mlspp_session_t* session);

/** Enable or disable handshake message encryption (0=plaintext, 1=encrypted). */
void mlspp_session_encrypt_handshake(mlspp_session_t* session, int enabled);

/** Add a member by key package data. Returns serialized proposal. */
mlspp_bytes_t mlspp_session_add(
    mlspp_session_t* session,
    const uint8_t* key_package_data, size_t key_package_data_len);

/** Update own leaf. Returns serialized proposal. */
mlspp_bytes_t mlspp_session_update(mlspp_session_t* session);

/** Remove a member by index. Returns serialized proposal. */
mlspp_bytes_t mlspp_session_remove(mlspp_session_t* session, uint32_t index);

/**
 * Commit a single proposal.
 * out_welcome: serialized welcome (caller frees), or {NULL,0}.
 * Returns serialized commit, or {NULL,0} on failure.
 */
mlspp_bytes_t mlspp_session_commit_proposal(
    mlspp_session_t* session,
    const uint8_t* proposal_data, size_t proposal_data_len,
    mlspp_bytes_t* out_welcome);

/**
 * Commit multiple proposals.
 * proposals: array of mlspp_bytes_t
 * Returns serialized commit, or {NULL,0} on failure.
 */
mlspp_bytes_t mlspp_session_commit_proposals(
    mlspp_session_t* session,
    const mlspp_bytes_t* proposals, size_t proposals_count,
    mlspp_bytes_t* out_welcome);

/**
 * Commit with no pending proposals (empty commit).
 * Returns serialized commit, or {NULL,0} on failure.
 */
mlspp_bytes_t mlspp_session_commit_empty(
    mlspp_session_t* session,
    mlspp_bytes_t* out_welcome);

/** Handle an incoming handshake message. Returns 1 on state change, 0 otherwise. */
int mlspp_session_handle(
    mlspp_session_t* session,
    const uint8_t* handshake_data, size_t handshake_data_len);

/** Encrypt application data. Returns ciphertext bytes. */
mlspp_bytes_t mlspp_session_protect(
    mlspp_session_t* session,
    const uint8_t* plaintext, size_t plaintext_len);

/** Decrypt application data. Returns plaintext bytes. */
mlspp_bytes_t mlspp_session_unprotect(
    mlspp_session_t* session,
    const uint8_t* ciphertext, size_t ciphertext_len);

/** Get the current epoch number. */
uint64_t mlspp_session_epoch(const mlspp_session_t* session);

/** Get this member's leaf index in the group. */
uint32_t mlspp_session_index(const mlspp_session_t* session);

/** Get the cipher suite ID used by this session. */
uint16_t mlspp_session_cipher_suite(const mlspp_session_t* session);

/** Export a secret from the session. Caller must free returned bytes with mlspp_bytes_free. */
mlspp_bytes_t mlspp_session_do_export(
    const mlspp_session_t* session,
    const char* label,
    const uint8_t* context, size_t context_len,
    size_t size);

/** Get the epoch authenticator. Caller must free returned bytes with mlspp_bytes_free. */
mlspp_bytes_t mlspp_session_epoch_authenticator(
    const mlspp_session_t* session);

/* ========================================================================
 * TLS serialization helpers
 * ======================================================================== */

/**
 * Serialize a GroupInfo to TLS wire format.
 * Caller must free returned bytes.
 */
mlspp_bytes_t mlspp_group_info_serialize(const mlspp_group_info_t* gi);

/**
 * Deserialize a GroupInfo from TLS wire format.
 * Returns NULL on failure.
 */
mlspp_group_info_t* mlspp_group_info_deserialize(
    const uint8_t* data, size_t data_len);

/**
 * Serialize a KeyPackage to TLS wire format.
 * Caller must free returned bytes.
 */
mlspp_bytes_t mlspp_key_package_serialize(const mlspp_key_package_t* kp);

/**
 * Deserialize a KeyPackage from TLS wire format.
 * Returns NULL on failure.
 */
mlspp_key_package_t* mlspp_key_package_deserialize(
    const uint8_t* data, size_t data_len);

/**
 * Serialize an MLSMessage to TLS wire format.
 */
mlspp_bytes_t mlspp_mls_message_serialize(const mlspp_mls_message_t* msg);

/**
 * Deserialize an MLSMessage from TLS wire format.
 */
mlspp_mls_message_t* mlspp_mls_message_deserialize(
    const uint8_t* data, size_t data_len);

/**
 * Serialize a Welcome to TLS wire format.
 */
mlspp_bytes_t mlspp_welcome_serialize(const mlspp_welcome_t* w);

/**
 * Deserialize a Welcome from TLS wire format.
 */
mlspp_welcome_t* mlspp_welcome_deserialize(
    const uint8_t* data, size_t data_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MLSPP_SYS_WRAPPER_H */
