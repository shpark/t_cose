/*
 * t_cose_gp_tee_crypto.h
 *
 * Copyright 2025, Seonghyun Park
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose_crypto.h"

bool t_cose_crypto_is_algorithm_supported(int32_t cose_algorithm_id) {
        return false;
}

enum t_cose_err_t
t_cose_crypto_sig_size(int32_t            cose_algorithm_id,
                       struct t_cose_key  signing_key,
                       size_t            *sig_size) {
	return T_COSE_SUCCESS;
}

enum t_cose_err_t
t_cose_crypto_sign(int32_t                cose_algorithm_id,
                   struct t_cose_key      signing_key,
                   struct q_useful_buf_c  hash_to_sign,
                   struct q_useful_buf    signature_buffer,
                   struct q_useful_buf_c *signature) {
	return T_COSE_SUCCESS;
}

enum t_cose_err_t
t_cose_crypto_verify(int32_t               cose_algorithm_id,
                     struct t_cose_key     verification_key,
                     struct q_useful_buf_c kid,
                     struct q_useful_buf_c hash_to_verify,
                     struct q_useful_buf_c signature) {
	return T_COSE_SUCCESS;
}

#ifndef t_cose_disable_eddsa

enum t_cose_err_t
t_cose_crypto_sign_eddsa(struct t_cose_key      signing_key,
                         struct q_useful_buf_c  tbs,
                         struct q_useful_buf    signature_buffer,
                         struct q_useful_buf_c *signature) {
	return T_COSE_SUCCESS;
}

enum t_cose_err_t
t_cose_crypto_verify_eddsa(struct t_cose_key     verification_key,
                           struct q_useful_buf_c kid,
                           struct q_useful_buf_c tbs,
                           struct q_useful_buf_c signature) {
	return T_COSE_SUCCESS;
}

#endif /* T_COSE_DISABLE_EDDSA */

enum t_cose_err_t
t_cose_crypto_hash_start(struct t_cose_crypto_hash *hash_ctx,
                         int32_t                    cose_hash_alg_id) {
	return T_COSE_SUCCESS;
}

void t_cose_crypto_hash_update(struct t_cose_crypto_hash *hash_ctx,
                               struct q_useful_buf_c      data_to_hash) {
}

enum t_cose_err_t
t_cose_crypto_hash_finish(struct t_cose_crypto_hash *hash_ctx,
                          struct q_useful_buf        buffer_to_hold_result,
                          struct q_useful_buf_c     *hash_result) {
	return T_COSE_SUCCESS;
}
