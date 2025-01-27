/*
 * t_cose_gp_tee_crypto.h
 *
 * Copyright 2025, Seonghyun Park
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include <tee_api.h>
#include <tee_api_defines.h>
#include <tee_api_defines_extensions.h>

#include <trace.h>

#include "qcbor/UsefulBuf.h"
#include "t_cose/t_cose_common.h"
#include "t_cose_crypto.h"
#include "t_cose_standard_constants.h"
#include "tee_api_compat.h"
#include "tee_api_types.h"
#include "utee_defines.h"

bool t_cose_crypto_is_algorithm_supported(int32_t cose_algorithm_id) {
    switch (cose_algorithm_id) {
    case T_COSE_ALGORITHM_ES256:
        return true;
    default:
        return false;
    }
}

enum t_cose_err_t
t_cose_crypto_sig_size(int32_t            cose_algorithm_id,
                       struct t_cose_key  signing_key,
                       size_t            *sig_size) {
    TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;
    TEE_ObjectInfo info = { };

    if (!signing_key.k.key_obj)
        return T_COSE_ERR_EMPTY_KEY;

    res = TEE_GetObjectInfo1(signing_key.k.key_obj, &info);
    if (res != TEE_SUCCESS || info.objectType != TEE_TYPE_ECDSA_KEYPAIR) {
        return T_COSE_ERR_WRONG_TYPE_OF_KEY;
    }

    /* XXX: Check what values go into info... E.g., keySize and maxKeySize */

    switch (cose_algorithm_id) {
    case T_COSE_ALGORITHM_ES256: {
        uint32_t attr = 0;

        res = TEE_GetObjectValueAttribute(signing_key.k.key_obj,
                                          TEE_ATTR_ECC_CURVE, &attr, NULL);
        if (res != TEE_SUCCESS || attr != TEE_ECC_CURVE_NIST_P256) {
            return T_COSE_ERR_FAIL;
        }

        *sig_size = 2 * 32; /* maybe 2 * info.keySize? */
        break;
    }
    default:
        /* TODO: Add support for more key types */
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    return T_COSE_SUCCESS;
}

enum t_cose_err_t
t_cose_crypto_sign(int32_t                cose_algorithm_id,
                   struct t_cose_key      signing_key,
                   struct q_useful_buf_c  hash_to_sign,
                   struct q_useful_buf    signature_buffer,
                   struct q_useful_buf_c *signature) {
    TEE_Result res = TEE_ERROR_GENERIC;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_ObjectInfo info = { };
    uint32_t alg = 0;
    uint32_t curve = 0;

    if (!signing_key.k.key_obj)
        return T_COSE_ERR_EMPTY_KEY;

    res = TEE_GetObjectInfo1(signing_key.k.key_obj, &info);
    if (res != TEE_SUCCESS || info.objectType != TEE_TYPE_ECDSA_KEYPAIR)
        return T_COSE_ERR_WRONG_TYPE_OF_KEY;

    DMSG("info.keySize=%u", info.keySize);
    DMSG("info.maxKeySize=%u", info.maxKeySize);

    res = TEE_GetObjectValueAttribute(signing_key.k.key_obj,
                                      TEE_ATTR_ECC_CURVE, &curve, NULL);
    if (res != TEE_SUCCESS)
        return T_COSE_ERR_WRONG_TYPE_OF_KEY;

    switch (cose_algorithm_id) {
    case T_COSE_ALGORITHM_ES256: {
        if (curve != TEE_ECC_CURVE_NIST_P256)
            return T_COSE_ERR_WRONG_TYPE_OF_KEY;

        if (info.keySize != (TEE_SHA256_HASH_SIZE << 3))
            return T_COSE_ERR_WRONG_TYPE_OF_KEY;

        alg = TEE_ALG_ECDSA_P256;
        break;
    }
    default:
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    DMSG("meh 001");

    res = TEE_AllocateOperation(&op, alg, TEE_MODE_SIGN, info.keySize);
    if (res != TEE_SUCCESS)
        return T_COSE_ERR_FAIL;

    DMSG("meh 002");

    res = TEE_SetOperationKey(op, signing_key.k.key_obj);
    if (res != TEE_SUCCESS)
        goto out;

    DMSG("meh 002b");

    res = TEE_AsymmetricSignDigest(op, NULL, 0,
                                   hash_to_sign.ptr, hash_to_sign.len,
                                   signature_buffer.ptr,
                                   (uint32_t*)&signature_buffer.len);
    if (res != TEE_SUCCESS)
        goto out;

    DMSG("meh 003");

    *signature = (struct q_useful_buf_c) { signature_buffer.ptr,
                                           signature_buffer.len };

    DMSG("meh 004");

out:
    TEE_FreeOperation(op);

    return res == TEE_SUCCESS ? T_COSE_SUCCESS : T_COSE_ERR_FAIL;
}

enum t_cose_err_t
t_cose_crypto_verify(int32_t               cose_algorithm_id,
                     struct t_cose_key     verification_key,
                     struct q_useful_buf_c kid,
                     struct q_useful_buf_c hash_to_verify,
                     struct q_useful_buf_c signature) {
    TEE_Result res = TEE_ERROR_GENERIC;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_ObjectInfo info = { };
    uint32_t alg = 0;
    uint32_t curve = 0;

    /* XXX: how's kid supposed to be used? */
    (void)kid;

    if (!verification_key.k.key_obj)
        return T_COSE_ERR_EMPTY_KEY;

    res = TEE_GetObjectInfo1(verification_key.k.key_obj, &info);
    if (res != TEE_SUCCESS ||
        (info.objectType != TEE_TYPE_ECDSA_KEYPAIR &&
         info.objectType != TEE_TYPE_ECDSA_PUBLIC_KEY))
        return T_COSE_ERR_WRONG_TYPE_OF_KEY;

    DMSG("info.keySize=%u", info.keySize);
    DMSG("info.maxKeySize=%u", info.maxKeySize);

    res = TEE_GetObjectValueAttribute(verification_key.k.key_obj,
                                      TEE_ATTR_ECC_CURVE, &curve, NULL);
    if (res != TEE_SUCCESS)
        return T_COSE_ERR_WRONG_TYPE_OF_KEY;

    switch (cose_algorithm_id) {
    case T_COSE_ALGORITHM_ES256: {
        if (curve != TEE_ECC_CURVE_NIST_P256)
            return T_COSE_ERR_WRONG_TYPE_OF_KEY;

        if (info.keySize != (TEE_SHA256_HASH_SIZE << 3))
            return T_COSE_ERR_WRONG_TYPE_OF_KEY;

        alg = TEE_ALG_ECDSA_P256;
        break;
    }
    default:
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    DMSG("meh 001");

    res = TEE_AllocateOperation(&op, alg, TEE_MODE_VERIFY, info.keySize);
    if (res != TEE_SUCCESS)
        return T_COSE_ERR_FAIL;

    DMSG("meh 002");

    res = TEE_SetOperationKey(op, verification_key.k.key_obj);
    if (res != TEE_SUCCESS)
        goto out;

    DMSG("meh 002b");

    /*
     * NOTE: On signature verification failure, this function returns
     * TEE_ERROR_SIGNATURE_INVALID.
     */
    res = TEE_AsymmetricVerifyDigest(op, NULL, 0,
                                     hash_to_verify.ptr, hash_to_verify.len,
                                     signature.ptr, signature.len);
    if (res == TEE_ERROR_SIGNATURE_INVALID)
        DMSG("siganture verification failed... ding");
    if (res != TEE_SUCCESS)
        goto out;

    DMSG("meh 003");

out:
    TEE_FreeOperation(op);

    return res == TEE_SUCCESS ? T_COSE_SUCCESS : T_COSE_ERR_FAIL;
}

#ifndef t_cose_disable_eddsa

enum t_cose_err_t
t_cose_crypto_sign_eddsa(struct t_cose_key      signing_key,
                         struct q_useful_buf_c  tbs,
                         struct q_useful_buf    signature_buffer,
                         struct q_useful_buf_c *signature) {
    (void)signing_key;
    (void)tbs;
    (void)signature_buffer;
    (void)signature;

    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}

enum t_cose_err_t
t_cose_crypto_verify_eddsa(struct t_cose_key     verification_key,
                           struct q_useful_buf_c kid,
                           struct q_useful_buf_c tbs,
                           struct q_useful_buf_c signature) {
    (void)verification_key;
    (void)kid;
    (void)tbs;
    (void)signature;

    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}

#endif /* T_COSE_DISABLE_EDDSA */

enum t_cose_err_t
t_cose_crypto_hash_start(struct t_cose_crypto_hash *hash_ctx,
                         int32_t                    cose_hash_alg_id) {
    TEE_Result res = TEE_SUCCESS;
    uint32_t alg = 0;

    switch (cose_hash_alg_id) {
    case COSE_ALGORITHM_SHA_256:
        alg = TEE_ALG_SHA256;
        break;
    default:
        return T_COSE_ERR_UNSUPPORTED_HASH;
    }

    res = TEE_AllocateOperation(&hash_ctx->op, alg, TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS)
        return T_COSE_ERR_FAIL;

    return T_COSE_SUCCESS;
}

/* This assumes hash_ctx.op is properly initialized. */
void t_cose_crypto_hash_update(struct t_cose_crypto_hash *hash_ctx,
                               struct q_useful_buf_c      data_to_hash) {
    TEE_DigestUpdate(hash_ctx->op, data_to_hash.ptr, data_to_hash.len);
}

enum t_cose_err_t
t_cose_crypto_hash_finish(struct t_cose_crypto_hash *hash_ctx,
                          struct q_useful_buf        buffer_to_hold_result,
                          struct q_useful_buf_c     *hash_result) {
    TEE_Result res = TEE_SUCCESS;

    res = TEE_DigestDoFinal(hash_ctx->op, NULL, 0, buffer_to_hold_result.ptr,
                           (uint32_t *)&buffer_to_hold_result.len);
    if (res != TEE_SUCCESS)
        return T_COSE_ERR_HASH_GENERAL_FAIL;

    *hash_result = (struct q_useful_buf_c) { buffer_to_hold_result.ptr,
                                             buffer_to_hold_result.len };

    return T_COSE_SUCCESS;
}
