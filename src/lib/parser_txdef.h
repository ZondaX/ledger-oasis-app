/*******************************************************************************
*  (c) 2019 ZondaX GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
#pragma once

#define CBOR_PARSER_MAX_RECURSIONS 4
#include <cbor.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

typedef enum {
    unknownMethod,
    stakingTransfer,
    stakingBurn,
    stakingAddEscrow,
    stakingReclaimEscrow,
    stakingAmendComissionSchedule
} oasis_methods_e;

typedef uint8_t publickey_t[32];
typedef uint8_t quantity_t[64];

typedef struct {
    uint64_t fee_gas;
    const uint8_t *fee_amount;
    size_t fee_amount_len;

    // Union type will depend on method
    union {
        struct {
            publickey_t xfer_to;
            quantity_t xfer_tokens;
        } stakingTransfer;

        struct {
            quantity_t burn_tokens;
        } stakingBurn;

        struct {
            publickey_t escrow_account;
            quantity_t escrow_tokens;
        } stakingAddEscrow;

        struct {
            publickey_t escrow_account;
            quantity_t reclaim_shares;
        } stakingReclaimEscrow;

        struct {
            const char *reclaim_shares;
        } stakingAmendCommissionSchedule;
    } body;

    uint64_t nonce;
    oasis_methods_e method;
} oasis_tx_t;

typedef struct {
    oasis_tx_t oasis_tx;
    CborParser parser;
} parser_tx_t;

#ifdef __cplusplus
}
#endif
