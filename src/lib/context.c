/*******************************************************************************
*   (c) 2019 ZondaX GmbH
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

#include "context.h"
#include <zxmacros.h>
#include "coin.h"
#include "parser_common.h"

// +1 to ensure zero-termination
uint8_t crypto_context[MAX_CONTEXT_SIZE + 1];
uint8_t crypto_context_length = 0;

const char context_prefix_tx[] = "oasis-core/consensus: tx for chain ";

parser_error_t crypto_set_context(const uint8_t *new_context, uint8_t new_context_length) {
    MEMZERO(crypto_context, sizeof(crypto_context));
    crypto_context_length = 0;

    if (new_context_length > MAX_CONTEXT_SIZE) {
        return parser_context_unexpected_size;
    }

    // Check all bytes in context as ASCII within 32..127
    for (uint8_t i = 0; i < new_context_length; i++) {
        if (new_context[i] < 32 || new_context[i] > 127) {
            return parser_context_invalid_chars;
        }
    }

    if (new_context_length > 0) {
        MEMCPY(crypto_context, new_context, new_context_length);
        crypto_context_length = new_context_length;
    }

    return parser_ok;
}

const uint8_t *crypto_get_context() {
    return crypto_context;
}

uint8_t crypto_get_context_length() {
    return crypto_context_length;
}

const char *crypto_get_expected_prefix(oasis_methods_e method) {
    switch (method) {
        case stakingTransfer:
        case stakingBurn:
        case stakingAddEscrow:
        case stakingReclaimEscrow:
        case stakingAmendCommissionSchedule:
            return context_prefix_tx;
        case unknownMethod:
        default:
            // This should fail
            break;
    }
    return NULL;
}

parser_error_t  crypto_validate_context(oasis_methods_e method) {
    const char *expectedPrefix = crypto_get_expected_prefix(method);
    if (expectedPrefix == NULL)
        return parser_context_unknown_prefix;

    // confirm that the context starts with the correct prefix
    if (strncmp(expectedPrefix, (char *) crypto_context, strlen(expectedPrefix)) != 0) {
        return parser_context_mismatch;
    }

    return parser_ok;
}

const uint8_t *crypto_get_context_suffix(oasis_methods_e method) {
    if (crypto_validate_context(method) != parser_ok) {
        // Return everything when not valid
        return crypto_context;
    }

    const char *expectedPrefix = crypto_get_expected_prefix(method);
    return crypto_context + strlen(expectedPrefix);
}
