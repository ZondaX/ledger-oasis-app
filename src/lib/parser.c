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

#include <stdio.h>
#include <zxmacros.h>
#include <bech32.h>
#include "lib/parser_impl.h"
#include "bignum.h"
#include "view_internal.h"
#include "parser.h"
#include "parser_txdef.h"
#include "coin.h"

parser_error_t parser_parse(parser_context_t *ctx,
                            const uint8_t *data,
                            uint16_t dataLen) {
    parser_init(ctx, data, dataLen);
    return _readTx(ctx, &parser_tx_obj);
}

parser_error_t parser_validate(parser_context_t *ctx) {
    parser_error_t err = _validateTx(ctx, &parser_tx_obj);
    if (err != parser_ok)
        return err;

    // TODO: Iterate through all items to check that all can be shown and are valid
    return parser_ok;
}

uint8_t parser_getNumItems(parser_context_t *ctx) {
    return _getNumItems(ctx, &parser_tx_obj);
}

__Z_INLINE parser_error_t parser_getType(parser_context_t *ctx, char *outVal, uint16_t outValLen) {
    switch (parser_tx_obj.oasis_tx.method) {
        case stakingTransfer:
            snprintf(outVal, outValLen, "Transfer");
            return parser_ok;
        case stakingBurn:
            snprintf(outVal, outValLen, "Burn");
            return parser_ok;
        case stakingAddEscrow:
            snprintf(outVal, outValLen, "Add escrow");
            return parser_ok;
        case stakingReclaimEscrow:
            snprintf(outVal, outValLen, "Reclaim escrow");
            return parser_ok;
        case stakingAmendComissionSchedule:
            snprintf(outVal, outValLen, "Amend comission schedule");
            return parser_ok;
        case unknownMethod:
        default:
            break;
    }
    return parser_unexpected_method;
}

__Z_INLINE parser_error_t parser_printQuantity(quantity_t *q,
                                               char *outVal, uint16_t outValLen,
                                               uint8_t pageIdx, uint8_t *pageCount) {
    uint8_t bcd_buffer[128];
    char bignum_buffer[256];

    MEMZERO(bcd_buffer, sizeof(bcd_buffer));
    MEMZERO(bignum_buffer, sizeof(bignum_buffer));

    bignumBigEndian_to_bcd(bcd_buffer, sizeof(bcd_buffer), q->buffer, q->len);

    if (!bignumBigEndian_bcdprint(bignum_buffer,
                                  sizeof(bignum_buffer),
                                  bcd_buffer, sizeof(bcd_buffer)
    )) {
        return parser_unexpected_value;
    }

    pageString(outVal, outValLen, bignum_buffer, pageIdx, pageCount);
    return parser_ok;
}

__Z_INLINE parser_error_t parser_printPublicKey(publickey_t *pk,
                                                char *outVal, uint16_t outValLen,
                                                uint8_t pageIdx, uint8_t *pageCount) {
    char outBuffer[128];
    MEMZERO(outBuffer, sizeof(outBuffer));

    bech32EncodeFromBytes(outBuffer, COIN_HRP, (uint8_t *) pk, sizeof(publickey_t));
    pageString(outVal, outValLen, outBuffer, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t parser_getItem(parser_context_t *ctx,
                              int8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, " ");

    if (displayIdx < 0 || displayIdx > parser_getNumItems(ctx)) {
        return parser_no_data;
    }

    // Fixed items
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Type");
            return parser_getType(ctx, outVal, outValLen);
        case 1:
            snprintf(outKey, outKeyLen, "Fee Amount");
            return parser_printQuantity(&parser_tx_obj.oasis_tx.fee_amount, outVal, outValLen, pageIdx, pageCount);
        case 2:
            snprintf(outKey, outKeyLen, "Fee Gas");
            uint64_to_str(outVal, outValLen, parser_tx_obj.oasis_tx.fee_gas);
            return parser_ok;
    }

    // Variable items
    switch (parser_tx_obj.oasis_tx.method) {
        case stakingTransfer:
            switch (displayIdx) {
                case 3: {
                    snprintf(outKey, outKeyLen, "To");
                    return parser_printPublicKey(&parser_tx_obj.oasis_tx.body.stakingTransfer.xfer_to,
                                                 outVal, outValLen, pageIdx, pageCount);
                }
                case 4: {
                    snprintf(outKey, outKeyLen, "Tokens");
                    return parser_printQuantity(&parser_tx_obj.oasis_tx.body.stakingTransfer.xfer_tokens,
                                                outVal, outValLen, pageIdx, pageCount);
                }
                default:
                    return parser_no_data;
            }
            break;
        case stakingBurn:
            switch (displayIdx) {
                case 3: {
                    snprintf(outKey, outKeyLen, "Tokens");
                    return parser_printQuantity(&parser_tx_obj.oasis_tx.body.stakingBurn.burn_tokens,
                                                outVal, outValLen, pageIdx, pageCount);
                }
                default:
                    return parser_no_data;
            }
            break;
        case stakingAddEscrow:
            switch (displayIdx) {
                case 3: {
                    snprintf(outKey, outKeyLen, "Escrow");
                    return parser_printPublicKey(&parser_tx_obj.oasis_tx.body.stakingAddEscrow.escrow_account,
                                                 outVal, outValLen, pageIdx, pageCount);
                }
                case 4: {
                    snprintf(outKey, outKeyLen, "Tokens");
                    return parser_printQuantity(&parser_tx_obj.oasis_tx.body.stakingAddEscrow.escrow_tokens,
                                                outVal, outValLen, pageIdx, pageCount);
                }
                default:
                    return parser_no_data;
            }
            break;
        case stakingReclaimEscrow:
            switch (displayIdx) {
                case 3: {
                    snprintf(outKey, outKeyLen, "Escrow");
                    return parser_printPublicKey(&parser_tx_obj.oasis_tx.body.stakingReclaimEscrow.escrow_account,
                                                 outVal, outValLen, pageIdx, pageCount);
                }
                case 4: {
                    snprintf(outKey, outKeyLen, "Tokens");
                    return parser_printQuantity(&parser_tx_obj.oasis_tx.body.stakingReclaimEscrow.reclaim_shares,
                                                outVal, outValLen, pageIdx, pageCount);
                }
                default:
                    return parser_no_data;
            }
            break;
        case stakingAmendComissionSchedule:
            // FIXME: Complete
            break;
        case unknownMethod:
        default:
            break;
    }

    return parser_no_data;
}
