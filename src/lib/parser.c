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

#if defined(TARGET_NANOX)
// For some reason NanoX requires this function
void __assert_fail(const char * assertion, const char * file, unsigned int line, const char * function){
    // FIXME: improve behaviour
    while(1) {};
}
#endif

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

    uint8_t numItems = parser_getNumItems(ctx);

    char tmpKey[40];
    char tmpVal[40];

    for (uint8_t idx = 0; idx < numItems; idx++) {
        uint8_t pageCount;
        err = parser_getItem(ctx, idx, tmpKey, sizeof(tmpKey), tmpVal, sizeof(tmpVal), 0, &pageCount);
        if (err != parser_ok) {
            return err;
        }
    }

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
        case stakingAmendCommissionSchedule:
            snprintf(outVal, outValLen, "Amend commission schedule");
            return parser_ok;
        case unknownMethod:
        default:
            break;
    }
    return parser_unexpected_method;
}

#define LESS_THAN_64_DIGIT(num_digit) if (num_digit > 64) return parser_value_out_of_range;

__Z_INLINE bool format_quantity(quantity_t *q,
                                uint8_t *bcd, uint16_t bcdSize,
                                char *bignum, uint16_t bignumSize) {

    bignumBigEndian_to_bcd(bcd, bcdSize, q->buffer, q->len);
    if (!bignumBigEndian_bcdprint(bignum, bignumSize, bcd, bcdSize)) {
      return false;
    }
    return true;
}

__Z_INLINE parser_error_t parser_printQuantity(quantity_t *q,
                                               char *outVal, uint16_t outValLen,
                                               uint8_t pageIdx, uint8_t *pageCount) {
    // upperbound 2**(64*8)
    // results in 155 decimal digits => max 78 bcd bytes

    // Too many digits, we cannot format this
    LESS_THAN_64_DIGIT(q->len);

    char bignum[160];
    union {
        // overlapping arrays to avoid excessive stack usage. Do not use at the same time
        uint8_t bcd[80];
        char output[160];
    } overlapped;

    MEMZERO(overlapped.bcd, sizeof(overlapped.bcd));
    MEMZERO(bignum, sizeof(bignum));

    if (!format_quantity(q, overlapped.bcd, sizeof(overlapped.bcd), bignum, sizeof(bignum))) {
        return parser_unexpected_value;
    }

    fpstr_to_str(overlapped.output, bignum, COIN_AMOUNT_DECIMAL_PLACES);
    pageString(outVal, outValLen, overlapped.output, pageIdx, pageCount);
    return parser_ok;
}

__Z_INLINE parser_error_t parser_printRate(quantity_t *q,
                                               char *outVal, uint16_t outValLen,
                                               uint8_t pageIdx, uint8_t *pageCount) {

    // Too many digits, we cannot format this
    LESS_THAN_64_DIGIT(q->len);

    char bignum[160];
    union {
        // overlapping arrays to avoid excessive stack usage. Do not use at the same time
        uint8_t bcd[80];
        char output[160];
    } overlapped;

    MEMZERO(overlapped.bcd, sizeof(overlapped.bcd));
    MEMZERO(bignum, sizeof(bignum));

    if (!format_quantity(q, overlapped.bcd, sizeof(overlapped.bcd), bignum, sizeof(bignum))) {
        return parser_unexpected_value;
    }

    fpstr_to_str(overlapped.output, bignum, COIN_RATE_DECIMAL_PLACES - 2);
    overlapped.output[strlen(overlapped.output)] = '%';
    pageString(outVal, outValLen, overlapped.output, pageIdx, pageCount);

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
        case stakingAmendCommissionSchedule:
            if ((displayIdx - 3) / 2 < parser_tx_obj.oasis_tx.body.stakingAmendCommissionSchedule.rates_length) {
              int8_t index = (displayIdx - 3) / 2;

              switch ((displayIdx - 3) % 2) {
                case 0: {
                  snprintf(outKey, outKeyLen, "Rates : [%i] start", index);
                  uint64_to_str(outVal, outValLen, parser_tx_obj.oasis_tx.body.stakingAmendCommissionSchedule.rates[index].start);
                  return parser_ok;
                }
                case 1: {
                  snprintf(outKey, outKeyLen, "Rates : [%i] rate", index);
                  return parser_printRate(&parser_tx_obj.oasis_tx.body.stakingAmendCommissionSchedule.rates[index].rate,
                                              outVal, outValLen, pageIdx, pageCount);
                }
              }
            } else {
              int8_t index = (displayIdx - 3 - parser_tx_obj.oasis_tx.body.stakingAmendCommissionSchedule.rates_length*2) / 3;

              switch ((displayIdx - 3 - parser_tx_obj.oasis_tx.body.stakingAmendCommissionSchedule.rates_length*2) % 3) {
                case 0: {
                  snprintf(outKey, outKeyLen, "Bounds : [%i] start", index);
                  uint64_to_str(outVal, outValLen, parser_tx_obj.oasis_tx.body.stakingAmendCommissionSchedule.bounds[index].start);
                  return parser_ok;
                }
                case 1: {
                  snprintf(outKey, outKeyLen, "Bounds : [%i] min", index);
                  return parser_printRate(&parser_tx_obj.oasis_tx.body.stakingAmendCommissionSchedule.bounds[index].rate_min,
                                              outVal, outValLen, pageIdx, pageCount);
                }
                case 2: {
                  snprintf(outKey, outKeyLen, "Bounds : [%i] max", index);
                  return parser_printRate(&parser_tx_obj.oasis_tx.body.stakingAmendCommissionSchedule.bounds[index].rate_max,
                                              outVal, outValLen, pageIdx, pageCount);
                }
              }
            }

            break;
        case unknownMethod:
        default:
            break;
    }

    return parser_no_data;
}
