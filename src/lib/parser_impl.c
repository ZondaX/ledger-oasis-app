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

#include <zxmacros.h>
#include "parser_impl.h"
#include "parser_txdef.h"

parser_tx_t parser_tx_obj;

parser_error_t parser_init_context(parser_context_t *ctx,
                                   const uint8_t *buffer,
                                   uint16_t bufferSize) {
    ctx->offset = 0;

    if (bufferSize == 0 || buffer == NULL) {
        // Not available, use defaults
        ctx->buffer = NULL;
        ctx->bufferLen = 0;
        return parser_init_context_empty;
    }

    ctx->buffer = buffer;
    ctx->bufferLen = bufferSize;

    return parser_ok;
}

parser_error_t parser_init(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferSize) {
    parser_error_t err = parser_init_context(ctx, buffer, bufferSize);
    if (err != parser_ok)
        return err;

    return err;
}

const char *parser_getErrorDescription(parser_error_t err) {
    switch (err) {
        case parser_ok:
            return "No error";
        case parser_no_data:
            return "No more data";
        case parser_unexpected_type:
            return "Unexpected data type";
        case parser_unexpected_method:
            return "Unexpected method";
        case parser_unexpected_buffer_end:
            return "Unexpected buffer end";
        case parser_unexpected_value:
            return "Unexpected value";
        case parser_unexpected_number_items:
            return "Unexpected number of items";
        case parser_unexpected_data_at_end:
            return "Unexpected data at end";
        case parser_init_context_empty:
            return "Initialized empty context";
        case parser_unexpected_characters:
            return "Unexpected characters";
        case parser_unexpected_field:
            return "Unexpected field";
        case parser_value_out_of_range:
            return "Value out of range";
        case parser_cbor_unexpected:
            return "unexpected CBOR error";

        default:
            return "Unrecognized error code";
    }
}

// TODO: improve this and remap error + messages
#define CHECK_CBOR_ERR(err) if (err!=CborNoError) return parser_cbor_unexpected;
#define CHECK_PARSER_ERR(err) if (err!=parser_ok) return err;
#define CHECK_CBOR_TYPE(type, expected) if (type!=expected) return parser_unexpected_type;

#define CHECK_CBOR_MAP_LEN(map, expected_count) { \
    size_t numItems; CHECK_CBOR_ERR(cbor_value_get_map_length(map, &numItems)); \
    if (numItems != expected_count)  return parser_unexpected_number_items; }

#define CHECK_CBOR_MATCH_KEY(value, expected_key) { \
  CHECK_CBOR_TYPE(cbor_value_get_type(value), CborTextStringType); \
  if (!_matchKey(value, expected_key)) return parser_unexpected_field; \
}

__Z_INLINE parser_error_t _matchKey(CborValue *value, const char *expectedKey) {
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborTextStringType);
    bool result;
    cbor_value_text_string_equals(value, expectedKey, &result);
    return result;
}

__Z_INLINE parser_error_t _readPublicKey(CborValue *value, publickey_t *out) {
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborByteStringType);
    CborValue dummy;
    size_t len = sizeof(publickey_t);
    CHECK_CBOR_ERR(cbor_value_copy_byte_string(value, (uint8_t *) out, &len, &dummy));
    if (len != sizeof(publickey_t)) {
        return parser_unexpected_value;
    }
    return parser_ok;
}

#define sizeof_field(type, member) sizeof(((type *)0)->member)

__Z_INLINE parser_error_t _readQuantity(CborValue *value, quantity_t *out) {
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborByteStringType);
    CborValue dummy;
    MEMZERO(out, sizeof(quantity_t));
    out->len = sizeof_field(quantity_t, buffer);
    CHECK_CBOR_ERR(cbor_value_copy_byte_string(value, (uint8_t *) out->buffer, &out->len, &dummy));
    return parser_ok;
}

__Z_INLINE parser_error_t _readRate(CborValue *value, commissionRateStep_t *out) {
//      {
//        "rate": "0",
//        "start": 0
//      }
//  canonical cbor orders keys by length
// https://tools.ietf.org/html/rfc7049#section-3.9

    CborValue contents;
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborMapType);
    CHECK_CBOR_MAP_LEN(value, 2);
    CHECK_CBOR_ERR(cbor_value_enter_container(value, &contents));

    CHECK_CBOR_MATCH_KEY(&contents, "rate")
    CHECK_CBOR_ERR(cbor_value_advance(&contents));
    CHECK_CBOR_ERR(_readQuantity(&contents, &out->rate))
    CHECK_CBOR_ERR(cbor_value_advance(&contents));

    CHECK_CBOR_MATCH_KEY(&contents, "start");
    CHECK_CBOR_ERR(cbor_value_advance(&contents));
    CHECK_CBOR_TYPE(cbor_value_get_type(&contents), CborIntegerType);
    CHECK_CBOR_ERR(cbor_value_get_uint64(&contents, &out->start));
    CHECK_CBOR_ERR(cbor_value_advance(&contents));

    return parser_ok;
}

__Z_INLINE parser_error_t _readBound(CborValue *value, commissionRateBoundStep_t *out) {
//  {
//    "start": 0,
//    "rate_min": "0",
//    "rate_max": "0"
//  }
//  canonical cbor orders keys by length
// https://tools.ietf.org/html/rfc7049#section-3.9

    CborValue contents;
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborMapType);
    CHECK_CBOR_MAP_LEN(value, 3);
    CHECK_CBOR_ERR(cbor_value_enter_container(value, &contents));

    CHECK_CBOR_MATCH_KEY(&contents, "start");
    CHECK_CBOR_ERR(cbor_value_advance(&contents));
    CHECK_CBOR_TYPE(cbor_value_get_type(&contents), CborIntegerType);
    CHECK_CBOR_ERR(cbor_value_get_uint64(&contents, &out->start));
    CHECK_CBOR_ERR(cbor_value_advance(&contents));

    CHECK_CBOR_MATCH_KEY(&contents, "rate_max")
    CHECK_CBOR_ERR(cbor_value_advance(&contents));
    CHECK_CBOR_ERR(_readQuantity(&contents, &out->rate_max))
    CHECK_CBOR_ERR(cbor_value_advance(&contents));

    CHECK_CBOR_MATCH_KEY(&contents, "rate_min")
    CHECK_CBOR_ERR(cbor_value_advance(&contents));
    CHECK_CBOR_ERR(_readQuantity(&contents, &out->rate_min))
    CHECK_CBOR_ERR(cbor_value_advance(&contents));

    return parser_ok;
}

__Z_INLINE parser_error_t _readAmendment(parser_tx_t *v, CborValue *value) {
//  {
//    "rates": [
//     ...
//    ],
//    "bounds": [
//     ...
//    ]
//  }

    /// Enter container
    CborValue contents;
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborMapType);
    CHECK_CBOR_MAP_LEN(value, 2);
    CHECK_CBOR_ERR(cbor_value_enter_container(value, &contents));

    CHECK_CBOR_MATCH_KEY(&contents, "rates");
    CHECK_CBOR_ERR(cbor_value_advance(&contents));
    CHECK_CBOR_TYPE(cbor_value_get_type(&contents), CborArrayType);

    // Array of rates
    cbor_value_get_array_length(&contents, &v->oasis_tx.body.stakingAmendCommissionSchedule.rates_length);

    CHECK_CBOR_ERR(cbor_value_advance(&contents));

    CHECK_CBOR_MATCH_KEY(&contents, "bounds");
    CHECK_CBOR_ERR(cbor_value_advance(&contents));
    CHECK_CBOR_TYPE(cbor_value_get_type(&contents), CborArrayType);

    // Array of bounds
    cbor_value_get_array_length(&contents, &v->oasis_tx.body.stakingAmendCommissionSchedule.bounds_length);

    return parser_ok;
}

__Z_INLINE parser_error_t _readFee(parser_tx_t *v, CborValue *value) {
//    "fee": {
//        "gas": 0,
//        "amount": ""
//    },
    CHECK_CBOR_MATCH_KEY(value, "fee");
    CHECK_CBOR_ERR(cbor_value_advance(value));

    /// Enter container
    CborValue contents;
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborMapType);
    CHECK_CBOR_MAP_LEN(value, 2);
    CHECK_CBOR_ERR(cbor_value_enter_container(value, &contents));

    CHECK_CBOR_MATCH_KEY(&contents, "gas")
    CHECK_CBOR_ERR(cbor_value_advance(&contents));
    CHECK_CBOR_TYPE(cbor_value_get_type(&contents), CborIntegerType);
    CHECK_CBOR_ERR(cbor_value_get_uint64(&contents, &v->oasis_tx.fee_gas));
    CHECK_CBOR_ERR(cbor_value_advance(&contents));

    CHECK_CBOR_MATCH_KEY(&contents, "amount");
    CHECK_CBOR_ERR(cbor_value_advance(&contents));
    CHECK_PARSER_ERR(_readQuantity(&contents, &v->oasis_tx.fee_amount));
    CHECK_CBOR_ERR(cbor_value_advance(&contents));

    // Close container
    CHECK_CBOR_ERR(cbor_value_leave_container(value, &contents));

    return parser_ok;
}

__Z_INLINE parser_error_t _skipBody(parser_tx_t *v, CborValue *value) {
    CHECK_CBOR_MATCH_KEY(value, "body");
    CHECK_CBOR_ERR(cbor_value_advance(value));
    CHECK_CBOR_ERR(cbor_value_advance(value));
    return parser_ok;
}

__Z_INLINE parser_error_t _readBody(parser_tx_t *v, CborValue *value) {
    // Reference: https://github.com/oasislabs/oasis-core/blob/kostko/feature/docs-staking/docs/consensus/staking.md#test-vectors

    CHECK_CBOR_MATCH_KEY(value, "body");
    CHECK_CBOR_ERR(cbor_value_advance(value));

    CborValue contents;
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborMapType);

    switch (v->oasis_tx.method) {
        case stakingTransfer: {
            CHECK_CBOR_MAP_LEN(value, 2);
            CHECK_CBOR_ERR(cbor_value_enter_container(value, &contents));

            CHECK_CBOR_MATCH_KEY(&contents, "xfer_to");
            CHECK_CBOR_ERR(cbor_value_advance(&contents));
            CHECK_PARSER_ERR(_readPublicKey(&contents, &v->oasis_tx.body.stakingTransfer.xfer_to));
            CHECK_CBOR_ERR(cbor_value_advance(&contents));

            CHECK_CBOR_MATCH_KEY(&contents, "xfer_tokens");
            CHECK_CBOR_ERR(cbor_value_advance(&contents));
            CHECK_PARSER_ERR(_readQuantity(&contents, &v->oasis_tx.body.stakingTransfer.xfer_tokens));
            CHECK_CBOR_ERR(cbor_value_advance(&contents));
            break;
        }
        case stakingBurn: {
            CHECK_CBOR_MAP_LEN(value, 1);
            CHECK_CBOR_ERR(cbor_value_enter_container(value, &contents));

            CHECK_CBOR_MATCH_KEY(&contents, "burn_tokens");
            CHECK_CBOR_ERR(cbor_value_advance(&contents));
            CHECK_PARSER_ERR(_readQuantity(&contents, &v->oasis_tx.body.stakingBurn.burn_tokens));
            CHECK_CBOR_ERR(cbor_value_advance(&contents));
            break;
        }
        case stakingAddEscrow: {
            CHECK_CBOR_MAP_LEN(value, 2);
            CHECK_CBOR_ERR(cbor_value_enter_container(value, &contents));

            CHECK_CBOR_MATCH_KEY(&contents, "escrow_tokens");
            CHECK_CBOR_ERR(cbor_value_advance(&contents));
            CHECK_PARSER_ERR(_readQuantity(&contents, &v->oasis_tx.body.stakingAddEscrow.escrow_tokens));
            CHECK_CBOR_ERR(cbor_value_advance(&contents));

            CHECK_CBOR_MATCH_KEY(&contents, "escrow_account");
            CHECK_CBOR_ERR(cbor_value_advance(&contents));
            CHECK_PARSER_ERR(_readPublicKey(&contents, &v->oasis_tx.body.stakingAddEscrow.escrow_account));
            CHECK_CBOR_ERR(cbor_value_advance(&contents));
            break;
        }
        case stakingReclaimEscrow: {
            CHECK_CBOR_MAP_LEN(value, 2);
            CHECK_CBOR_ERR(cbor_value_enter_container(value, &contents));

            CHECK_CBOR_MATCH_KEY(&contents, "escrow_account");
            CHECK_CBOR_ERR(cbor_value_advance(&contents));
            CHECK_PARSER_ERR(_readPublicKey(&contents, &v->oasis_tx.body.stakingReclaimEscrow.escrow_account));
            CHECK_CBOR_ERR(cbor_value_advance(&contents));

            CHECK_CBOR_MATCH_KEY(&contents, "reclaim_shares");
            CHECK_CBOR_ERR(cbor_value_advance(&contents));
            CHECK_PARSER_ERR(_readQuantity(&contents, &v->oasis_tx.body.stakingReclaimEscrow.reclaim_shares));
            CHECK_CBOR_ERR(cbor_value_advance(&contents));
            break;
        }
        case stakingAmendCommissionSchedule: {
            CHECK_CBOR_MAP_LEN(value, 1);
            CHECK_CBOR_ERR(cbor_value_enter_container(value, &contents));

            CHECK_CBOR_MATCH_KEY(&contents, "amendment");
            CHECK_CBOR_ERR(cbor_value_advance(&contents));
            // ONLY READ LENGTH ! THEN GET ON ITEM ON DEMAND
            CHECK_PARSER_ERR(_readAmendment(v, &contents))
            CHECK_CBOR_ERR(cbor_value_advance(&contents));

            break;
        }
        case unknownMethod:
        default:
            return parser_unexpected_method;
    }

    // Close container
    CHECK_CBOR_ERR(cbor_value_leave_container(value, &contents));

    return parser_ok;
}

__Z_INLINE parser_error_t _readNonce(parser_tx_t *v, CborValue *value) {
    CHECK_CBOR_MATCH_KEY(value, "nonce");
    CHECK_CBOR_ERR(cbor_value_advance(value));

    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborIntegerType);
    CHECK_CBOR_ERR(cbor_value_get_uint64(value, &v->oasis_tx.nonce));
    CHECK_CBOR_ERR(cbor_value_advance(value));
    return parser_ok;
}

__Z_INLINE parser_error_t _readMethod(parser_tx_t *v, CborValue *value) {
    CHECK_CBOR_MATCH_KEY(value, "method");
    CHECK_CBOR_ERR(cbor_value_advance(value));

    v->oasis_tx.method = unknownMethod;
    if (_matchKey(value, "staking.Transfer"))
        v->oasis_tx.method = stakingTransfer;
    if (_matchKey(value, "staking.Burn"))
        v->oasis_tx.method = stakingBurn;
    if (_matchKey(value, "staking.AddEscrow"))
        v->oasis_tx.method = stakingAddEscrow;
    if (_matchKey(value, "staking.ReclaimEscrow"))
        v->oasis_tx.method = stakingReclaimEscrow;
    if (_matchKey(value, "staking.AmendCommissionSchedule"))
        v->oasis_tx.method = stakingAmendCommissionSchedule;
    if (v->oasis_tx.method == unknownMethod)
        return parser_unexpected_method;

    CHECK_CBOR_ERR(cbor_value_advance(value));
    return parser_ok;
}

parser_error_t _readTx(parser_context_t *c, parser_tx_t *v) {
    CborValue it;
    CHECK_CBOR_ERR(cbor_parser_init(c->buffer,
                                    c->bufferLen,
                                    c->offset,
                                    &v->parser,
                                    &it));

    if (cbor_value_at_end(&it)) {
        return parser_unexpected_buffer_end;
    }

    MEMZERO(&v->oasis_tx, sizeof(oasis_tx_t));

    CHECK_CBOR_TYPE(cbor_value_get_type(&it), CborMapType);
    CHECK_CBOR_MAP_LEN(&it, 4);

    /// Enter container
    CborValue contents;
    CHECK_CBOR_ERR(cbor_value_enter_container(&it, &contents));

    /// Retrieve expected fields (this is canonical cbor, so order it deterministic)
    CHECK_PARSER_ERR(_readFee(v, &contents));

    CborValue bodyField = contents; // Keep a copy and skip
    CHECK_PARSER_ERR(_skipBody(v, &contents));
    CHECK_PARSER_ERR(_readNonce(v, &contents));
    CHECK_PARSER_ERR(_readMethod(v, &contents));

    CHECK_PARSER_ERR(_readBody(v, &bodyField));

    // Close container
    CHECK_CBOR_ERR(cbor_value_leave_container(&it, &contents));

    if (it.ptr != c->buffer + c->bufferLen) {
        // End of buffer does not match end of parsed data
        return parser_unexpected_data_at_end;
    }

    return parser_ok;
}

parser_error_t _validateTx(parser_context_t *c, parser_tx_t *v) {
    // TODO: Add any additional sensible validation here
    return parser_ok;
}

uint8_t _getNumItems(parser_context_t *c, parser_tx_t *v) {
    // typical tx: Type, Fee, Gas, + Body
    uint8_t itemCount = 3;

    switch (v->oasis_tx.method) {
        case stakingTransfer:
            itemCount += 2;
            break;
        case stakingBurn:
            itemCount += 1;
            break;
        case stakingAddEscrow:
            itemCount += 2;
            break;
        case stakingReclaimEscrow:
            itemCount += 2;
            break;
        case stakingAmendCommissionSchedule:
            // Each rate contains 2 items (start & rate)
            itemCount += v->oasis_tx.body.stakingAmendCommissionSchedule.rates_length * 2;
            // Each bound contains 3 items (start, rate_max & rate_min)
            itemCount += v->oasis_tx.body.stakingAmendCommissionSchedule.bounds_length * 3;
            break;
        case unknownMethod:
        default:
            break;
    }

    return itemCount;
}

__Z_INLINE parser_error_t _getAmendmentContainer(CborValue *value, CborValue *amendmentContainer) {
    if (cbor_value_at_end(value)) {
        return parser_unexpected_buffer_end;
    }


    if (!cbor_value_is_map(value)) {
        return parser_unexpected_type;
    }

    CborValue bodyContainer;
    CHECK_CBOR_ERR(cbor_value_map_find_value(value, "body", &bodyContainer));

    if (!cbor_value_is_map(&bodyContainer)) {
        return parser_unexpected_type;
    }

    CHECK_CBOR_ERR(cbor_value_map_find_value(&bodyContainer, "amendment", amendmentContainer));

    if (!cbor_value_is_map(amendmentContainer)) {
        return parser_unexpected_type;
    }

    return parser_ok;
}

__Z_INLINE parser_error_t _getRatesContainer(CborValue *value, CborValue *ratesContainer) {

    CborValue amendmentContainer;
    CHECK_CBOR_ERR(_getAmendmentContainer(value, &amendmentContainer));

    CborValue container;
    CHECK_CBOR_ERR(cbor_value_map_find_value(&amendmentContainer, "rates", &container));

    if (!cbor_value_is_array(&container)) {
        return parser_unexpected_type;
    }

    CHECK_CBOR_ERR(cbor_value_enter_container(&container, ratesContainer));

    return parser_ok;
}

__Z_INLINE parser_error_t _getBoundsContainer(CborValue *value, CborValue *boundsContainer) {

    CborValue amendmentContainer;
    CHECK_CBOR_ERR(_getAmendmentContainer(value, &amendmentContainer));

    CborValue container;
    CHECK_CBOR_ERR(cbor_value_map_find_value(&amendmentContainer, "bounds", &container));

    if (!cbor_value_is_array(&container)) {
        return parser_unexpected_type;
    }

    CHECK_CBOR_ERR(cbor_value_enter_container(&container, boundsContainer));

    return parser_ok;
}

parser_error_t _getCommissionRateStepAtIndex(parser_context_t *c, parser_tx_t *v, uint8_t index) {
    CborValue it;
    CHECK_CBOR_ERR(cbor_parser_init(c->buffer,
                                    c->bufferLen,
                                    c->offset,
                                    &v->parser,
                                    &it));

    // We should have already initiated v but should we verify ?

    CborValue ratesContainer;
    CHECK_CBOR_ERR(_getRatesContainer(&it, &ratesContainer));

    for (int i = 0; i < index; i++) {
      CHECK_CBOR_ERR(cbor_value_advance(&ratesContainer));
    }

    CHECK_CBOR_ERR(_readRate(&ratesContainer, &v->oasis_tx.body.stakingAmendCommissionSchedule.rate));

    return parser_ok;

}

parser_error_t _getCommissionBoundStepAtIndex(parser_context_t *c, parser_tx_t *v, uint8_t index) {
    CborValue it;
    CHECK_CBOR_ERR(cbor_parser_init(c->buffer,
                                    c->bufferLen,
                                    c->offset,
                                    &v->parser,
                                    &it));

    if (cbor_value_at_end(&it)) {
        return parser_unexpected_buffer_end;
    }

    CborValue boundsContainer;
    CHECK_CBOR_ERR(_getBoundsContainer(&it, &boundsContainer));

    for (int i = 0; i < index; i++) {
      CHECK_CBOR_ERR(cbor_value_advance(&boundsContainer));
    }

    CHECK_CBOR_ERR(_readBound(&boundsContainer, &v->oasis_tx.body.stakingAmendCommissionSchedule.bound));

    return parser_ok;

}
