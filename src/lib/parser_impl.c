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
        // General errors
        case parser_ok:
            return "No error";
        case parser_no_data:
            return "No more data";
        case parser_init_context_empty:
            return "Initialized empty context";
        case parser_display_idx_out_of_range:
            return "display_idx_out_of_range";
        case parser_display_page_out_of_range:
            return "display_page_out_of_range";

        // Coin specific
        case parser_cbor_unexpected:
            return "unexpected CBOR error";
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
        case parser_unexpected_characters:
            return "Unexpected characters";
        case parser_unexpected_field:
            return "Unexpected field";
        case parser_value_out_of_range:
            return "Value out of range";
        /////////// Context specific
        case parser_context_mismatch:
            return "context prefix is invalid";
        case parser_context_unexpected_size:
            return "context unexpected size";
        case parser_context_invalid_chars:
            return "context invalid chars";
         // Required fields error
        case parser_required_nonce:
            return "Required field nonce";
        case parser_required_method:
            return "Required field method";
        default:
            return "Unrecognized error code";
    }
}

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
    cbor_value_get_array_length(&contents, &v->oasis.tx.body.stakingAmendCommissionSchedule.rates_length);

    CHECK_CBOR_ERR(cbor_value_advance(&contents));

    CHECK_CBOR_MATCH_KEY(&contents, "bounds");
    CHECK_CBOR_ERR(cbor_value_advance(&contents));
    CHECK_CBOR_TYPE(cbor_value_get_type(&contents), CborArrayType);

    // Array of bounds
    cbor_value_get_array_length(&contents, &v->oasis.tx.body.stakingAmendCommissionSchedule.bounds_length);

    return parser_ok;
}

__Z_INLINE parser_error_t _readFee(parser_tx_t *v, CborValue *value) {
//    "fee": {
//        "gas": 0,
//        "amount": ""
//    },

    /// Enter container
    CborValue contents;
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborMapType);
    CHECK_CBOR_MAP_LEN(value, 2);
    CHECK_CBOR_ERR(cbor_value_enter_container(value, &contents));

    CHECK_CBOR_MATCH_KEY(&contents, "gas")
    CHECK_CBOR_ERR(cbor_value_advance(&contents));
    CHECK_CBOR_TYPE(cbor_value_get_type(&contents), CborIntegerType);
    CHECK_CBOR_ERR(cbor_value_get_uint64(&contents, &v->oasis.tx.fee_gas));
    CHECK_CBOR_ERR(cbor_value_advance(&contents));

    CHECK_CBOR_MATCH_KEY(&contents, "amount");
    CHECK_CBOR_ERR(cbor_value_advance(&contents));
    CHECK_PARSER_ERR(_readQuantity(&contents, &v->oasis.tx.fee_amount));
    CHECK_CBOR_ERR(cbor_value_advance(&contents));

    // Close container
    CHECK_CBOR_ERR(cbor_value_leave_container(value, &contents));

    v->oasis.tx.has_fee = true;

    return parser_ok;
}

__Z_INLINE parser_error_t _readBody(parser_tx_t *v, CborValue *value) {
    // Reference: https://github.com/oasislabs/oasis-core/blob/kostko/feature/docs-staking/docs/consensus/staking.md#test-vectors

    CborValue contents;
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborMapType);

    switch (v->oasis.tx.method) {
        case stakingTransfer: {
            CHECK_CBOR_MAP_LEN(value, 2);
            CHECK_CBOR_ERR(cbor_value_enter_container(value, &contents));

            CHECK_CBOR_MATCH_KEY(&contents, "xfer_to");
            CHECK_CBOR_ERR(cbor_value_advance(&contents));
            CHECK_PARSER_ERR(_readPublicKey(&contents, &v->oasis.tx.body.stakingTransfer.xfer_to));
            CHECK_CBOR_ERR(cbor_value_advance(&contents));

            CHECK_CBOR_MATCH_KEY(&contents, "xfer_tokens");
            CHECK_CBOR_ERR(cbor_value_advance(&contents));
            CHECK_PARSER_ERR(_readQuantity(&contents, &v->oasis.tx.body.stakingTransfer.xfer_tokens));
            CHECK_CBOR_ERR(cbor_value_advance(&contents));
            break;
        }
        case stakingBurn: {
            CHECK_CBOR_MAP_LEN(value, 1);
            CHECK_CBOR_ERR(cbor_value_enter_container(value, &contents));

            CHECK_CBOR_MATCH_KEY(&contents, "burn_tokens");
            CHECK_CBOR_ERR(cbor_value_advance(&contents));
            CHECK_PARSER_ERR(_readQuantity(&contents, &v->oasis.tx.body.stakingBurn.burn_tokens));
            CHECK_CBOR_ERR(cbor_value_advance(&contents));
            break;
        }
        case stakingAddEscrow: {
            CHECK_CBOR_MAP_LEN(value, 2);
            CHECK_CBOR_ERR(cbor_value_enter_container(value, &contents));

            CHECK_CBOR_MATCH_KEY(&contents, "escrow_tokens");
            CHECK_CBOR_ERR(cbor_value_advance(&contents));
            CHECK_PARSER_ERR(_readQuantity(&contents, &v->oasis.tx.body.stakingAddEscrow.escrow_tokens));
            CHECK_CBOR_ERR(cbor_value_advance(&contents));

            CHECK_CBOR_MATCH_KEY(&contents, "escrow_account");
            CHECK_CBOR_ERR(cbor_value_advance(&contents));
            CHECK_PARSER_ERR(_readPublicKey(&contents, &v->oasis.tx.body.stakingAddEscrow.escrow_account));
            CHECK_CBOR_ERR(cbor_value_advance(&contents));
            break;
        }
        case stakingReclaimEscrow: {
            CHECK_CBOR_MAP_LEN(value, 2);
            CHECK_CBOR_ERR(cbor_value_enter_container(value, &contents));

            CHECK_CBOR_MATCH_KEY(&contents, "escrow_account");
            CHECK_CBOR_ERR(cbor_value_advance(&contents));
            CHECK_PARSER_ERR(_readPublicKey(&contents, &v->oasis.tx.body.stakingReclaimEscrow.escrow_account));
            CHECK_CBOR_ERR(cbor_value_advance(&contents));

            CHECK_CBOR_MATCH_KEY(&contents, "reclaim_shares");
            CHECK_CBOR_ERR(cbor_value_advance(&contents));
            CHECK_PARSER_ERR(_readQuantity(&contents, &v->oasis.tx.body.stakingReclaimEscrow.reclaim_shares));
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
        case registryDeregisterEntity: {
            CHECK_CBOR_MAP_LEN(value, 1);
            CHECK_CBOR_ERR(cbor_value_enter_container(value, &contents));

            CHECK_CBOR_MATCH_KEY(&contents, "node_id");
            CHECK_CBOR_ERR(cbor_value_advance(&contents));
            CHECK_PARSER_ERR(_readPublicKey(&contents, &v->oasis.tx.body.registryUnfreezeNode.node_id));
            CHECK_CBOR_ERR(cbor_value_advance(&contents));

            break;
        }
        case unknownMethod:
        default:
            return parser_unexpected_method;
    }

    return parser_ok;
}

__Z_INLINE parser_error_t _readNonce(parser_tx_t *v, CborValue *value) {
    if (!cbor_value_is_valid(value))
        return parser_required_nonce;

    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborIntegerType);
    CHECK_CBOR_ERR(cbor_value_get_uint64(value, &v->oasis.tx.nonce));

    return parser_ok;
}

__Z_INLINE parser_error_t _readMethod(parser_tx_t *v, CborValue *value) {

    if (!cbor_value_is_valid(value))
        return parser_required_method;

    // Verify it is well formed (no missing bytes...)
    CHECK_CBOR_ERR(cbor_value_validate_basic(value));

    v->oasis.tx.method = unknownMethod;
    if (_matchKey(value, "staking.Transfer"))
        v->oasis.tx.method = stakingTransfer;
    if (_matchKey(value, "staking.Burn"))
        v->oasis.tx.method = stakingBurn;
    if (_matchKey(value, "staking.AddEscrow"))
        v->oasis.tx.method = stakingAddEscrow;
    if (_matchKey(value, "staking.ReclaimEscrow"))
        v->oasis.tx.method = stakingReclaimEscrow;
    if (_matchKey(value, "staking.AmendCommissionSchedule"))
        v->oasis.tx.method = stakingAmendCommissionSchedule;
    if (_matchKey(value, "registry.DeregisterEntity"))
        v->oasis.tx.method = registryDeregisterEntity;
    if (_matchKey(value, "registry.UnfreezeNode"))
        v->oasis.tx.method = registryUnfreezeNode;
    if (v->oasis.tx.method == unknownMethod)
        return parser_unexpected_method;

    return parser_ok;
}

__Z_INLINE parser_error_t _readTx(parser_tx_t *v, CborValue *it) {

    MEMZERO(&v->oasis.tx, sizeof(oasis_tx_t));

    uint8_t valuesCount = 0;

    CHECK_CBOR_TYPE(cbor_value_get_type(it), CborMapType);

    // Find method and read it first
    CborValue methodField;
    CHECK_CBOR_ERR(cbor_value_map_find_value(it, "method", &methodField));
    CHECK_PARSER_ERR(_readMethod(v, &methodField));
    valuesCount++;

    CborValue feeField;
    CHECK_CBOR_ERR(cbor_value_map_find_value(it, "fee", &feeField));
    v->oasis.tx.has_fee = false;

    // We have fee
    if (cbor_value_is_valid(&feeField)) {
        CHECK_PARSER_ERR(_readFee(v, &feeField));
        valuesCount++;
    }

    CborValue nonceField;
    CHECK_CBOR_ERR(cbor_value_map_find_value(it, "nonce", &nonceField));
    CHECK_PARSER_ERR(_readNonce(v, &nonceField));
    valuesCount++;

    if (v->oasis.tx.method != registryDeregisterEntity) {
        // This method doesn't have a body
        CborValue bodyField;
        CHECK_CBOR_ERR(cbor_value_map_find_value(it, "body", &bodyField));
        CHECK_PARSER_ERR(_readBody(v, &bodyField));
        valuesCount++;
    }

    // Verify there is no extra fields in transaction
    CHECK_CBOR_MAP_LEN(it, valuesCount);

    return parser_ok;
}

__Z_INLINE parser_error_t _readEntity(parser_tx_t *v, CborValue *value) {
    /* Not using cbor_value_map_find because Cbor canonical order should be respected */

    MEMZERO(&v->oasis.entity, sizeof(oasis_entity_t));

    CborValue contents;

    // expect id, nodes, allow_entity_signed_nodes
    CHECK_CBOR_MAP_LEN(value, 3);
    CHECK_CBOR_ERR(cbor_value_enter_container(value, &contents));

    CHECK_CBOR_MATCH_KEY(&contents, "id");
    CHECK_CBOR_ERR(cbor_value_advance(&contents));
    CHECK_PARSER_ERR(_readPublicKey(&contents, &v->oasis.entity.id));
    CHECK_CBOR_ERR(cbor_value_advance(&contents));

    CHECK_CBOR_MATCH_KEY(&contents, "nodes");
    CHECK_CBOR_ERR(cbor_value_advance(&contents));
    // Only get length
    CHECK_CBOR_TYPE(cbor_value_get_type(&contents), CborArrayType);
    cbor_value_get_array_length(&contents, &v->oasis.entity.nodes_length);

    // too much nodes id in the blob to be print
    if (v->oasis.entity.nodes_length > MAX_ENTITY_NODES)
        return parser_unexpected_number_items;

    CHECK_CBOR_ERR(cbor_value_advance(&contents));

    CHECK_CBOR_MATCH_KEY(&contents, "allow_entity_signed_nodes");
    CHECK_CBOR_ERR(cbor_value_advance(&contents));
    CHECK_CBOR_TYPE(cbor_value_get_type(&contents), CborBooleanType);
    CHECK_CBOR_ERR(cbor_value_get_boolean(&contents, &v->oasis.entity.allow_entity_signed_nodes));
    CHECK_CBOR_ERR(cbor_value_advance(&contents));

    return parser_ok;
}

parser_error_t _read(parser_context_t *c, parser_tx_t *v) {
    CborValue it;
    CHECK_CBOR_ERR(cbor_parser_init(c->buffer,
                                    c->bufferLen,
                                    c->offset,
                                    &v->parser,
                                    &it));

    if (cbor_value_at_end(&it)) {
        return parser_unexpected_buffer_end;
    }

    if (!cbor_value_is_map(&it)) {
        return parser_unexpected_type;
    }

    // ENTITY OR TX ?
    CborValue idField;
    CHECK_CBOR_ERR(cbor_value_map_find_value(&it, "id", &idField));

    // default Unknown type
    v->type = unknownType;
    if (cbor_value_get_type(&idField) == CborInvalidType) {
        // READ TX
        CHECK_CBOR_ERR(_readTx(v, &it));
        v->type = txType;
    } else {
        // READ ENTITY
        CHECK_CBOR_ERR(_readEntity(v, &it));
        v->type = entityType;
    }

    CHECK_CBOR_ERR(cbor_value_advance(&it));

    // Could we do it.parser->end != it.ptr ?
    if (it.ptr != c->buffer + c->bufferLen) {
        // End of buffer does not match end of parsed data
        return parser_unexpected_data_at_end;
    }

    return parser_ok;
}

parser_error_t _validateTx(parser_context_t *c, parser_tx_t *v) {
    // TODO: Add any additional sensible validation here
    CborValue it;
    CHECK_CBOR_ERR(cbor_parser_init(c->buffer,
                                    c->bufferLen,
                                    c->offset,
                                    &v->parser,
                                    &it));

    // validate CBOR canonical order
    CHECK_CBOR_ERR(cbor_value_validate(&it, CborValidateCanonicalFormat));

    return parser_ok;
}

uint8_t _getNumItems(parser_context_t *c, parser_tx_t *v) {
    // typical tx: Type, Fee, Gas, + Body
    uint8_t itemCount = 3;

    // Entity (not a tx)
    if (v->type == entityType) {
        itemCount = 2 + v->oasis.entity.nodes_length;
        return itemCount;
    }

    if (!v->oasis.tx.has_fee)
        itemCount = 1;

    switch (v->oasis.tx.method) {
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
            itemCount += v->oasis.tx.body.stakingAmendCommissionSchedule.rates_length * 2;
            // Each bound contains 3 items (start, rate_max & rate_min)
            itemCount += v->oasis.tx.body.stakingAmendCommissionSchedule.bounds_length * 3;
            break;
        case registryDeregisterEntity:
            itemCount += 0;
            break;
        case registryUnfreezeNode:
            itemCount += 1;
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

    CHECK_CBOR_ERR(_readRate(&ratesContainer, &v->oasis.tx.body.stakingAmendCommissionSchedule.rate));

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

    CHECK_CBOR_ERR(_readBound(&boundsContainer, &v->oasis.tx.body.stakingAmendCommissionSchedule.bound));

    return parser_ok;

}

parser_error_t _getNodesIdAtIndex(parser_context_t *c, parser_tx_t *v, uint8_t index) {
    CborValue it;
    CHECK_CBOR_ERR(cbor_parser_init(c->buffer,
                                    c->bufferLen,
                                    c->offset,
                                    &v->parser,
                                    &it));

    if (cbor_value_at_end(&it)) {
        return parser_unexpected_buffer_end;
    }

    if (!cbor_value_is_map(&it)) {
        return parser_unexpected_type;
    }

    CborValue nodesContainer;
    CHECK_CBOR_ERR(cbor_value_map_find_value(&it, "nodes", &nodesContainer));

    if (!cbor_value_is_array(&nodesContainer)) {
        return parser_unexpected_type;
    }

    for (int i = 0; i < index; i++) {
        CHECK_CBOR_ERR(cbor_value_advance(&nodesContainer));
    }

    CHECK_CBOR_ERR(_readPublicKey(&nodesContainer, &v->oasis.entity.node));

    return parser_ok;
}
