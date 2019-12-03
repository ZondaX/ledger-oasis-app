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
#pragma once

#include <stdint.h>
#include <zxtypes.h>
#include "parser_txdef.h"
#include "parser_common.h"

#ifdef __cplusplus
extern "C" {
#endif

parser_error_t crypto_set_context(const uint8_t *context, uint8_t context_len);

const uint8_t *crypto_get_context();

uint8_t crypto_get_context_length();

bool_t crypto_validate_context(oasis_methods_e method);

#ifdef __cplusplus
}
#endif
