/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "cryptlib_fault.h"
#include "hal/library/debuglib.h"

typedef struct {
    bool forced;
    uint32_t skip;
    uint32_t count;
    libspdm_crypto_fault_action_t action;
    uint32_t call_count;
    uint32_t applied_count;
} libspdm_crypto_fault_state_t;

static libspdm_crypto_fault_state_t m_state[LIBSPDM_CRYPTO_FAULT_OP_COUNT];
static uint32_t m_suspend_depth;

static libspdm_crypto_fault_action_t count_call(libspdm_crypto_fault_state_t *state,
                                                bool can_corrupt, bool can_apply)
{
    state->call_count++;
    if (!can_apply || !state->forced || (state->call_count <= state->skip) ||
        (state->applied_count >= state->count)) {
        return LIBSPDM_CRYPTO_FAULT_ACTION_NONE;
    }
    if ((state->action == LIBSPDM_CRYPTO_FAULT_ACTION_CORRUPT_OUTPUT) && !can_corrupt) {
        return LIBSPDM_CRYPTO_FAULT_ACTION_NONE;
    }
    state->applied_count++;

    return state->action;
}

libspdm_crypto_fault_action_t libspdm_crypto_fault_hit(libspdm_crypto_fault_op_t op,
                                                       bool can_corrupt)
{
    libspdm_crypto_fault_action_t action;
    libspdm_crypto_fault_action_t any_action;

    LIBSPDM_ASSERT((op > LIBSPDM_CRYPTO_FAULT_OP_ANY) && (op < LIBSPDM_CRYPTO_FAULT_OP_COUNT));
    if (m_suspend_depth != 0) {
        return LIBSPDM_CRYPTO_FAULT_ACTION_NONE;
    }

    /* A fault forced on the operation itself takes precedence over one forced on ANY. */
    action = count_call(&m_state[op], can_corrupt, true);
    any_action = count_call(&m_state[LIBSPDM_CRYPTO_FAULT_OP_ANY], can_corrupt,
                            action == LIBSPDM_CRYPTO_FAULT_ACTION_NONE);

    return (action != LIBSPDM_CRYPTO_FAULT_ACTION_NONE) ? action : any_action;
}

void libspdm_crypto_fault_corrupt(uint8_t *output, size_t output_size)
{
    if ((output != NULL) && (output_size != 0)) {
        output[0] ^= 0x01;
    }
}

void libspdm_crypto_fault_force(libspdm_crypto_fault_op_t op, uint32_t skip, uint32_t count,
                                libspdm_crypto_fault_action_t action)
{
    libspdm_crypto_fault_state_t *state;

    LIBSPDM_ASSERT(op < LIBSPDM_CRYPTO_FAULT_OP_COUNT);
    LIBSPDM_ASSERT(action != LIBSPDM_CRYPTO_FAULT_ACTION_NONE);

    state = &m_state[op];
    state->forced = true;
    state->skip = skip;
    state->count = count;
    state->action = action;
    state->call_count = 0;
    state->applied_count = 0;
}

void libspdm_crypto_fault_release(libspdm_crypto_fault_op_t op)
{
    size_t index;

    LIBSPDM_ASSERT(op < LIBSPDM_CRYPTO_FAULT_OP_COUNT);

    for (index = 0; index < LIBSPDM_CRYPTO_FAULT_OP_COUNT; index++) {
        if ((op == LIBSPDM_CRYPTO_FAULT_OP_ANY) || (index == (size_t)op)) {
            m_state[index].forced = false;
            m_state[index].call_count = 0;
            m_state[index].applied_count = 0;
        }
    }
}

uint32_t libspdm_crypto_fault_get_applied_count(libspdm_crypto_fault_op_t op)
{
    LIBSPDM_ASSERT(op < LIBSPDM_CRYPTO_FAULT_OP_COUNT);

    return m_state[op].applied_count;
}

uint32_t libspdm_crypto_fault_get_call_count(libspdm_crypto_fault_op_t op)
{
    LIBSPDM_ASSERT(op < LIBSPDM_CRYPTO_FAULT_OP_COUNT);

    return m_state[op].call_count;
}

void libspdm_crypto_fault_suspend(void)
{
    m_suspend_depth++;
}

void libspdm_crypto_fault_resume(void)
{
    LIBSPDM_ASSERT(m_suspend_depth != 0);

    m_suspend_depth--;
}
