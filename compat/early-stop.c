/* SPDX-License-Identifier: MIT */
/* See early-stop.h. Freestanding: no library calls, no structure copies. */
#include "early-stop.h"
#include "adreno-guest.h"
#include "auxkc-observe.h"

_Static_assert(sizeof(struct early_stop_params) == 8 * EARLY_STOP_PARAMS_WORDS,
               "probes/xnuboot.py writes params.early_stop word by word");
_Static_assert(sizeof(struct early_stop_state) == 8 * EARLY_STOP_STATE_WORDS,
               "tools/early_stop.py decodes every word of the record");
_Static_assert(sizeof(struct early_stop_host_request) == 8 * EARLY_STOP_HOST_REQUEST_WORDS,
               "q1n1 platform/uefi/call-service.h fills the same words");
_Static_assert(__atomic_always_lock_free(sizeof(uint64_t), 0), "native 64-bit atomics required");

/* HVC #imm16: 0xd4000002 | imm16 << 5. The trap reports only the immediate,
 * so the bytes are read back to prove this exact instruction raised it. */
#define HVC_WORD(imm) (0xd4000002u | ((uint32_t)(imm) << 5))

int early_stop_guest_caller(const struct auxkc_range *kc, uint64_t hvc_va,
                            uint64_t hvc_pa, uint32_t word, uint64_t spsr)
{
    unsigned mode = (unsigned)(spsr & 31);
    if (!kc || (mode != 4 && mode != 5)) return EARLY_STOP_E_CALLER;   /* EL1t or EL1h */
    if (!kc->va_end || kc->va_end - kc->va_base < 4 || kc->pa_end - kc->pa_base < 4 ||
        kc->va_end < kc->va_base || kc->pa_end < kc->pa_base || (hvc_va & 3) ||
        hvc_va < kc->va_base || hvc_va > kc->va_end - 4 ||
        hvc_pa < kc->pa_base || hvc_pa > kc->pa_end - 4)
        return EARLY_STOP_E_CALLER;
    /* probes/auxkc.py maps every segment at base_va + off -> base_pa + off. */
    if (hvc_va - kc->va_base != hvc_pa - kc->pa_base) return EARLY_STOP_E_CALLER;
    return word == HVC_WORD(ADRENO_GUEST_HVC) ? 0 : EARLY_STOP_E_CALLER;
}

int early_stop_delay(const struct early_stop_params *p, uint64_t requested, uint64_t *accepted)
{
    if (!p || !accepted || requested > EARLY_STOP_DELAY_LIMIT ||
        p->max_delay_s > EARLY_STOP_DELAY_LIMIT) return EARLY_STOP_E_DELAY;
    *accepted = requested < p->max_delay_s ? requested : p->max_delay_s;
    return 0;
}

int early_stop_guest_admit(const struct early_stop_params *p, const struct auxkc_range *kc,
                           uint64_t hvc_va, uint64_t hvc_pa, uint32_t word, uint64_t spsr,
                           uint64_t reason, uint64_t requested, uint64_t *accepted)
{
    if (!p || !(p->flags & EARLY_STOP_F_GUEST)) return EARLY_STOP_E_DISABLED;
    int e = early_stop_guest_caller(kc, hvc_va, hvc_pa, word, spsr);
    if (e) return e;
    if (!reason || reason > EARLY_STOP_GUEST_REASON_MAX) return EARLY_STOP_E_REASON;
    return early_stop_delay(p, requested, accepted);
}

static uint64_t load(const uint64_t *p) { return __atomic_load_n(p, __ATOMIC_ACQUIRE); }
static void bump(uint64_t *p) { if (__atomic_load_n(p, __ATOMIC_RELAXED) != UINT64_MAX)
                                    __atomic_add_fetch(p, 1, __ATOMIC_RELAXED); }

int early_stop_request(struct early_stop_state *s, unsigned source, uint64_t reason,
                       uint64_t detail, uint64_t requested, uint64_t accepted,
                       uint64_t now, uint64_t hz, unsigned cpu, uint64_t pc,
                       const uint64_t *text)
{
    if (!s) return EARLY_STOP_DUPLICATE;
    /* Request/fire writers normally hold the monitor service lock. The phase
     * claim also preserves a coherent record if a peer races that boundary. */
    uint64_t ticks = hz && accepted > INT64_MAX / hz ? (uint64_t)INT64_MAX : accepted * hz;
    uint64_t deadline = now + ticks;
    uint64_t phase = EARLY_STOP_IDLE;
    if (!__atomic_compare_exchange_n(&s->state, &phase, EARLY_STOP_ARMING, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        if ((source != EARLY_STOP_SOURCE_HOST && source != EARLY_STOP_SOURCE_THERMAL) || phase != EARLY_STOP_PENDING)
            goto duplicate;
        phase = EARLY_STOP_PENDING;
        if (!__atomic_compare_exchange_n(&s->state, &phase, EARLY_STOP_UPDATING, 0,
                                         __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            goto duplicate;
        /* Check after claiming: another stop writer may already have shortened it.
         * UPDATING keeps the old deadline visible; it never opens a budget gap. */
        if ((int64_t)(deadline - load(&s->deadline)) >= 0) {
            __atomic_store_n(&s->state, EARLY_STOP_PENDING, __ATOMIC_RELEASE);
            goto duplicate;
        }
    }
    s->source = source; s->reason = reason; s->detail = detail;
    s->requested_delay = requested; s->accepted_delay = accepted;
    s->request_ticks = now; s->request_cpu = (uint64_t)cpu + 1; s->request_pc = pc;
    for (unsigned n = 0; n < 8; n++) s->text[n] = text ? text[n] : 0;
    __atomic_store_n(&s->deadline, deadline, __ATOMIC_RELEASE);
    __atomic_store_n(&s->state, EARLY_STOP_PENDING, __ATOMIC_RELEASE);
    return EARLY_STOP_ACCEPTED;
duplicate:
    bump(&s->duplicates);
    return EARLY_STOP_DUPLICATE;
}

void early_stop_refuse(struct early_stop_state *s, int code)
{
    if (!s) return;
    bump(&s->refusals);
    __atomic_store_n(&s->last_refusal, (uint64_t)(int64_t)code, __ATOMIC_RELAXED);
}

uint64_t early_stop_deadline(const struct early_stop_state *s, uint64_t budget)
{
    if (!s) return budget;
    uint64_t state = load(&s->state);
    if (state != EARLY_STOP_PENDING && state != EARLY_STOP_FIRED && state != EARLY_STOP_UPDATING) return budget;
    uint64_t deadline = __atomic_load_n(&s->deadline, __ATOMIC_RELAXED);
    return (int64_t)(deadline - budget) < 0 ? deadline : budget;
}

int early_stop_fire(struct early_stop_state *s, uint64_t now, uint64_t budget, unsigned cpu)
{
    if (!s) return 0;
    uint64_t state = load(&s->state);
    if (state != EARLY_STOP_PENDING && state != EARLY_STOP_FIRED) return 0;
    uint64_t deadline = __atomic_load_n(&s->deadline, __ATOMIC_RELAXED);
    /* A deadline no earlier than the budget leaves the stop to the watchdog,
     * so a tie is always recorded as the budget's. */
    if ((int64_t)(now - deadline) < 0 || (int64_t)(deadline - budget) >= 0) return 0;
    uint64_t pending = EARLY_STOP_PENDING;
    if (__atomic_compare_exchange_n(&s->state, &pending, EARLY_STOP_FIRED, 0,
                                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        s->fire_ticks = now;
        s->fire_cpu = (uint64_t)cpu + 1;
        return 1;
    }
    /* An updating request owns the metadata. Retry at the next timer entry;
     * a peer that already fired is the only other successful stop condition. */
    return pending == EARLY_STOP_FIRED;
}

void early_stop_finish(struct early_stop_state *s, uint64_t stop_word)
{
    if (!s) return;
    uint64_t state = load(&s->state);
    if (state == EARLY_STOP_FIRED)
        s->outcome = stop_word == ((UINT64_C(1) << 32) | s->fire_cpu) ?   /* SERVICE_STOP_NORMAL */
                     EARLY_STOP_OUTCOME_STOPPED : EARLY_STOP_OUTCOME_CONCURRENT;
    else s->outcome = state == EARLY_STOP_PENDING ? EARLY_STOP_OUTCOME_SUPERSEDED
                                                  : EARLY_STOP_OUTCOME_NONE;
}

int early_stop_host_due(struct early_stop_state *s, const struct early_stop_params *p,
                        uint64_t now, uint64_t hz)
{
    if (!p || !(p->flags & EARLY_STOP_F_HOST) || !p->host_call || !p->session || !hz ||
        p->host_poll_ms < EARLY_STOP_POLL_FLOOR(p) || p->host_poll_ms > EARLY_STOP_POLL_MAX_MS)
        return 0;
    if (s->host_polls && (int64_t)(now - s->host_next_poll) < 0) return 0;
    uint64_t period = hz / 1000 * p->host_poll_ms;
    s->host_next_poll = now + (period ? period : 1);
    bump(&s->host_polls);
    return 1;
}

int early_stop_host_admit(const struct early_stop_params *p,
                          const struct early_stop_host_request *r, uint64_t *accepted)
{
    if (!p || !r || !(p->flags & EARLY_STOP_F_HOST)) return EARLY_STOP_E_DISABLED;
    if (r->magic != EARLY_STOP_HOST_MAGIC || r->session != p->session || !p->session)
        return EARLY_STOP_E_HOST;
    if (!r->reason || r->reason > EARLY_STOP_HOST_REASON_MAX) return EARLY_STOP_E_REASON;
    /* q1n1 NUL-terminates; a record whose last byte is not NUL was not written by it. */
    if (r->text[7] >> 56) return EARLY_STOP_E_HOST;
    return early_stop_delay(p, r->delay_s, accepted);
}
