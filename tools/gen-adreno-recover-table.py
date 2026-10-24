#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate compat/adreno-recover-table.h: the register program the monitor's CP soft reset replays
(SNAP_ADRENO_RECOVER=2, agents/gpu-recovery FAILURE-MODES.md R9-R11), taken from q1n1's own cp-fence code so no
register value is typed by hand:
  - hw_init(): a8xx hw_init up to the SQE start, run against a recording session (nothing reaches hardware). Its
    qcom_scm_set_gpu_smmu_aperture SMC becomes an SMC op at the same position; ahb_timeouts() (CX_MISC) is left out.
  - sqe_start(): its CP_SQE_CNTL write only (the rest are diagnostic samples).
  - cmd_cp_fence C4: the CP_THREAD_CONTROL + CP_ME_INIT words (read from the source, evaluated against adreno_x2).
  - cmd_cp_fence C5: SECVID_TRUST_CNTL = NONSECURE with its read-back check, the BR RB_GC_GMEM_PROTECT write, the
    aperture clear (checked against the source text, then replayed through q1n1's pipe_write/aperture_clear).
Only writes inside the monitor's GX passthrough windows (compat/adreno.c map: [0x03d00000, 0x03d37000) and
[0x03d3c000, 0x03d40000)) are replayed: a GX reset leaves CX-side blocks (CX_MISC, GMU) as they were. Those writes are
listed in the header as comments. Reads hw_init makes for ordering (gpu_read after a write) are kept as READ ops.

Usage: gen-adreno-recover-table.py [--q1n1-tools DIR] [--x290] [--out compat/adreno-recover-table.h] [--check]
--check regenerates into memory and exits 1 if the file differs (the drift test)."""
from __future__ import annotations

import argparse
import hashlib
import inspect
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PASS = ((0x03d00000, 0x03d37000), (0x03d3c000, 0x03d40000))
GPU_PA = 0x03d00000
MONITOR_SMC_CP_APERTURE = (0x42000C1B, 4, 0xFFFF0000, 0xFFFFFFFF)   # compat/adreno.h adreno_smc_allowed
OP = {'WRITE': 0, 'READ': 1, 'SMC_APERTURE': 2, 'READBACK': 3}


def passthrough(pa):
    return any(lo <= pa < hi for lo, hi in PASS)


class Recorder:
    """The parts of q1n1's Session3 that hw_init, sqe_start, pipe_write and aperture_clear use. Every access is
    recorded; reads answer 0 (hw_init's reads are ordering reads; sqe_start's are samples and are dropped)."""

    def __init__(self, R):
        self.R = R
        self.ops = []
        self.skipped = []
        self.step = 'C3'
        self.arena = (0, 32 << 20)
        self.proven = {'gx': 'recorder', 'cx_gmu': 'recorder', 'cx_misc': 'recorder', 'always': 'recorder'}
        self.clock = lambda: 0.0

    def _reg(self, name, index):
        reg = self.R.REGS[name]
        return reg, reg.at(index)

    def wr(self, name, value, index=0):
        reg, pa = self._reg(name, index)
        value &= 0xFFFFFFFF
        if passthrough(pa):
            self.ops.append(('WRITE', pa, value, f'{name}[{index}]' if reg.count > 1 else name))
        else:
            self.skipped.append(('write', pa, value, name))

    def rd(self, name, index=0):
        reg, pa = self._reg(name, index)
        if passthrough(pa):
            self.ops.append(('READ', pa, 0, f'{name}[{index}]' if reg.count > 1 else name))
        return 0

    def wr_update(self, name, mask, bits, index=0):
        reg, pa = self._reg(name, index)
        if passthrough(pa):
            raise SystemExit(f'{name}: read-modify-write of a GX register cannot be replayed from a recording')
        self.skipped.append(('update', pa, bits & mask, name))
        return bits & mask

    def udelay(self, us):
        pass


def load_q1n1(tools):
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(tools))
    import adreno_x2 as R             # noqa: E402
    import a16gpu_stage3 as S3        # noqa: E402
    return R, S3


def generate(tools, x290):
    R, S3 = load_q1n1(tools)
    if tuple(S3.SMC_CP_APERTURE) != MONITOR_SMC_CP_APERTURE:
        raise SystemExit(f'q1n1 SMC_CP_APERTURE {S3.SMC_CP_APERTURE} is not the monitor allow-list entry')
    s = Recorder(R)
    args = S3.Args()
    args.x290 = x290
    real_ahb, real_aperture = S3.ahb_timeouts, S3.cp_aperture

    def no_ahb(sess, out, a):
        sess.skipped.append(('ahb_timeouts', 0, 0, 'CX_MISC_CX_AHB_CNTL[*] (CX side)'))
        return None

    def aperture_smc(sess, out, a, host):
        sess.ops.append(('SMC_APERTURE', 0, 0, 'qcom_scm_set_gpu_smmu_aperture(0)'))

    S3.ahb_timeouts, S3.cp_aperture = no_ahb, aperture_smc
    try:
        out = {'order': []}
        gmem_protect = S3.hw_init(s, out, args, {})
        hw = list(s.ops)
        s.ops.clear()
        S3.sqe_start(s, {'order': []}, args, False, None)
        sqe = [o for o in s.ops if o[0] == 'WRITE']
        s.ops.clear()
    finally:
        S3.ahb_timeouts, S3.cp_aperture = real_ahb, real_aperture
    if [o[3] for o in sqe] != ['CP_SQE_CNTL'] or sqe[0][2] != 1:
        raise SystemExit(f'sqe_start no longer writes exactly CP_SQE_CNTL = 1: {sqe}')
    if gmem_protect != S3.x285_gmem_protect():
        raise SystemExit('hw_init returned a GMEM protect value other than x285_gmem_protect()')
    src = inspect.getsource(S3.cmd_cp_fence)
    m = re.search(r"init = (\[R\.pkt7\(R\.CP_THREAD_CONTROL, 1\).*?\])\n", src, re.S)
    if not m:
        raise SystemExit('cmd_cp_fence C4: the CP_ME_INIT word list was not found')
    # q1n1's own list expression (local sources, read-only), evaluated with no builtins and only adreno_x2 in scope.
    me_init = eval(m.group(1), {'__builtins__': {}, 'R': R})   # noqa: S307
    if len(me_init) != 10 or me_init[0] != R.pkt7(R.CP_THREAD_CONTROL, 1) or me_init[2] != R.pkt7(R.CP_ME_INIT, 7):
        raise SystemExit(f'cmd_cp_fence C4 words changed shape: {me_init}')
    c5 = ("s.wr('RBBM_SECVID_TRUST_CNTL', R.SECVID_TRUST_CNTL_NONSECURE)",
          "secvid = s.rd('RBBM_SECVID_TRUST_CNTL')",
          "pipe_write(s, R.PIPE_BR, 'RB_GC_GMEM_PROTECT', gmem_protect)",
          "aperture_clear(s)")
    at = [src.find(line) for line in c5]
    if min(at) < 0 or at != sorted(at) or src.find("s.step = 'C5'") > at[0]:
        raise SystemExit('cmd_cp_fence C5 changed: SECVID, the BR GMEM protect write and the aperture clear')
    s.wr('RBBM_SECVID_TRUST_CNTL', R.SECVID_TRUST_CNTL_NONSECURE)
    pa = R.REGS['RBBM_SECVID_TRUST_CNTL'].at(0)
    s.ops.append(('READBACK', pa, R.SECVID_TRUST_CNTL_NONSECURE, 'RBBM_SECVID_TRUST_CNTL'))
    S3.pipe_write(s, R.PIPE_BR, 'RB_GC_GMEM_PROTECT', gmem_protect)
    S3.aperture_clear(s)
    secvid = list(s.ops)
    # adreno_x2.py loads X285_NONCTXT (hw_init's non-context writes, among them RB_GC_GMEM_PROTECT) from
    # adreno_x2_protect.py since q1n1 split its GPL-2.0-only tables out; a q1n1 from before the split has none.
    protect = [tools / 'adreno_x2_protect.py'] if (tools / 'adreno_x2_protect.py').exists() else []
    sources = [tools / 'a16gpu_stage3.py', tools / 'adreno_x2.py', *protect]
    sources += [tools / 'a16gpu_x290.py'] if x290 else []
    inputs = ' '.join(f'{p.name}:{hashlib.sha256(p.read_bytes()).hexdigest()}' for p in sources)
    return hw, sqe, me_init, secvid, s.skipped, inputs


def c_ops(name, ops):
    rows = []
    for kind, pa, value, what in ops:
        reg = (pa - GPU_PA) // 4 if kind != 'SMC_APERTURE' else 0
        if kind != 'SMC_APERTURE' and (not passthrough(pa) or pa & 3):
            raise SystemExit(f'{what} at {pa:#x} is outside the GX passthrough windows')
        rows.append(f'    {{ADRENO_RT_{kind}, 0x{reg:05x}u, 0x{value:08x}u}},   /* {what} */')
    return f'static const struct adreno_recover_op {name}[{len(ops)}] = {{\n' + '\n'.join(rows) + '\n};\n'


def render(hw, sqe, me_init, secvid, skipped, inputs, x290):
    options = '--x290' if x290 else ''
    skip = '\n'.join(f' *   {k} {name} @ {pa:#010x} = {v:#x}' for k, pa, v, name in skipped)
    words = ', '.join(f'0x{w:08x}u' for w in me_init)
    protect = sum(1 for o in hw if o[3].startswith('CP_PROTECT_GLOBAL['))
    return f'''/* SPDX-License-Identifier: MIT */
/* GENERATED by tools/gen-adreno-recover-table.py from q1n1 tools/a16gpu_stage3.py (cp-fence {options or 'default options'}).
 * Do not edit: regenerate, and run tools/test-gen-adreno-recover-table.py. The CP soft reset (SNAP_ADRENO_RECOVER=2,
 * compat/adreno-ib.c adreno_recover) replays these after RBBM_SW_RESET_CMD, in this order: hw_init (with the CP
 * aperture SMC where q1n1 makes it), the SQE start, CP_ME_INIT on the ring, then SECVID and the BR GMEM protect.
 * reg is a GPU dword offset: the monitor writes ADRENO_PA + 4 * reg, and refuses an entry outside its GX passthrough
 * windows. READ is an ordering read (gpu_read after a write in Linux and q1n1); READBACK must read `value`.
 * Not replayed (CX side, not reset by a GX soft reset; q1n1 made them in gmu-boot/cp-fence):
{skip}
 */
#pragma once
#include <stdint.h>
#define ADRENO_RECOVER_TABLE_INPUTS "{inputs}"
#define ADRENO_RECOVER_TABLE_CP_FENCE_OPTIONS "{options}"
#define ADRENO_RECOVER_TABLE_PROTECT_GLOBAL {protect}u
#define ADRENO_RT_WRITE 0u
#define ADRENO_RT_READ 1u
#define ADRENO_RT_SMC_APERTURE 2u
#define ADRENO_RT_READBACK 3u
struct adreno_recover_op {{ uint32_t op, reg, value; }};
{c_ops('adreno_recover_hw_init', hw)}{c_ops('adreno_recover_sqe_start', sqe)}static const uint32_t adreno_recover_me_init[{len(me_init)}] = {{{words}}};
{c_ops('adreno_recover_secvid', secvid)}'''


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--q1n1-tools', default=str(ROOT.parent / 'q1n1' / 'tools'))
    ap.add_argument('--x290', action='store_true')
    ap.add_argument('--out', default=str(ROOT / 'compat' / 'adreno-recover-table.h'))
    ap.add_argument('--check', action='store_true')
    a = ap.parse_args(argv)
    text = render(*generate(Path(a.q1n1_tools).resolve(), a.x290), a.x290)
    out = Path(a.out)
    if a.check:
        same = out.exists() and out.read_text() == text
        print(f'{out}: {"up to date" if same else "DIFFERS from the generator output"}')
        return 0 if same else 1
    out.write_text(text)
    print(f'wrote {out}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
