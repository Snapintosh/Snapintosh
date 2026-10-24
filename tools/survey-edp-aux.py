#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only survey of the eDP controller's AUX block (mdss_dp3) from q1n1, before an --edp-backlight boot.

compat/edp-backlight.h: the monitor's ADRENO_GUEST_BACKLIGHT needs the MDSS AHB and DPTX3 AUX clocks on, the MDSS
core power domain on and the AUX controller enabled, as the firmware left them; it never turns any of them on. This
reads, in order, stopping at the first failed check (an unclocked MDSS read is an SError, a cold reboot):
  1. DISP_CC_MDSS_AHB_CBCR and DISP_CC_MDSS_DPTX3_AUX_CBCR: CLK_OFF (bit 31) clear; MDSS_CORE_GDSCR: PWR_ON (bit 31)
     set;
  2. the controller's HW version, interrupt status (with its mask bits) and the AUX block's HPD, enable, timeout,
     limit and status registers.
Nothing is written, no AUX transaction is started, and neither the AUX FIFO nor the PHY interrupt status (possibly
read-to-clear) is read: the panel's DPCD capabilities are first read by the monitor's own probe at boot.

    python3 tools/survey-edp-aux.py --plan                     # the read list, offline
    python3 tools/survey-edp-aux.py --check SURVEY.json        # decode a saved survey, offline
    python3 tools/survey-edp-aux.py --survey --device udp://enN --output NEW.json
"""
from pathlib import Path
import argparse
import json
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def constants():
    out = {}
    for header in ('compat/dpu-intf.h', 'compat/edp-backlight.h'):
        text = (ROOT / header).read_text()
        for name, value in re.findall(r'#define ((?:DPU|EDP)_\w+)\s+(0x[0-9A-Fa-f]+|\d+)(?:ULL|u)?\b', text):
            out[name] = int(value, 0)
        for name, shift in re.findall(r'#define ((?:DPU|EDP)_\w+)\s+\(1u << (\d+)\)', text):
            out[name] = 1 << int(shift)
    return out


C = constants()
AHB, AUX, CC = C['EDP_DP3_AHB_PA'], C['EDP_DP3_AUX_PA'], C['DPU_DISPCC_PA']
CLOCKS = (('DISP_CC_MDSS_AHB_CBCR', CC + C['DPU_DISPCC_MDSS_AHB_CBCR'], 'clock'),
          ('DISP_CC_MDSS_CORE_GDSCR', CC + C['DPU_DISPCC_MDSS_CORE_GDSCR'], 'gdsc'),
          ('DISP_CC_MDSS_DPTX3_AUX_CBCR', CC + C['EDP_DISPCC_DPTX3_AUX_CBCR'], 'clock'))
# Offsets from Linux drivers/gpu/drm/msm/dp/dp_reg.h (facts only): HW_VERSION 0x00, INTR_STATUS 0x20, INTR_STATUS2
# 0x24 in "ahb"; HPD_CTRL 0x00, HPD_INT_STATUS 0x04, HPD_INT_MASK 0x0c, AUX_CTRL 0x30, TIMEOUT_COUNT 0x3c,
# AUX_LIMITS 0x40, AUX_STATUS 0x44 in "aux".
REGS = (('DP_HW_VERSION', AHB + 0x00), ('DP_INTR_STATUS', AHB + C['EDP_AHB_INTR_STATUS']),
        ('DP_INTR_STATUS2', AHB + 0x24), ('AUX_HPD_CTRL', AUX + 0x00),
        ('AUX_HPD_INT_STATUS', AUX + C['EDP_AUX_HPD_INT_STATUS']), ('AUX_HPD_INT_MASK', AUX + 0x0c),
        ('AUX_CTRL', AUX + C['EDP_AUX_CTRL']), ('AUX_TIMEOUT_COUNT', AUX + 0x3c), ('AUX_LIMITS', AUX + 0x40),
        ('AUX_STATUS', AUX + 0x44))
NEVER = (AUX + C['EDP_AUX_DATA'], AUX + C['EDP_AUX_PHY_INTR_STATUS'])


def plan():
    reads = [(name, pa, kind) for name, pa, kind in CLOCKS] + [(name, pa, 'dp') for name, pa in REGS]
    for _, pa, kind in reads:
        assert pa not in NEVER and (kind != 'dp' or AHB <= pa < AHB + 0x400)
    return reads


INTR_NAMES = ((0, 'HPD'), (3, 'AUX_DONE'), (6, 'WRONG_ADDR'), (9, 'TIMEOUT'), (12, 'NACK_DEFER'),
              (15, 'WRONG_DATA_CNT'), (18, 'I2C_NACK'), (21, 'I2C_DEFER'), (24, 'PLL_UNLOCKED'), (27, 'AUX_ERROR'))


def check(record):
    regs = {k: int(v, 0) if isinstance(v, str) else v for k, v in record['registers'].items()}
    out = {}
    for name, _, kind in CLOCKS:
        v = regs.get(name)
        out[name] = None if v is None else ('on' if (kind == 'clock' and not v >> 31) or (kind == 'gdsc' and v >> 31)
                                            else 'OFF')
    if 'AUX_CTRL' not in regs:
        out['verdict'] = 'stopped before the DP block: ' + record.get('stopped', 'no DP registers')
        return out
    intr, hpd = regs['DP_INTR_STATUS'], regs['AUX_HPD_INT_STATUS']
    out['aux_enabled'] = bool(regs['AUX_CTRL'] & C['EDP_AUX_CTRL_ENABLE'])
    out['hpd_state'] = {0x40000000: 'connected', 0x20000000: 'pending', 0: 'disconnected'}.get(
        hpd & 0xE0000000, f'{hpd & 0xE0000000:#x}')
    out['pending_statuses'] = [n for bit, n in INTR_NAMES if intr >> bit & 1]
    out['unmasked_interrupts'] = [n for bit, n in INTR_NAMES if intr >> (bit + 2) & 1]
    ready = all(out[n] == 'on' for n, _, _ in CLOCKS) and out['aux_enabled']
    out['verdict'] = ('ready: the monitor probe will read DPCD 0x00D, 0x700-0x703 and 0x721-0x726' if ready else
                      'NOT ready: ADRENO_GUEST_BACKLIGHT will answer FAILED (nothing is enabled from EL2)')
    return out


def survey(device, output):
    sys.path.insert(0, str(ROOT.parent / 'q1n1' / 'tools'))
    import q1n1proxy
    proxy = q1n1proxy.connect(device=device)
    registers, record = {}, dict(schema='snapintosh-edp-aux-survey-v1', device=device, started=time.time())
    for name, pa, kind in CLOCKS:                    # 1: clocks and power before any DP read
        v = registers[name] = proxy.read32(pa)
        if (kind == 'clock' and v >> 31) or (kind == 'gdsc' and not v >> 31):
            record.update(registers={k: hex(x) for k, x in registers.items()},
                          stopped=f'{name} = {v:#x}: not clocked or not powered; no DP read')
            record['check'] = check(record)
            Path(output).write_text(json.dumps(record, indent=1) + '\n')
            raise SystemExit(record['stopped'])
    for name, pa, _ in plan()[len(CLOCKS):]:         # 2
        registers[name] = proxy.read32(pa)
    record.update(registers={k: hex(v) for k, v in registers.items()}, finished=time.time())
    record['check'] = check(record)
    Path(output).write_text(json.dumps(record, indent=1) + '\n')
    print(json.dumps(record['check'], indent=1))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--plan', action='store_true')
    ap.add_argument('--check')
    ap.add_argument('--survey', action='store_true')
    ap.add_argument('--device')
    ap.add_argument('--output')
    a = ap.parse_args()
    if a.plan:
        for name, pa, kind in plan():
            print(f'{pa:#012x}  {kind:5}  {name}')
    elif a.check:
        print(json.dumps(check(json.loads(Path(a.check).read_text())), indent=1))
    elif a.survey:
        if not a.device or not a.output or Path(a.output).exists():
            raise SystemExit('--survey needs --device and a new --output')
        survey(a.device, a.output)
    else:
        ap.print_help()


if __name__ == '__main__':
    main()
