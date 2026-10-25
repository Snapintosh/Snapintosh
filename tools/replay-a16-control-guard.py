#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline q1n1 wire-protocol replay of the complete control guard lifecycle.

No target, socket, USB, or device is opened. Uses the production q1n1 Proxy and
Link with a deterministic injected transport. Produces a retained JSON receipt.
Failure inventory: docs/A16-CPU-POLICY-REVIEW-20261018.md.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import time


ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def save_json(path, record):
    temporary = path.with_suffix(path.suffix + '.tmp')
    with temporary.open('w') as stream:
        json.dump(record, stream, indent=2, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def check(condition, description):
    if not condition:
        raise AssertionError(description)


def run_case(q, guard_module, name, *, phase=None, fault=None, raw=False,
             journal_failure=None, nonnative=False, swallowed=False):
    record = dict(name=name, phase=phase, fault=fault, hardware=False)
    durable = []
    phase_addresses = dict(inventory=0x1000, regime=0x1100, sync=0x1200, measurement=0x1300)
    injected = False

    def save():
        state = record.get('control_guard', {})
        if journal_failure == 'before' and state.get('native_inflight'):
            raise OSError('injected receipt failure before native dispatch')
        if journal_failure == 'after' and any(x['event'] == 'native_acknowledged'
                                              for x in state.get('events', [])):
            raise OSError('injected receipt failure after native acknowledgment')
        durable.append(json.loads(json.dumps(record)))

    class ReplayTransport:
        def __init__(self):
            self.queue = bytearray()
            self.trace = []
            self.closed = 0
            self.memory = {}
            self.read_fault = None

        def frame(self, command, data, status=0):
            prefix = struct.pack('<Ii24s', command, status, data.ljust(24, b'\0'))
            return prefix + struct.pack('<I', q.checksum(prefix))

        def close(self):
            self.closed += 1

        def write(self, data):
            nonlocal injected
            data = bytes(data)
            check(len(data) == 64, 'unexpected wire request size')
            check(q.checksum(data[:-4]) == struct.unpack('<I', data[-4:])[0], 'bad request checksum')
            command = struct.unpack_from('<I', data)[0]
            check(command == q.REQ_PROXY, 'only proxy frames are needed for this replay')
            opcode, *arguments = struct.unpack_from('<7Q', data, 4)
            address = arguments[0]
            self.trace.append(dict(operation='write', opcode=opcode, address=address))
            if opcode == q.Proxy.P_CALL:
                check(durable and durable[-1]['control_guard']['native_inflight'],
                      'native frame preceded its durable dispatch journal')
            active_fault = None
            if not injected and fault and ((nonnative and opcode == q.Proxy.P_READ32)
                                           or address == phase_addresses.get(phase)):
                injected = True
                active_fault = fault
            if active_fault == 'write_loss':
                raise q.ProxyTimeout('injected uncertain transport write')
            if active_fault == 'lost_ack':
                self.read_fault = q.ProxyTimeout('injected lost completion')
                return
            if active_fault == 'interrupt':
                self.read_fault = KeyboardInterrupt('injected interrupt during completion')
                return
            value = 0x5c if opcode == q.Proxy.P_CALL else self.memory.get(address, 0)
            if opcode == q.Proxy.P_READ32 and address == 0x2000:
                value = 0xfffffffb     # SCMI OUT_OF_RANGE data, not proxy failure
            if opcode == q.Proxy.P_WRITE32:
                self.memory[address] = arguments[1]
            echo = opcode + 1 if active_fault == 'bad_echo' else opcode
            status = -1 if active_fault == 'remote_error' else 0
            reply = self.frame(q.REQ_PROXY, struct.pack('<QqQ', echo, status, value))
            if active_fault == 'bad_checksum':
                reply = reply[:-1] + bytes([reply[-1] ^ 1])
            if active_fault in ('exception', 'boot'):
                reason = q.START_EXCEPTION if active_fault == 'exception' else q.START_BOOT
                reply = self.frame(q.REQ_BOOT, struct.pack('<IIQ', reason, 2, 0x9999))
            if active_fault == 'truncated':
                reply = reply[:12]
            self.queue.extend(reply)

        def read(self, size, timeout):
            self.trace.append(dict(operation='read', size=size))
            if self.read_fault:
                failure, self.read_fault = self.read_fault, None
                raise failure
            if len(self.queue) < size:
                raise q.ProxyTimeout('injected truncated completion')
            data = bytes(self.queue[:size])
            del self.queue[:size]
            return data

    class ReplayProxy(q.Proxy):
        def swallow_then_write(self):
            try:
                self.read32(0x7000)
            except BaseException:
                pass
            self.write32(0x7000, 1)

    transport = ReplayTransport()
    link = q.Link('offline-replay-only', transport=transport)
    proxy = ReplayProxy(link)
    guard = guard_module.ControlGuard(proxy, record, save)
    p = guard.proxy
    cached_read = p.read32

    class Scratch:
        def __init__(self):
            self.restore_calls = 0

        def restore(self):
            self.restore_calls += 1
            p.write32(0x3000, 0)
            return dict(restored=True)

    scratch = Scratch()
    try:
        if swallowed:
            p.swallow_then_write()
        elif nonnative:
            p.read32(0x7000)
        else:
            for label, address in phase_addresses.items():
                record['current_phase'] = label
                if raw:
                    payload = struct.pack('<7Q', q.Proxy.P_CALL, address, 0, 0, 0, 0, 0)
                    p.link.proxyreq(payload)
                else:
                    p.call(address)
            p.write32(0x4000, 8)
            check(p.read32(0x4000) == 8, 'write/read round trip changed')
            check(p.read32(0x2000) == 0xfffffffb, 'SCMI status data was lost')
            check(not guard.frozen, 'definite SCMI negative status froze the transport')
        check(not fault and not journal_failure, 'injected failure did not stop the lifecycle')
        record['scratch'] = guard.restore_scratch(scratch)
        check(scratch.restore_calls == 1, 'healthy scratch restore was omitted')
        record['outcome'] = 'healthy'
    except BaseException as exc:
        if not fault and not journal_failure:
            raise
        check(guard.frozen, 'failure did not freeze session')
        record['raised'] = f'{type(exc).__name__}: {exc}'
        count = len(transport.trace)
        blocked = []
        attempts = dict(
            read=lambda: p.read32(0), write=lambda: p.write32(0, 1),
            cached_read=lambda: cached_read(0), native=lambda: p.call(0),
            request=lambda: p.request(q.Proxy.P_NOP),
            raw_proxy_request=lambda: proxy.request(q.Proxy.P_NOP),
            raw_proxy_method=lambda: proxy.read32(0),
            link_nop=lambda: p.link.nop(),
            link_request=lambda: p.link.proxyreq(bytes(56)),
            transport_write=lambda: p.link.transport.write(bytes(64)),
            transport_read=lambda: p.link.transport.read(1, 0.01),
            serror_cleanup=lambda: p.serror_strict(False),
            serror_diagnostic=lambda: p.serror_state())
        for label, operation in attempts.items():
            try:
                operation()
            except guard_module.Frozen:
                blocked.append(label)
            else:
                raise AssertionError(f'{label} was not blocked')
        record['scratch'] = guard.restore_scratch(scratch)
        check(scratch.restore_calls == 0, 'frozen scratch restore attempted target I/O')
        check(len(transport.trace) == count, 'target I/O occurred after freeze')
        if journal_failure == 'before':
            check(not transport.trace, 'native dispatch occurred after journal save failed')
        if fault in ('exception', 'boot'):
            writes = [x for x in transport.trace if x['operation'] == 'write']
            check(all(x['opcode'] == q.Proxy.P_CALL for x in writes),
                  'unexpected exception callback issued reads or auto-resume')
        record.update(outcome='frozen_as_required', blocked=blocked,
                      post_freeze_target_operations=0)
    finally:
        p.link.close()
        guard.close()
    check(transport.closed == 1, 'local close did not remain available/idempotent')
    record['wire_trace'] = transport.trace
    record['durable_snapshots'] = len(durable)
    record['local_close_count'] = transport.closed
    return record


class DatagramTarget:
    """A q1n1 target behind a datagram link (udplink), for MEMWRITE and NOP:
    it scans for a request, checks request and data checksums, and answers
    ST_XFRERR for a write whose data does not check out. The transport carries
    1400-byte datagrams and loses the ones a case names. Nothing is opened."""

    datagrams = True

    def __init__(self, q, drop):
        self.q, self.drop = q, set(drop)
        self.sent = 0
        self.stream, self.out = bytearray(), bytearray()
        self.memory = {}
        self.trace, self.closed, self.xfrerr = [], 0, 0

    def close(self):
        self.closed += 1

    def write(self, data):
        q = self.q
        data = bytes(data)
        for at in range(0, len(data), 1400):
            self.sent += 1
            if self.sent in self.drop:
                self.trace.append(dict(operation='dropped', datagram=self.sent))
                continue
            self.stream += data[at:at + 1400]
        self.trace.append(dict(operation='write', bytes=len(data)))
        while True:
            at = self.stream.find(b'\xff\x55\xaa')
            if at < 0:
                del self.stream[:max(0, len(self.stream) - 2)]
                return
            del self.stream[:at]
            if len(self.stream) < 64:
                return
            request = bytes(self.stream[:64])
            kind = struct.unpack_from('<I', request)[0]
            if q.checksum(request[:60]) != struct.unpack_from('<I', request, 60)[0]:
                del self.stream[:3]
                continue
            if kind == q.REQ_MEMWRITE:
                address, size, expected = struct.unpack_from('<QQI', request, 4)
                if len(self.stream) < 64 + size:
                    return
                payload = bytes(self.stream[64:64 + size])
                del self.stream[:64 + size]
                status = 0
                if q.checksum(payload) == expected:
                    self.memory[address] = payload
                else:
                    status = q.ST_XFRERR
                    self.xfrerr += 1
                self.reply(kind, status, struct.pack('<I', expected))
            elif kind == q.REQ_NOP:
                del self.stream[:64]
                self.reply(kind, 0, struct.pack('<Q', 0))
            else:
                raise AssertionError(f'unexpected request {kind:#x}')

    def reply(self, kind, status, data):
        prefix = struct.pack('<Ii24s', kind, status, data.ljust(24, b'\0'))
        self.out += prefix + struct.pack('<I', self.q.checksum(prefix))

    def read(self, size, timeout):
        self.trace.append(dict(operation='read', size=size))
        if len(self.out) < size:
            raise TimeoutError(f'expected {size} bytes, got {len(self.out)}')
        data = bytes(self.out[:size])
        del self.out[:size]
        return data

    def drain(self, quiet, limit):
        kept = bytes(self.out)
        self.out.clear()
        return kept


def run_loss_case(q, guard_module, name, *, retries, drop, expect):
    """A memory write over a lossy datagram link: the guard must let the
    Link's own recovery through (journaled) and still freeze when it fails."""
    record = dict(name=name, retries=retries, dropped=sorted(drop), hardware=False)
    snapshots = []
    target = DatagramTarget(q, drop)
    link = q.Link('offline-replay-only', transport=target)
    link.loss_retries = retries
    proxy = q.Proxy(link)
    proxy.stage_features = lambda: 0
    guard = guard_module.ControlGuard(proxy, record, lambda: snapshots.append(json.loads(json.dumps(record))))
    p = guard.proxy
    data = bytes((k * 7 + 3) & 0xff for k in range(6000))
    try:
        p.link.writemem(0x8000, data)
        record['outcome'] = 'written'
    except BaseException as exc:
        record['raised'] = f'{type(exc).__name__}: {exc}'
        record['outcome'] = 'frozen' if guard.frozen else 'raised'
    events = [e['event'] for e in record['control_guard']['events']]
    record['events'] = events
    check(record['outcome'] == expect, f'{name}: {record["outcome"]}, expected {expect}')
    if expect == 'written':
        check(not guard.frozen and target.memory.get(0x8000) == data, f'{name}: write not recovered intact')
        check('transport_loss' in events and 'transport_loss_recovered' in events,
              f'{name}: recovery was not journaled')
        check(any('transport_loss' in [e['event'] for e in snap['control_guard']['events']]
                  for snap in snapshots), f'{name}: loss not saved before the recovery went on')
        p.link.writemem(0x9000, data[:100])            # the session goes on
        check(target.memory.get(0x9000) == data[:100], f'{name}: session did not continue')
    else:
        check(guard.frozen, f'{name}: a failed write did not freeze the session')
        count = len(target.trace)
        for attempt in (lambda: p.link.writemem(0, b'x'), lambda: p.link.transport.read(1, 0.01)):
            try:
                attempt()
            except guard_module.Frozen:
                pass
            else:
                raise AssertionError(f'{name}: I/O after freeze was not blocked')
        check(len(target.trace) == count, f'{name}: target I/O occurred after freeze')
    guard.close()
    record['wire_trace'] = target.trace
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output already exists; retain prior receipts')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    paths = dict(guard=ROOT / 'tools/a16-control-guard.py',
                 replay=Path(__file__).resolve(),
                 q1n1_proxy=ROOT.parent / 'q1n1/tools/q1n1proxy.py')
    q = module('a16_replay_q1n1proxy', paths['q1n1_proxy'])
    guard_module = module('a16_replay_control_guard', paths['guard'])
    result = dict(schema=1, kind='offline-control-guard-wire-replay', hardware=False,
                  started_unix=time.time(), status='RUNNING', cases=[],
                  sources={k: dict(path=str(v), sha256=hashlib.sha256(v.read_bytes()).hexdigest())
                           for k, v in paths.items()})
    save_json(args.output, result)
    try:
        cases = [('healthy', {})]
        faults = ('write_loss', 'lost_ack', 'interrupt', 'bad_echo', 'remote_error',
                  'bad_checksum', 'exception', 'boot', 'truncated')
        for phase in ('inventory', 'regime', 'sync', 'measurement'):
            for fault in faults:
                cases.append((f'{phase}-{fault}', dict(phase=phase, fault=fault)))
        cases += [('raw-native-healthy', dict(raw=True)),
                  ('raw-native-bad-echo', dict(raw=True, phase='inventory', fault='bad_echo')),
                  ('raw-native-rejected', dict(raw=True, phase='inventory', fault='remote_error')),
                  ('journal-before', dict(journal_failure='before')),
                  ('journal-after', dict(journal_failure='after')),
                  ('nonnative-lost-ack', dict(nonnative=True, fault='lost_ack')),
                  ('swallowed-inner-failure', dict(nonnative=True, swallowed=True, fault='lost_ack'))]
        for name, options in cases:
            result['current_case'] = name
            save_json(args.output, result)
            result['cases'].append(run_case(q, guard_module, name, **options))
            save_json(args.output, result)
        # Datagram loss in a 6000-byte memory write. Datagrams: the request (1)
        # and its data (2-6); after a loss the resync's filler (7-11) and NOP
        # (12); then the repeated request (13) and data (14-18).
        loss_cases = [
            ('udp-write-loss-recovered', dict(retries=1, drop={3}, expect='written')),
            ('udp-write-loss-retries-off', dict(retries=0, drop={3}, expect='frozen')),
            ('udp-write-loss-every-attempt', dict(retries=1, drop={3, 15}, expect='frozen')),
            ('udp-write-loss-resync-nop-lost', dict(retries=1, drop={3, 12}, expect='frozen'))]
        for name, options in loss_cases:
            result['current_case'] = name
            save_json(args.output, result)
            result['cases'].append(run_loss_case(q, guard_module, name, **options))
            save_json(args.output, result)
        result.update(status='PASS', cases_passed=len(result['cases']), finished_unix=time.time())
        result.pop('current_case', None)
    except BaseException as exc:
        result.update(status='FAIL', error=f'{type(exc).__name__}: {exc}', finished_unix=time.time())
        save_json(args.output, result)
        raise
    save_json(args.output, result)
    print(json.dumps(dict(status=result['status'], cases=result['cases_passed'],
                          artifact=str(args.output.resolve()), hardware=False)))


if __name__ == '__main__':
    main()
