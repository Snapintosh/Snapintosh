#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fail-closed session boundary for bounded A16 control experiments.

Use ControlGuard(proxy, record, save).proxy from the beginning of admission.
The save callback must durably save record and must never access the target.
The guard owns this proxy/link until close; do not retain or reuse raw handles.
This is a single-owner session guard, not a reconnect or recovery mechanism.
The one recovery it lets through is the q1n1 Link's own, inside a memory
write on a datagram link (see _recoverable_write).

Failure inventory and contract: docs/A16-CPU-POLICY-REVIEW-20261018.md.
"""

import functools
import hashlib
import struct
import time


class Frozen(RuntimeError):
    """Target I/O is prohibited for this session."""


def _timed_out(exc):
    """A transport timeout as the q1n1 Link raises it (TimeoutError from a
    datagram transport, or its ProxyTimeout), matched by name so the guard
    keeps no import of the proxy module."""
    return not isinstance(exc, Frozen) and any(
        c.__name__ in ('TimeoutError', 'ProxyTimeout') for c in type(exc).__mro__)


def _summary(value):
    if isinstance(value, (bytes, bytearray, memoryview)):
        return dict(bytes=len(value), sha256=hashlib.sha256(value).hexdigest())
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return type(value).__name__


class _Facade:
    def __init__(self, guard, obj, kind):
        object.__setattr__(self, '_guard', guard)
        object.__setattr__(self, '_obj', obj)
        object.__setattr__(self, '_kind', kind)

    def __getattr__(self, name):
        value = getattr(self._obj, name)
        if not callable(value):
            return value

        @functools.wraps(value)
        def guarded(*args, **kwargs):
            return self._guard._invoke(self._kind, name, value, args, kwargs)
        return guarded

    def __setattr__(self, name, value):
        self._guard._require_open()
        if name in ('request', 'link', 'transport', 'exception_handler', 'handle_boot'):
            raise ValueError(f'cannot replace guarded {name}')
        setattr(self._obj, name, value)


class ControlGuard:
    """Guard proxy methods, raw requests, nested link I/O, and native calls.

    Any exception from a target-facing operation freezes the session. Definite
    SCMI status errors are decoded above this layer and need not freeze it.
    A transport timeout inside link.writemem, when the Link recovers lost
    datagrams itself, is journaled instead; the write still freezes the
    session if it fails as a whole.
    A returned P_CALL acknowledges execution only; the conductor must validate
    its expected return/report and call freeze() on ambiguous results.
    """

    def __init__(self, proxy, record, save):
        if 'control_guard' in record:
            raise ValueError('a control guard receipt cannot be resumed or reused')
        self._record, self._save = record, save
        self._raw_proxy, self._raw_link = proxy, proxy.link
        self._raw_request = proxy.request
        self._raw_close = self._raw_link.close
        self._p_call = proxy.P_CALL
        self._state = record['control_guard'] = dict(
            schema=1, frozen=False, reason=None, closed=False,
            native_inflight=None, native_calls=0, operations=0, events=[])
        self._frozen = False
        self._reason = None
        self._closed = False
        self._raw_transport = getattr(self._raw_link, 'transport', None)
        self._write_depth = 0          # nesting of recoverable link.writemem calls

        # Internal helpers are bound to the raw proxy/link. Guard their lower
        # boundary too, so catching an exception inside a helper cannot revive I/O.
        transport = getattr(self._raw_link, 'transport', None)
        if transport is not None:
            self._raw_link.transport = _Facade(self, transport, 'transport')
        proxy.link = _Facade(self, self._raw_link, 'link')
        proxy.request = self._request
        self._raw_link.exception_handler = self._exception
        if callable(getattr(self._raw_link, 'handle_boot', None)):
            self._raw_link.handle_boot = self._unexpected_boot
        self.proxy = _Facade(self, proxy, 'proxy')
        self._persist()

    @property
    def frozen(self):
        return self._frozen

    @property
    def reason(self):
        return self._reason

    def _event(self, event, **fields):
        item = dict(event=event, monotonic_ns=time.monotonic_ns(), **fields)
        self._state['events'].append(item)
        return item

    def _persist(self):
        try:
            self._save()
        except BaseException as exc:
            # A missing journal must never be followed by a target mutation.
            self._frozen = self._state['frozen'] = True
            self._reason = self._state['reason'] = f'journal save failed: {type(exc).__name__}: {exc}'
            self._state['journal_error'] = self._reason
            raise

    def _require_open(self):
        if self._frozen or self._closed:
            raise Frozen(self._reason or 'session is closed')

    def freeze(self, reason):
        """Irreversibly prohibit I/O; only local receipt work and close remain."""
        if not self._frozen:
            self._frozen = self._state['frozen'] = True
            self._reason = self._state['reason'] = str(reason)
            self._event('frozen', reason=self._reason)
        try:
            self._save()
        except BaseException as exc:
            self._state['journal_error'] = f'{type(exc).__name__}: {exc}'

    def _exception(self, code, info):
        self.freeze(f'target exception callback code={code:#x} info={info:#x}')
        raise Frozen(self.reason)

    def _unexpected_boot(self, data):
        fields = {}
        if len(data) >= 16:
            reason, code, info = struct.unpack_from('<IIQ', data)
            fields = dict(boot_reason=reason, code=code, info=hex(info))
        self._event('unexpected_boot', **fields)
        self.freeze('unexpected boot/exception message during control session')
        raise Frozen(self.reason)

    def _native(self, label, args, kwargs, operation):
        self._require_open()
        if self._state['native_inflight'] is not None:
            self.freeze('nested native call while another native call is unresolved')
            raise Frozen(self.reason)
        if kwargs.get('no_reply'):
            self.freeze('native call without a reply is forbidden')
            raise Frozen(self.reason)
        self._state['native_calls'] += 1
        event = self._event('native_dispatch_pending', operation=label,
                            arguments=[_summary(x) for x in args],
                            options={k: _summary(v) for k, v in kwargs.items()})
        self._state['native_inflight'] = dict(event)
        self._persist()                  # before any target dispatch
        try:
            result = operation()
            self._require_open()
            if result is None:
                raise RuntimeError('native call returned without a completion value')
            if label == 'link.proxyreq(P_CALL)':
                if not isinstance(result, bytes) or len(result) != 24:
                    raise RuntimeError('malformed raw native completion')
                echo, status, _ = struct.unpack('<QqQ', result)
                if echo != self._p_call or status:
                    raise RuntimeError(f'invalid raw native completion: echo={echo:#x} status={status}')
        except BaseException as exc:
            self.freeze(f'{label} completion unknown: {type(exc).__name__}: {exc}')
            raise
        self._event('native_acknowledged', operation=label, result=_summary(result))
        self._state['native_inflight'] = None
        self._persist()
        return result

    def _request(self, opcode, *args, **kwargs):
        self._require_open()
        try:
            if opcode == self._p_call:
                return self._native('proxy.request(P_CALL)', args, kwargs,
                                    lambda: self._raw_request(opcode, *args, **kwargs))
            return self._raw_request(opcode, *args, **kwargs)
        except BaseException as exc:
            self.freeze(f'proxy.request({opcode:#x}) failed: {type(exc).__name__}: {exc}')
            raise

    def _recoverable_write(self, kind, name):
        """Whether this call is a memory write the q1n1 Link may recover itself.

        On a datagram link (udplink) one lost datagram leaves the target waiting
        for write data and the host waiting for a reply; with Q1N1_UDP_RETRIES
        the Link then resynchronises (filler to finish the target's read, a
        drain, and a NOP round trip that proves the stream back in step) and
        repeats the write. A memory write is idempotent, so its inner transport
        timeouts are not ambiguous target state. Never a P_ request, never a
        read (a repeated MMIO read can have side effects), never while a native
        call is unresolved."""
        return (kind == 'link' and name == 'writemem' and self._state['native_inflight'] is None
                and getattr(self._raw_link, 'loss_retries', 0) > 0
                and getattr(self._raw_transport, 'datagrams', False))

    def _invoke(self, kind, name, operation, args, kwargs):
        if kind in ('link', 'transport') and name == 'close':
            # The link close is a host resource release, not a target command.
            if kind == 'link':
                return self.close()
            return operation(*args, **kwargs)
        self._require_open()
        self._state['operations'] += 1
        label = f'{kind}.{name}'
        recoverable = self._recoverable_write(kind, name)
        if recoverable:
            self._write_depth += 1
            losses = self._state.get('transport_losses', 0)
        try:
            if kind == 'link' and name == 'readmem':
                # Do not allow the link helper to retry a corrupted payload.
                kwargs = dict(kwargs, attempts=1)
            if kind == 'link' and name == 'proxyreq' and args:
                payload = args[0]
                if len(payload) >= 8 and int.from_bytes(payload[:8], 'little') == self._p_call:
                    if self._state['native_inflight'] is None:
                        return self._native('link.proxyreq(P_CALL)', args, kwargs,
                                            lambda: operation(*args, **kwargs))
            if kind == 'transport' and name == 'write' and args:
                frame = args[0]
                if (len(frame) >= 12 and int.from_bytes(frame[:4], 'little') == 0x01AA55FF
                        and int.from_bytes(frame[4:12], 'little') == self._p_call
                        and self._state['native_inflight'] is None):
                    raise RuntimeError('split raw native request bypasses journaled completion')
            result = operation(*args, **kwargs)
            self._require_open()         # also catches swallowed inner failures
            if recoverable and self._state.get('transport_losses', 0) != losses:
                self._event('transport_loss_recovered', operation=label,
                            losses=self._state['transport_losses'] - losses)
                self._persist()
            return result
        except BaseException as exc:
            if kind == 'transport' and self._write_depth and _timed_out(exc):
                # Inside a recoverable write: the Link resynchronises next.
                self._state['transport_losses'] = self._state.get('transport_losses', 0) + 1
                self._event('transport_loss', operation=label, error=f'{type(exc).__name__}: {exc}')
                self._persist()
                raise
            self.freeze(f'{label} failed: {type(exc).__name__}: {exc}')
            raise
        finally:
            if recoverable:
                self._write_depth -= 1

    def restore_scratch(self, scratch):
        """Return a host-only skipped record if native/transport state is unknown."""
        if self.frozen or self._closed:
            result = dict(restored=False, skipped=True,
                          reason=self.reason or 'session is closed')
            self._event('scratch_restore_skipped', **result)
            try:
                self._save()
            except BaseException as exc:
                self._state['journal_error'] = f'{type(exc).__name__}: {exc}'
            return result
        try:
            return scratch.restore()
        except BaseException as exc:
            self.freeze(f'scratch restore failed: {type(exc).__name__}: {exc}')
            raise

    def close(self):
        if self._closed:
            return
        self._closed = self._state['closed'] = True
        try:
            self._raw_close()
        finally:
            self._event('host_link_closed')
            try:
                self._save()
            except BaseException as exc:
                self._state['journal_error'] = f'{type(exc).__name__}: {exc}'
