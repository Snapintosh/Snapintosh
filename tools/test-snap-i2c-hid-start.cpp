// SPDX-License-Identifier: MIT
// The real SnapI2CHIDBus (drivers/snap-i2c-hid/src/SnapI2CHID.cpp) on the host, against the
// stand-ins in tools/test-snap-i2c-hid-standin.h and a GENI controller model behind the driver's
// MMIO hook (SNAP_I2C_HID_MMIO_READ/WRITE): one scenario per process, chosen by argv[1], run by
// tools/test-snap-i2c-hid-kext.py under ASan/UBSan.
//
// Failure inventory (docs/A16-INPUT-INSTALLED-20261017.md sections 2 and 10), driver side:
//   - a node without its address, descriptor register or window, a short window or one that
//     is not page aligned: start() fails and the driver performs no MMIO at all;
//   - firmware's state that the transport does not drive (another protocol, a busy engine,
//     unread FIFO data, a pending error, with firmware's interrupt enables): start() fails and
//     nothing is written or popped;
//   - a controller that never completes: the bus gives up after bounded retries (FAILED, no
//     timer left armed), writes only the tools' register set, never enables the engine's
//     interrupt, and stop() restores the lengths and enables it found;
//   - an engine someone else starts mid-run: the bus declares itself wedged and, from then on,
//     including stop(), performs no MMIO;
//   - a previous run's leftover after a panic and a chainload (M_IRQ_EN 0, our lengths): a
//     finished read nobody drained, a latched error, a read stalled on a full FIFO, an engine
//     that needs cancel: recovered (exactly the reported words discarded) and started; an
//     engine neither cancel nor abort stops, or leftover transmit words: refused, and after a
//     wedged refusal no further MMIO.
// Precision Touchpad (docs/A16-INPUT-PTP-20261020.md, failure modes F1, F2, F9, F10, F15, F16,
// F22), behind the driver's feature-report hook (SNAP_I2C_HID_FEATURE_GET/SET) and a model of the
// touchpad's features: the switch at publish decides the pointer service's identity (trackpad
// scroll keys only when armed, today's properties otherwise); report 4 goes to the engine and
// report 1 still to the mouse path; a re-initialisation re-applies the switch and ends the touch
// state; the keyboard bus sends no feature request at all.
#include "test-snap-i2c-hid-standin.h"
#include <array>
#include <set>
extern "C" {
#include "i2c-hid.h"
#include "hid-ptp.h"
#include "hid-mt2.h"
}

// ------------------------------------------------------------- feature model ----
struct Features {
    uint8_t mode = 0, selective = 3;
    bool refuse_write = false, ignore_mode = false, no_get = false;
    unsigned requests = 0, sets_by_id[256] = {};
};
static Features F;

static uint32_t feature_bytes(uint8_t id)
{
    switch (id) {
    case 2: case 3: case 5: case 7: return 2;
    case 8: return 257;
    case 11: return 129;
    case 12: return 34;
    case 13: case 14: return 5;
    default: return 0;
    }
}

static int harness_get_feature(struct i2c_hid_dev *, uint8_t id, uint8_t *buf, uint32_t cap, uint32_t *got)
{
    uint32_t n = feature_bytes(id);
    F.requests++;
    *got = 0;
    if (F.no_get || !n)
        return I2C_HID_R_EMPTY;
    if (n > cap)
        return I2C_HID_R_INVALID;
    memset(buf, 0, n);
    buf[0] = id;
    if (id == 2) buf[1] = 0x05;
    if (id == 3) buf[1] = F.mode;
    if (id == 5) buf[1] = F.selective;
    *got = n;
    return I2C_HID_R_OK;
}

static int harness_set_feature(struct i2c_hid_dev *, const uint8_t *r, uint32_t len)
{
    F.requests++;
    F.sets_by_id[r[0]]++;
    if (len != feature_bytes(r[0]))
        return I2C_HID_R_INVALID;
    if (F.refuse_write && r[0] == 3)
        return I2C_HID_R_BUS;
    if (r[0] == 3 && !F.ignore_mode)
        F.mode = r[1];
    if (r[0] == 5)
        F.selective = r[1] & 3u;
    return I2C_HID_R_OK;
}
#define SNAP_I2C_HID_FEATURE_GET(dev, id, buf, cap, got) harness_get_feature((dev), (id), (buf), (cap), (got))
#define SNAP_I2C_HID_FEATURE_SET(dev, report, len) harness_set_feature((dev), (report), (len))

Standin standin;
static OSBoolean booleanTrue;
OSBoolean *const kOSBooleanTrue = &booleanTrue;
static const IORegistryPlane servicePlane = {};
const IORegistryPlane *gIOServicePlane = &servicePlane;

#include "test-snap-i2c-hid-fixture.h"

// ---------------------------------------------------------------- controller model ----
struct Geni {
    uint32_t regs[0x1000 / 4];
    uint32_t irq_status = 0, irq_en = 0, tx_len = 0, rx_len = 0;
    unsigned rxn = 0, txn = 0, pending = 0;      // pending: words a stalled read still owes
    bool rx_last = false, active = false, cancel_works = true, abort_works = true;
    bool nack_commands = false;                   // commands complete at once with a NACK
    bool forbid = false;                          // any access from here is a failure
    unsigned reads = 0, writes = 0, pops = 0, underflows = 0, cancels = 0, aborts = 0, commands = 0;
    unsigned violations = 0;
    std::set<uint32_t> written;
};
static Geni G;

static void geni_reset()
{
    G = Geni();
    for (const auto &r : a16_ic20_registers)
        G.regs[r.offset / 4] = r.value;
    G.irq_status = G.regs[0x610 / 4];
    G.irq_en = G.regs[0x614 / 4];
    G.tx_len = G.regs[0x26c / 4];
    G.rx_len = G.regs[0x270 / 4];
}

static void geni_run()
{
    // A stalled read moves on as soon as the FIFO has room, and finishes.
    if (G.active && G.pending && G.rxn < 32) {
        unsigned n = G.pending < 32 - G.rxn ? G.pending : 32 - G.rxn;
        G.rxn += n;
        G.pending -= n;
        if (!G.pending) {
            G.active = false;
            G.rx_last = true;
            G.irq_status |= 1u | (1u << 27);      // DONE, RX_LAST
        }
    }
}

static uint32_t harness_read(volatile uint32_t *, uint32_t off)
{
    G.reads++;
    if (G.forbid) G.violations++;
    geni_run();
    switch (off) {
    case 0x040: return G.active ? 1u : 0u;
    case 0x610: return G.irq_status;
    case 0x614: return G.irq_en;
    case 0x26c: return G.tx_len;
    case 0x270: return G.rx_len;
    case 0x800: return G.txn;
    case 0x804: return G.rxn | (G.rx_last && G.rxn ? (1u << 31) : 0u);
    case 0x780:
        if (!G.rxn) {
            G.underflows++;
            G.irq_status |= 1u << 24;
            return 0xdeadbeef;
        }
        G.rxn--;
        G.pops++;
        return 0;
    default: return G.regs[off / 4];
    }
}

static void harness_write(volatile uint32_t *, uint32_t off, uint32_t v)
{
    G.writes++;
    if (G.forbid) G.violations++;
    G.written.insert(off);
    switch (off) {
    case 0x26c: G.tx_len = v; return;
    case 0x270: G.rx_len = v; return;
    case 0x614: G.irq_en = v; return;
    case 0x618: G.irq_status &= ~v; return;
    case 0x700: return;                                                // the engine sends what it is given
    case 0x600:
        G.commands++;
        if (G.active) { G.irq_status |= 1u << 2; return; }          // ILLEGAL_CMD
        G.txn = 0;                                                    // the engine takes its words
        if (G.nack_commands) G.irq_status |= 1u | (1u << 10);        // DONE, NACK
        return;
    case 0x604:
        if (!G.active) return;
        if (v & (1u << 2)) { G.cancels++; if (G.cancel_works) { G.active = false; G.pending = 0; G.irq_status |= 1u << 4; } }
        if (v & (1u << 1)) { G.aborts++; if (G.abort_works) { G.active = false; G.pending = 0; G.irq_status |= 1u << 5; G.txn = 0; } }
        return;
    default:
        G.regs[off / 4] = v;
        return;
    }
}

#define SNAP_I2C_HID_MMIO_READ(base, offset) harness_read((base), (offset))
#define SNAP_I2C_HID_MMIO_WRITE(base, offset, value) harness_write((base), (offset), (value))
// The harness drives the bus's timer and thread call and reads its transport state directly.
#define private public
#define protected public
#include "../drivers/snap-i2c-hid/src/SnapI2CHID.cpp"
#undef protected
#undef private

// ---------------------------------------------------------------- harness ----
static int failures;
#define CHECK(c, what) do { if (!(c)) { printf("FAIL: %s\n", what); failures++; } } while (0)

static const std::set<uint32_t> kWritable = {0x26c, 0x270, 0x600, 0x604, 0x614, 0x618, 0x700};
static uint32_t window_storage[0x1000 / 4];

static void put(IOService *nub, const char *key, std::vector<uint32_t> cells)
{
    nub->properties[key] = OSData::withBytes(cells.data(), (unsigned)(4 * cells.size()));
}

static IOService *keyboard_nub(bool window = true, uint64_t pa = 0x70088c000ull, uint64_t len = 0x1000)
{
    IOService *nub = new IOService;
    put(nub, "snapintosh,hid-address", {0x15});
    put(nub, "snapintosh,hid-descriptor-reg", {1});
    put(nub, "snapintosh,hid-vendor-product", {0x0b05, 0x4b42});
    put(nub, "snapintosh,poll-us", {8000});
    put(nub, "snapintosh,irq-policy", {1});
    if (window) {
        IOMemoryMap *map = new IOMemoryMap;
        map->va = (IOVirtualAddress)window_storage;
        map->pa = pa;
        map->len = len;
        nub->windows.push_back(map);
    }
    return nub;
}

static bool only_tool_writes()
{
    for (uint32_t off : G.written)
        if (!kWritable.count(off)) {
            printf("  wrote 0x%03x\n", off);
            return false;
        }
    return true;
}

static bool logged(const char *text)
{
    bool found = standin.log.find(text) != std::string::npos;
    if (!found)
        printf("  log was: %s\n", standin.log.c_str());
    return found;
}

// Run the bus's timer and thread call until nothing is armed or the fake clock passes limit.
static void run(SnapI2CHIDBus *bus, uint64_t limit_ns)
{
    for (;;) {
        if (bus->fPublish && bus->fPublish->pending) {
            bus->fPublish->pending = false;
            bus->fPublish->func(bus->fPublish->param, nullptr);
            continue;
        }
        if (!bus->fTimer || !bus->fTimer->armed || standin.now_ns > limit_ns)
            return;
        bus->fTimer->armed = false;
        if (bus->fTimer->due_ns > standin.now_ns)
            standin.now_ns = bus->fTimer->due_ns;
        bus->fTimer->action(bus->fTimer->owner, bus->fTimer);
    }
}

static bool refuses(IOService *nub, const char *log)
{
    SnapI2CHIDBus *bus = new SnapI2CHIDBus;
    bool started = bus->start(nub);
    bool ok = logged(log);
    G.forbid = true;                          // whatever the refusal, nothing touches it after
    bus->release();
    return !started && ok && !standin.registered && !standin.timeouts_armed && !G.violations;
}

// A previous run's controller, as a panic and a chainload leave it: our policy and lengths.
static void own_leftover()
{
    geni_reset();
    G.irq_en = 0;
    G.tx_len = 2;
    G.rx_len = 64;
}

static void starts_after_recovery(unsigned words, unsigned cancels, unsigned aborts)
{
    IOService *nub = keyboard_nub();
    SnapI2CHIDBus *bus = new SnapI2CHIDBus;
    CHECK(bus->start(nub), "a previous run's leftover is recovered and the bus starts");
    CHECK(logged("recovered a previous run's controller state"), "and says so with the registers found");
    CHECK(G.pops == words && G.underflows == 0, "exactly the reported receive words are discarded");
    CHECK(G.cancels == cancels && G.aborts == aborts, "cancel and abort only as needed");
    CHECK(!G.active && G.rxn == 0 && G.txn == 0 && !(G.irq_status & 0x3300360Eu), "idle, empty, no error");
    CHECK(G.irq_en == 0 && only_tool_writes(), "only the tools' registers, enables still 0");
    CHECK(standin.registered == 1 && bus->fTimer->armed, "the bus registers and arms its first step");
    unsigned commands = G.commands;
    run(bus, standin.now_ns + 50000000ull);
    CHECK(G.commands > commands, "and its first step reaches the device");
    bus->stop(nub);
    bus->release();
}

// ------------------------------------------------------------ touchpad helpers ----
// Report 4 of the A16 touchpad (the transport test's encoder): five 40-bit fingers, Scan Time at
// bit 200, Contact Count at 216, Button 1 at 224.
struct Touch { uint8_t conf, tip, id; uint16_t x, y; };
static unsigned harness_scan = 100;
static void feed(SnapI2CHIDPointer *ptr, const std::vector<Touch> &c, unsigned button = 0)
{
    uint8_t r[50] = {4};
    for (size_t i = 0; i < c.size() && i < 5; i++) {
        uint8_t *f = r + 1 + 5 * i;
        f[0] = (uint8_t)((c[i].conf ? 1 : 0) | (c[i].tip ? 2 : 0) | (c[i].id << 4));
        f[1] = (uint8_t)c[i].x; f[2] = (uint8_t)(c[i].x >> 8);
        f[3] = (uint8_t)c[i].y; f[4] = (uint8_t)(c[i].y >> 8);
    }
    harness_scan += 80;
    r[26] = (uint8_t)harness_scan; r[27] = (uint8_t)(harness_scan >> 8);
    r[28] = (uint8_t)c.size();
    r[29] = (uint8_t)(button & 1);
    standin.now_ns += 8000000u;
    ptr->handleReport(r, sizeof(r));
}

static OSObject *prop(IORegistryEntry *e, const char *key) { return e->getProperty(key); }
static uint64_t number(IORegistryEntry *e, const char *key)
{
    OSNumber *n = dynamic_cast<OSNumber *>(prop(e, key));
    return n ? n->v : ~0ull;
}
static std::string string_prop(IORegistryEntry *e, const char *key)
{
    OSString *s = dynamic_cast<OSString *>(prop(e, key));
    return s ? s->s : "";
}
static bool trackpad_identity(IORegistryEntry *e)
{
    OSArray *curves = dynamic_cast<OSArray *>(prop(e, "HIDScrollAccelCurves"));
    return string_prop(e, "HIDScrollAccelerationType") == "HIDTrackpadScrollAcceleration" &&
           number(e, "HIDScrollResolution") == (400u << 16) && number(e, "HIDTrackpadScrollAcceleration") == 20480 &&
           curves && curves->getCount() == 10 && !prop(e, "HIDPointerAccelerationType") &&
           !prop(e, "HIDPointerResolution");
}
static bool todays_identity(IORegistryEntry *e)
{
    return e->properties.size() == 2 && prop(e, "Built-In") == kOSBooleanTrue && prop(e, "HIDDefaultBehavior");
}

// A started bus whose transport is READY with the given descriptors, as step() leaves it before publish.
static SnapI2CHIDBus *ready_bus(const uint8_t *hid_desc, const uint8_t *rdesc, uint32_t len)
{
    IOService *nub = keyboard_nub();
    SnapI2CHIDBus *bus = new SnapI2CHIDBus;
    CHECK(bus->start(nub), "the bus starts");
    struct i2c_hid_dev *d = bus->fDev;
    CHECK(i2c_hid_parse_desc(hid_desc, 30, &d->desc) == I2C_HID_DESC_OK, "its HID descriptor parses");
    memcpy(d->rdesc, rdesc, len);
    d->rdesc_len = len;
    CHECK(hid_rdesc_parse(d->rdesc, len, &d->rinfo) == HID_RDESC_OK, "and its report descriptor");
    d->have_desc = d->have_rdesc = 1;
    d->state = I2C_HID_S_READY;
    bus->fTimer->armed = false;
    return bus;
}

#if SNAP_I2C_HID_FNKEYS
// ------------------------------------------------------------- Fn-key layer ----
// Built with -DSNAP_I2C_HID_FNKEYS=1 (and hid-keyboard.o with it): the layer is off without the boot-arg
// snap_i2c_fnkeys, and the keyboard is then exactly today's; with it, report 90 becomes macOS's usages, the raw log
// names the F-row and hotkeys but never a character key and holds to its rate limit, report 90 stays ours while an
// event driver holds the raw device, a refused boot-arg leaves the layer off and says why, and the bus names inputs
// the transport refused only on the keyboard and only with the raw log.
static SnapI2CHIDBus *fn_bus(bool set, uint32_t flags)
{
    standin.boot_args.clear();
    if (set)
        standin.boot_args["snap_i2c_fnkeys"] = flags;
    SnapI2CHIDBus *kb = ready_bus(a16_eckb_hid_desc, a16_eckb_report_desc, sizeof(a16_eckb_report_desc));
    kb->publish();
    CHECK(kb->fKeyboard, "the keyboard service runs");
    return kb;
}
static void fn_report(SnapI2CHIDBus *kb, std::vector<uint8_t> r)
{
    standin.now_ns += 8000000u;
    kb->fKeyboard->handleReport(r.data(), (uint32_t)r.size());
}
static void fn_vendor(SnapI2CHIDBus *kb, uint8_t code) { fn_report(kb, {0x5a, code, 0, 0, 0, 0}); }
static void fn_keys(SnapI2CHIDBus *kb, uint8_t mods, uint8_t key) { fn_report(kb, {0x36, mods, 0, key, 0, 0, 0, 0, 0}); }
static void fn_consumer(SnapI2CHIDBus *kb, uint16_t u) { fn_report(kb, {0x37, (uint8_t)u, (uint8_t)(u >> 8)}); }
static bool fn_events(size_t from, const std::vector<std::array<uint32_t, 3>> &want)
{
    bool same = standin.key_events.size() == from + want.size();
    for (size_t i = 0; same && i < want.size(); i++) {
        const auto &e = standin.key_events[from + i];
        same = e.page == want[i][0] && e.usage == want[i][1] && e.value == want[i][2];
    }
    if (!same)
        for (size_t i = from; i < standin.key_events.size(); i++)
            printf("  event %zu: 0x%x/0x%x %u\n", i, standin.key_events[i].page, standin.key_events[i].usage,
                   standin.key_events[i].value);
    return same;
}
static size_t occurrences(const char *text)
{
    size_t n = 0;
    for (size_t at = standin.log.find(text); at != std::string::npos; at = standin.log.find(text, at + 1))
        n++;
    return n;
}
static void fn_done(SnapI2CHIDBus *kb)
{
    kb->stop(kb->fProvider);
    kb->release();
}

static bool fnkeys_scenario(const std::string &s)
{
    if (s == "fnkeys-off") {
        const struct { bool set; uint32_t flags; const char *log; } cases[] = {
            {false, 0, "fn keys: off (no snap_i2c_fnkeys boot-arg)"}, {true, 0, "fn keys: off (snap_i2c_fnkeys 0x0)"},
            {true, 0x10, "fn keys: off (snap_i2c_fnkeys 0x10)"}};
        for (const auto &c : cases) {
            standin.log.clear();
            standin.key_events.clear();
            SnapI2CHIDBus *kb = fn_bus(c.set, c.flags);
            CHECK(kb->fKeyboard->fFn.flags == 0 && logged(c.log), "the layer is off, and says so");
            fn_vendor(kb, 0x10); fn_vendor(kb, 0);
            fn_consumer(kb, 0x70); fn_consumer(kb, 0);
            fn_keys(kb, 0, 0x3e); fn_keys(kb, 0, 0);
            CHECK(fn_events(0, {{12, 0x70, 1}, {12, 0x70, 0}, {7, 0x3e, 1}, {7, 0x3e, 0}}),
                  "report 90 dispatches nothing, reports 55 and 54 as without the layer");
            CHECK(standin.log.find("fn keys: report") == std::string::npos, "and nothing is raw-logged");
            fn_done(kb);
        }
    } else if (s == "fnkeys-translate") {
        SnapI2CHIDBus *kb = fn_bus(true, 0x1);
        CHECK(logged("fn keys: snap_i2c_fnkeys 0x1: translate on, raw log off, host Fn-lock off; brightness down "
                     "0x00ff/0x0005, up 0x00ff/0x0004; input report 90 6 bytes in the descriptor"),
              "the start line names the flags, the brightness usages and the descriptor's report 90");
        fn_vendor(kb, 0x10); fn_vendor(kb, 0);
        fn_vendor(kb, 0x20); fn_vendor(kb, 0);
        fn_vendor(kb, 0x7c); fn_vendor(kb, 0);
        fn_vendor(kb, 0x86); fn_vendor(kb, 0);                  // MyASUS: no macOS usage
        fn_consumer(kb, 0x6f); fn_consumer(kb, 0xe9); fn_consumer(kb, 0);
        fn_keys(kb, 0, 0x3e); fn_keys(kb, 0, 0);
        CHECK(fn_events(0, {{0xff, 5, 1}, {0xff, 5, 0}, {0xff, 4, 1}, {0xff, 4, 0}, {1, 0xa9, 1}, {1, 0xa9, 0},
                            {0xff, 4, 1}, {0xff, 4, 0}, {12, 0xe9, 1}, {12, 0xe9, 0}, {7, 0x3e, 1}, {7, 0x3e, 0}}),
              "hotkeys and report 55's brightness as macOS's usages, F5 as F5");
        CHECK(logged("keyboard dispatched 1 key transitions from 1 reports"), "progress is still counted");
        CHECK(standin.log.find("fn keys: report") == std::string::npos && standin.log.find("0x3e") == std::string::npos,
              "no raw log without its bit, and no key usage in the log");
        fn_vendor(kb, 0x20);
        size_t at = standin.key_events.size();
        kb->stop(kb->fProvider);
        CHECK(fn_events(at, {{0xff, 4, 0}}), "stop releases a held hotkey as what it was dispatched as");
        kb->release();
    } else if (s == "fnkeys-raw-log") {
        SnapI2CHIDBus *kb = fn_bus(true, 0x3);
        fn_vendor(kb, 0x10); fn_vendor(kb, 0);
        fn_vendor(kb, 0x6b); fn_vendor(kb, 0);
        fn_keys(kb, 0, 0x3e); fn_keys(kb, 0, 0);
        fn_consumer(kb, 0xe9); fn_consumer(kb, 0);
        fn_keys(kb, 0x0a, 0x72); fn_keys(kb, 0, 0);
        fn_keys(kb, 0x08, 0x13); fn_keys(kb, 0, 0);
        fn_report(kb, {0x07, 1, 2, 3, 4});
        CHECK(logged("fn keys: report 90 [5a 10 00 00 00 00]: code 0x10 down -> 0x00ff/0x0005") &&
              logged("fn keys: report 90 [5a 00 00 00 00 00]: code 0x10 up -> 0x00ff/0x0005"),
              "report 90's bytes and what each code became");
        CHECK(logged("fn keys: report 90 [5a 6b 00 00 00 00]: code 0x6b down -> nothing"), "an unmapped code is named");
        CHECK(logged("fn keys: report 54 key 0x3e down, modifiers 0x00 -> 0x0007/0x003e"), "an F-key is named");
        CHECK(logged("fn keys: report 55 usage 0x00e9 down -> 0x000c/0x00e9"), "a Consumer usage is named");
        CHECK(logged("fn keys: report 54 key 0x72 down past the logical maximum 0x65, modifiers 0x0a: not dispatched"),
              "F23 (the Copilot key's) is named");
        CHECK(logged("fn keys: report 54 chord: modifiers 0x08 and key 0x13 went down in one report"), "a chord is named");
        CHECK(logged("fn keys: report 7, 5 bytes [07 01 02 03 04]: not taken"), "an unknown report is named");
        size_t before = standin.log.size();
        for (uint8_t k = 0x04; k <= 0x39; k++) {
            fn_keys(kb, 0x02, k);
            fn_keys(kb, 0, 0);
        }
        CHECK(standin.log.find("fn keys:", before) == std::string::npos, "typing leaves no raw-log line");
        standin.log.clear();
        const uint8_t press[6] = {0x5a, 0x10, 0, 0, 0, 0}, none[6] = {0x5a, 0, 0, 0, 0, 0};
        for (int i = 0; i < 200; i++) {                         // in one instant
            kb->fKeyboard->handleReport(press, 6);
            kb->fKeyboard->handleReport(none, 6);
        }
        CHECK(occurrences("fn keys: report 90") <= HID_FNKEYS_RATE_BURST, "a flood is cut to the burst");
        standin.now_ns += 1000000000ull;
        fn_vendor(kb, 0x20);
        CHECK(logged("raw-log lines dropped by the rate limit") && logged("code 0x20 down"),
              "and the next allowed line says how many were dropped");
        CHECK(fn_events(standin.key_events.size() - 1, {{0xff, 4, 1}}), "dispatching is never rate-limited");
        fn_done(kb);
    } else if (s == "fnkeys-yield") {
        SnapI2CHIDBus *kb = fn_bus(true, 0x1);
        IOService *dk = new IOService;
        dk->meta.name = "AppleUserHIDEventService";
        G.nack_commands = true;                                 // the steps' own polls fail at once
        fn_consumer(kb, 0x70);                                  // brightness down held when the driver takes over
        CHECK(fn_events(0, {{0xff, 5, 1}}), "report 55's brightness, translated");
        CHECK(kb->fHID->handleOpen(dk, 0, nullptr), "an event driver opens the raw device");
        kb->step();
        CHECK(!strcmp(kb->fKeyboard->state(), "yielded") && fn_events(1, {{0xff, 5, 0}}),
              "yielding releases it as what it was dispatched as");
        fn_keys(kb, 0, 0x04); fn_keys(kb, 0, 0);
        fn_consumer(kb, 0x6f); fn_consumer(kb, 0);
        CHECK(fn_events(2, {}), "reports 54 and 55 are the event driver's");
        fn_vendor(kb, 0x20); fn_vendor(kb, 0);
        CHECK(fn_events(2, {{0xff, 4, 1}, {0xff, 4, 0}}), "report 90 is still ours");
        kb->fHID->handleClose(dk, 0);
        kb->step();
        fn_keys(kb, 0, 0x04); fn_keys(kb, 0, 0);
        CHECK(fn_events(4, {{7, 4, 1}, {7, 4, 0}}), "closed, the keyboard dispatches again");
        dk->release();
        fn_done(kb);
    } else if (s == "fnkeys-host-lock") {
        SnapI2CHIDBus *kb = fn_bus(true, 0x7);
        fn_vendor(kb, 0x10); fn_vendor(kb, 0);
        fn_vendor(kb, 0x4e); fn_vendor(kb, 0);
        CHECK(logged("fn keys: host Fn-lock on: F1-F12 first, hotkeys with Fn"), "Fn+Esc turns the host lock on");
        fn_vendor(kb, 0x10); fn_vendor(kb, 0);
        fn_keys(kb, 0, 0x3e); fn_keys(kb, 0, 0);
        fn_vendor(kb, 0x4e); fn_vendor(kb, 0);
        CHECK(logged("fn keys: host Fn-lock off: hotkeys first, F1-F12 with Fn"), "and off again");
        fn_vendor(kb, 0x10); fn_vendor(kb, 0);
        CHECK(fn_events(0, {{0xff, 5, 1}, {0xff, 5, 0}, {7, 0x3e, 1}, {7, 0x3e, 0}, {0xff, 5, 1}, {0xff, 5, 0},
                            {0xff, 5, 1}, {0xff, 5, 0}}),
              "locked, the brightness key is F5 and Fn+F5 brightness");
        fn_done(kb);
    } else if (s == "fnkeys-bootarg") {
        const struct { uint32_t flags; const char *log; uint32_t page, usage; } cases[] = {
            {0x40, "fn keys: snap_i2c_fnkeys 0x40 refused (unknown bits); off", 0, 0},
            {0x19, "fn keys: snap_i2c_fnkeys 0x19 refused (brightness encoding 3); off", 0, 0},
            {0x04, "fn keys: snap_i2c_fnkeys 0x4 refused (host lock without translate); off", 0, 0},
            {0x09, "brightness down 0xff01/0x0021, up 0xff01/0x0020", 0xff01, 0x21},
            {0x11, "brightness down 0x000c/0x0070, up 0x000c/0x006f", 0x0c, 0x70},
        };
        for (const auto &c : cases) {
            standin.log.clear();
            standin.key_events.clear();
            SnapI2CHIDBus *kb = fn_bus(true, c.flags);
            CHECK(logged(c.log), "the start line");
            fn_vendor(kb, 0x10); fn_vendor(kb, 0);
            CHECK(c.page ? fn_events(0, {{c.page, c.usage, 1}, {c.page, c.usage, 0}}) : fn_events(0, {}),
                  "a refused boot-arg leaves the layer off; an encoding picks the brightness usages");
            fn_done(kb);
        }
    } else if (s == "fnkeys-rejected") {
        static const uint8_t unknown[] = {0x07, 0x00, 0x40, 0x01, 0x02, 0x03, 0x04};
        static const uint8_t short54[] = {0x0a, 0x00, 0x36, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00};
        SnapI2CHIDBus *kb = fn_bus(true, 0x3);
        struct i2c_hid_dev *d = kb->fDev;
        memcpy(d->rejected, unknown, sizeof(unknown));
        d->rejected_len = 64;
        d->stats.unknown_id++;
        kb->noteRejectedInput();
        CHECK(logged("fn keys: transport refused an input: length prefix 7, report 64 [40 01 02 03 04]"),
              "an input the transport refused is named by the bus");
        size_t n = standin.log.size();
        kb->noteRejectedInput();
        CHECK(standin.log.size() == n, "once per refusal");
        memset(d->rejected, 0, sizeof(d->rejected));
        memcpy(d->rejected, short54, sizeof(short54));
        d->stats.wrong_size++;
        kb->noteRejectedInput();
        CHECK(logged("length prefix 10, report 54 (bytes withheld)") &&
              standin.log.find("36 00 00 04") == std::string::npos, "a keyboard report by its size only");
        fn_done(kb);
        standin.log.clear();
        kb = fn_bus(true, 0x1);                                 // translate only: not named
        memcpy(kb->fDev->rejected, unknown, sizeof(unknown));
        kb->fDev->rejected_len = 64;
        kb->fDev->stats.unknown_id++;
        kb->noteRejectedInput();
        SnapI2CHIDBus *tp = ready_bus(a16_tpad_hid_desc, a16_tpad_report_desc, sizeof(a16_tpad_report_desc));
        tp->publish();
        memcpy(tp->fDev->rejected, unknown, sizeof(unknown));
        tp->fDev->rejected_len = 52;
        tp->fDev->stats.unknown_id++;
        tp->noteRejectedInput();                                // the touchpad's bus has no keyboard
        CHECK(standin.log.find("transport refused") == std::string::npos, "without the raw log or a keyboard: nothing");
        tp->stop(tp->fProvider);
        tp->release();
        fn_done(kb);
    } else {
        return false;
    }
    return true;
}
#endif

int main(int argc, char **argv)
{
    std::string s = argc > 1 ? argv[1] : "";
    geni_reset();
    if (s == "no-address" || s == "bad-address" || s == "no-descriptor-register") {
        IOService *nub = keyboard_nub();
        if (s == "no-address") nub->properties.erase("snapintosh,hid-address");
        if (s == "bad-address") put(nub, "snapintosh,hid-address", {0x80});
        if (s == "no-descriptor-register") nub->properties.erase("snapintosh,hid-descriptor-reg");
        CHECK(refuses(nub, "node lacks hid-address/hid-descriptor-register"), "a node without its identity does not start");
        CHECK(standin.maps == 0 && G.reads + G.writes == 0, "and maps and touches nothing");
    } else if (s == "no-window" || s == "short-window" || s == "unaligned-window") {
        IOService *nub = s == "short-window" ? keyboard_nub(true, 0x70088c000ull, 0x800)
                       : s == "unaligned-window" ? keyboard_nub(true, 0x70088c800ull) : keyboard_nub(false);
        CHECK(refuses(nub, "cannot map the serial-engine page"), "a node without a usable window does not start");
        CHECK(G.reads + G.writes == 0, "and touches nothing");
    } else if (s == "config-refused" || s == "busy-refused" || s == "fifo-refused" || s == "error-refused") {
        if (s == "config-refused") G.regs[0x068 / 4] = 0x00000204;      // protocol 2 (SPI), not I2C
        if (s == "busy-refused") G.active = true;                        // firmware's engine running
        if (s == "fifo-refused") { G.rxn = 1; G.rx_last = true; }       // firmware's unread word
        if (s == "error-refused") G.irq_status |= 1u << 10;             // firmware's pending NACK
        IOService *nub = keyboard_nub();
        CHECK(refuses(nub, "controller refused"), "firmware state the transport does not drive refuses the start");
        CHECK(G.writes == 0 && G.pops == 0, "and nothing is written or popped");
    } else if (s == "never-completes") {
        IOService *nub = keyboard_nub();
        SnapI2CHIDBus *bus = new SnapI2CHIDBus;
        CHECK(bus->start(nub), "a healthy firmware state starts");
        CHECK(G.irq_en == 0, "M_IRQ_EN is 0 (irq-policy 1): the engine can raise no interrupt");
        CHECK(standin.registered == 1 && bus->fTimer->armed, "the bus registers and arms its first step");
        run(bus, 60ull * 1000000000u);
        CHECK(logged("FAILED in descriptor: init-errors"), "it gives up in the descriptor step");
        CHECK(!bus->fTimer->armed, "and leaves no timer armed: polling stops");
        CHECK(standin.now_ns < 2ull * 1000000000u, "within two seconds of bus time");
        CHECK(only_tool_writes(), "writing only the tools' register set");
        CHECK(G.irq_en == 0, "never enabling the engine's interrupt");
        CHECK(standin.thread_calls_entered == 0 && standin.hid_starts == 0, "no HID device is published");
        bus->stop(nub);
        CHECK(G.tx_len == 6 && G.rx_len == 0x40 && G.irq_en == 0x33c0007e,
              "stop restores the firmware lengths and interrupt enables");
        bus->release();
    } else if (s == "wedged-no-mmio") {
        IOService *nub = keyboard_nub();
        SnapI2CHIDBus *bus = new SnapI2CHIDBus;
        CHECK(bus->start(nub), "a healthy firmware state starts");
        G.active = true;                                                 // someone else starts the engine
        run(bus, 60ull * 1000000000u);
        CHECK(logged("FAILED in descriptor: bus"), "the first step finds the engine busy");
        CHECK(bus->fBus.wedged, "and declares the bus wedged");
        G.forbid = true;
        bus->stop(nub);
        bus->release();
        CHECK(G.violations == 0, "stop performed no MMIO on a wedged bus");
    } else if (s == "own-idle-leftover") {                               // v39: a finished poll nobody drained
        own_leftover();
        G.rxn = 16; G.rx_last = true; G.irq_status |= 1u | (1u << 27);
        starts_after_recovery(16, 0, 0);
    } else if (s == "own-error-leftover") {
        own_leftover();
        G.irq_status |= 1u | (1u << 10);                                 // DONE, NACK
        starts_after_recovery(0, 0, 0);
    } else if (s == "own-mid-transaction") {                             // the 144-byte read stalled, FIFO full
        own_leftover();
        G.rx_len = 144; G.active = true; G.rxn = 32; G.pending = 4; G.irq_status |= 1u << 26;
        starts_after_recovery(36, 0, 0);
    } else if (s == "own-hung-cancel" || s == "own-hung-abort") {
        own_leftover();
        G.active = true;
        G.cancel_works = s == "own-hung-cancel";
        starts_after_recovery(0, 1, s == "own-hung-abort" ? 1 : 0);
    } else if (s == "own-stuck") {
        own_leftover();
        G.active = true; G.cancel_works = G.abort_works = false;
        IOService *nub = keyboard_nub();
        CHECK(refuses(nub, "controller refused (wedged): status 0x1 irq 0x80 irq-en 0x0"),
              "an engine neither cancel nor abort stops is refused, with what was found");
        CHECK(G.cancels == 1 && G.aborts == 1, "after one bounded cancel and one bounded abort");
    } else if (s == "own-tx-leftover") {
        own_leftover();
        G.txn = 1;
        IOService *nub = keyboard_nub();
        CHECK(refuses(nub, "controller refused (busy)"), "leftover transmit words are refused");
        CHECK(G.writes == 0 && G.txn == 1, "with nothing written");
    } else if (s == "keyboard-service") {
        // Our own IOHIDEventService: started by the bus, primary 1/6 over I2C, report 54 and 55
        // turned into key transitions in order, report 90 and malformed reports ignored, LED
        // requests sent as output report 54, and no key usage ever in the log.
        IOService *nub = keyboard_nub();
        SnapI2CHIDBus *bus = new SnapI2CHIDBus;
        bus->fProvider = nub;
        bus->fDev = static_cast<struct i2c_hid_dev *>(IOMallocZero(sizeof(*bus->fDev)));
        bus->fDev->desc.vendor_id = 0x0b05;
        bus->fDev->desc.product_id = 0x4b42;
        bus->fDev->cfg.poll_us = 8000;
        bus->fWorkLoop = IOWorkLoop::workLoop();
        SnapI2CHIDKeyboard *kbd = new SnapI2CHIDKeyboard;
        CHECK(kbd->initWithBus(bus) && kbd->start(bus), "the keyboard event service starts on the bus");
        CHECK(standin.primary == 0x10006 && standin.transport == "I2C", "as a 1/6 keyboard over I2C");
        CHECK(kbd->getWorkLoop() == bus->fWorkLoop, "on the bus's work loop");
        auto keys = [&](uint8_t mods, std::vector<uint8_t> k) {
            uint8_t r[9] = {0x36, mods, 0, 0, 0, 0, 0, 0, 0};
            for (size_t i = 0; i < k.size(); i++) r[3 + i] = k[i];
            kbd->handleReport(r, 9);
        };
        auto consumer = [&](uint16_t u) { uint8_t r[3] = {0x37, (uint8_t)u, (uint8_t)(u >> 8)}; kbd->handleReport(r, 3); };
        keys(0, {0x04}); keys(0, {});                     // a
        keys(0x02, {}); keys(0x02, {0x04}); keys(0, {});   // Shift+A, both released together
        keys(0, {0x39}); keys(0, {});                     // Caps Lock
        keys(0, {0x01, 0x01, 0x01, 0x01, 0x01, 0x01});    // rollover: nothing
        consumer(0x00e9); consumer(0);                    // Volume Up
        uint8_t vendor[6] = {0x5a, 1, 2, 3, 4, 5}; kbd->handleReport(vendor, 6);
        uint8_t shortr[4] = {0x36, 0, 0, 4}; kbd->handleReport(shortr, 4);
        const std::vector<std::array<uint32_t, 3>> want = {
            {7, 4, 1}, {7, 4, 0}, {7, 0xe1, 1}, {7, 4, 1}, {7, 0xe1, 0}, {7, 4, 0},
            {7, 0x39, 1}, {7, 0x39, 0}, {12, 0xe9, 1}, {12, 0xe9, 0}};
        bool same = standin.key_events.size() == want.size();
        for (size_t i = 0; same && i < want.size(); i++)
            same = standin.key_events[i].page == want[i][0] && standin.key_events[i].usage == want[i][1] &&
                   standin.key_events[i].value == want[i][2];
        CHECK(same, "the transitions, in order");
        CHECK(logged("keyboard dispatched 1 key transitions from 1 reports") &&
              logged("keyboard dispatched 4 key transitions"), "progress is logged as counts");
        CHECK(logged("keyboard report 12 not taken (length), id 54, 4 bytes"), "a malformed report is named");
        CHECK(standin.log.find("usage 4") == std::string::npos && standin.log.find("0x39") == std::string::npos &&
              standin.log.find("0xe9") == std::string::npos, "no key usage in the log");
        keys(0x01, {0x05, 0x06});
        size_t before = standin.key_events.size();
        kbd->suppress("IOHIDEventDriver");
        CHECK(standin.key_events.size() == before + 3 && logged("keyboard event service stops dispatching: IOHIDEventDriver"),
              "suppression releases what is held");
        keys(0, {0x07});
        CHECK(standin.key_events.size() == before + 3, "and dispatches nothing after");
        CHECK(logged("keyboard yielded: 1 reports left to the event driver"), "counting what it left (D1)");
        kbd->resume();
        keys(0, {0x07});
        CHECK(standin.key_events.size() == before + 4 && standin.key_events.back().usage == 0x07 &&
              logged("keyboard event service dispatches again after 1 yielded reports"),
              "resumed (Y3), it dispatches again from a clean state");
        keys(0, {});
        CHECK(kbd->setElementValue(8, 2, 1) == kIOReturnOffline &&
              logged("keyboard LED 1: usage 2 -> 1, output 0x02 -> 0x2e5"), "the Caps Lock LED is an output report");
        CHECK(kbd->setElementValue(8, 2, 0) == kIOReturnOffline && logged("output 0x00"), "and goes off again");
    } else if (s == "pointer-service") {
        // The touchpad's pointer service: started by the bus as 1/2 over I2C from the device's own
        // mouse layout (here the fixture's synthetic touchpad descriptor), moves with buttons in
        // order, other reports and malformed ones ignored, counts only in the log, suppression
        // releasing a held button.
        IOService *nub = keyboard_nub();
        SnapI2CHIDBus *bus = new SnapI2CHIDBus;
        bus->fProvider = nub;
        bus->fDev = static_cast<struct i2c_hid_dev *>(IOMallocZero(sizeof(*bus->fDev)));
        bus->fDev->desc.vendor_id = 0x2808;
        bus->fDev->desc.product_id = 0x0219;
        bus->fDev->cfg.poll_us = 8000;
        bus->fWorkLoop = IOWorkLoop::workLoop();
        struct hid_pointer_layout layout;
        CHECK(hid_pointer_layout(synthetic_tpad_report_desc, sizeof(synthetic_tpad_report_desc), &layout) ==
              HID_POINTER_OK, "the synthetic touchpad descriptor has a mouse layout");
        SnapI2CHIDPointer *ptr = new SnapI2CHIDPointer;
        CHECK(ptr->initWithBus(bus, &layout) && ptr->start(bus), "the pointer event service starts on the bus");
        CHECK(standin.primary == 0x10002 && standin.transport == "I2C", "as a 1/2 mouse over I2C");
        CHECK(ptr->getWorkLoop() == bus->fWorkLoop, "on the bus's work loop");
        auto report = [&](uint8_t buttons, int8_t dx, int8_t dy) {
            uint8_t r[4] = {1, buttons, (uint8_t)dx, (uint8_t)dy};
            ptr->handleReport(r, 4);
        };
        report(0, 10, -4); report(0, 0, 0); report(1, 0, 0); report(1, 3, 3); report(0, 0, 0);
        uint8_t other[5] = {3, 1, 2, 3, 4}; ptr->handleReport(other, 5);
        uint8_t shortr[2] = {1, 0}; ptr->handleReport(shortr, 2);
        const std::vector<std::array<int32_t, 3>> want = {{10, -4, 0}, {0, 0, 1}, {3, 3, 1}, {0, 0, 0}};
        bool same = standin.pointer_events.size() == want.size();
        for (size_t i = 0; same && i < want.size(); i++)
            same = standin.pointer_events[i].a == want[i][0] && standin.pointer_events[i].b == want[i][1] &&
                   standin.pointer_events[i].c == want[i][2];
        CHECK(same, "moves and button transitions, in order");
        CHECK(standin.scroll_events.empty(), "no scroll without a wheel");
        CHECK(logged("pointer dispatched 1 moves and 0 scrolls from 1 reports") &&
              logged("pointer dispatched 4 moves"), "progress is logged as counts");
        CHECK(logged("pointer report 7 not taken (length), id 1, 2 bytes"), "a malformed report is named");
        report(1, 0, 0);
        size_t before = standin.pointer_events.size();
        ptr->suppress("IOHIDEventDriver");
        CHECK(standin.pointer_events.size() == before + 1 && standin.pointer_events.back().c == 0,
              "suppression releases the held button");
        report(0, 5, 5);
        CHECK(standin.pointer_events.size() == before + 1, "and dispatches nothing after");
        CHECK(logged("pointer yielded: 1 reports left to the event driver (0 touchpad frames)"), "counting it (D1)");
        ptr->resume();
        report(0, 5, 5);
        CHECK(standin.pointer_events.size() == before + 2 && logged("pointer event service dispatches again"),
              "resumed (Y3), it moves again");
        CHECK(todays_identity(ptr), "a mouse-only service keeps today's properties (F16)");
    } else if (s == "ptp-service") {
        // The armed service: trackpad scroll identity (pointer keys untouched), report 4 through
        // the engine (fixed-point pointer, phased scroll, momentum on the tick), report 1 still on
        // the mouse path (F9), and suppression ending the touch state (F22).
        IOService *nub = keyboard_nub();
        SnapI2CHIDBus *bus = new SnapI2CHIDBus;
        bus->fProvider = nub;
        bus->fDev = static_cast<struct i2c_hid_dev *>(IOMallocZero(sizeof(*bus->fDev)));
        bus->fDev->desc.vendor_id = 0x2808;
        bus->fDev->desc.product_id = 0x0219;
        bus->fDev->cfg.poll_us = 8000;
        bus->fWorkLoop = IOWorkLoop::workLoop();
        struct hid_pointer_layout mouse;
        struct hid_ptp_layout ptp;
        CHECK(hid_pointer_layout(a16_tpad_report_desc, sizeof(a16_tpad_report_desc), &mouse) == HID_POINTER_OK &&
              hid_ptp_layout(a16_tpad_report_desc, sizeof(a16_tpad_report_desc), &ptp) == HID_PTP_OK,
              "the A16 descriptor has both layouts");
        SnapI2CHIDPointer *ptr = new SnapI2CHIDPointer;
        CHECK(ptr->initWithBus(bus, &mouse, &ptp) && ptr->start(bus), "the armed pointer service starts");
        CHECK(standin.primary == 0x10002 && standin.transport == "I2C", "still a 1/2 pointer over I2C");
        CHECK(trackpad_identity(ptr), "with the trackpad scroll keys and curves, pointer keys untouched");
        Touch a = {1, 1, 1, 2000, 1500}, b = {1, 1, 2, 2600, 1500};
        feed(ptr, {a});
        for (int i = 0; i < 4; i++) { a.x += 32; feed(ptr, {a}); }
        CHECK(standin.pointer_fixed.size() == 4 && standin.pointer_events.empty(), "one finger: fixed-point moves");
        CHECK(standin.pointer_fixed[0].a > (15 << 16) && standin.pointer_fixed[0].a < (16 << 16) &&
              standin.pointer_fixed[0].b == 0, "1 mm is about 15.6 units of 1/400 inch");
        a.tip = 0; feed(ptr, {a}); feed(ptr, {});
        a = {1, 1, 1, 2000, 2000}; b.y = 2000;
        feed(ptr, {a, b});
        for (int i = 0; i < 6; i++) { a.y -= 16; b.y -= 16; feed(ptr, {a, b}); }
        CHECK(!standin.scroll_fixed.empty() && standin.scroll_fixed[0].c == kHIDDispatchOptionPhaseBegan &&
              standin.scroll_fixed[0].a > 0 && standin.scroll_fixed[1].c == kHIDDispatchOptionPhaseChanged,
              "two fingers: a phased scroll, fingers up positive");
        a.tip = b.tip = 0; feed(ptr, {a, b});
        CHECK(standin.scroll_fixed.back().c == kHIDDispatchOptionPhaseEnded, "a lift ends it");
        size_t before = standin.scroll_fixed.size();
        standin.now_ns += 8000000u;
        ptr->tick();
        CHECK(standin.scroll_fixed.size() == before + 1 &&
              standin.scroll_fixed.back().c == kHIDDispatchOptionScrollMomentumStart, "the bus tick starts momentum");
        standin.now_ns += 8000000u;
        ptr->tick();
        CHECK(standin.scroll_fixed.back().c == kHIDDispatchOptionScrollMomentumContinue, "and continues it");
        ptr->suppress("IOHIDEventDriver");
        CHECK(standin.scroll_fixed.back().c == kHIDDispatchOptionScrollMomentumEnd, "suppression ends momentum (F22)");
        CHECK(logged("pointer event service stops dispatching: IOHIDEventDriver"), "and says so");
        before = standin.scroll_fixed.size();
        standin.now_ns += 8000000u;
        ptr->tick();
        feed(ptr, {a, b});
        CHECK(standin.scroll_fixed.size() == before, "nothing after");
        // A second service, not suppressed: report 1 keeps the mouse path while armed (F9).
        standin.pointer_events.clear();
        SnapI2CHIDPointer *again = new SnapI2CHIDPointer;
        CHECK(again->initWithBus(bus, &mouse, &ptp) && again->start(bus), "another armed service");
        uint8_t m1[5] = {1, 0, 7, (uint8_t)-3, 0};
        again->handleReport(m1, 5);
        CHECK(standin.pointer_events.size() == 1 && standin.pointer_events[0].a == 7 &&
              standin.pointer_events[0].b == -3, "a mouse report while armed still moves the pointer");
        CHECK(logged("mouse-mode report 1 while in touchpad mode") && bus->fPtpReapply,
              "and is noted, asking the bus to re-apply the switch (F24)");
        // Its log has counts, never positions.
        for (int i = 0; i < 300; i++) feed(again, {{1, 1, 3, (uint16_t)(1000 + i), 1000}});
        CHECK(logged("touchpad: ") && logged(" frames"), "progress is logged as counts");
    } else if (s == "ptp-publish-armed" || s == "ptp-publish-unverified" || s == "ptp-publish-refused" ||
               s == "ptp-publish-readback" || s == "ptp-reinit") {
        // F1, F2, F16 and F10 through the real publish path and the feature hook.
        F.no_get = s == "ptp-publish-unverified";
        F.refuse_write = s == "ptp-publish-refused";
        F.ignore_mode = s == "ptp-publish-readback";
        bool armed = s == "ptp-publish-armed" || s == "ptp-publish-unverified" || s == "ptp-reinit";
        SnapI2CHIDBus *bus = ready_bus(a16_tpad_hid_desc, a16_tpad_report_desc, sizeof(a16_tpad_report_desc));
        bus->publish();
        CHECK(bus->fPointerStarted && bus->fPointer == bus->fPointerStarted, "the pointer service is published");
        // Y2: an armed touchpad gets no raw IOHIDDevice (nothing for a generic driver to take); mouse mode keeps
        // it. M1: an armed one gets the multitouch device instead (one IOHIDDevice start either way).
        CHECK(standin.hid_starts == 1 && bus->fRawPublished == !armed && (bus->fHID == nullptr) == armed &&
              (bus->fMT != nullptr) == armed, "the raw HID device without the switch, the multitouch device with it");
        CHECK(!armed || (logged("raw HID device not published: the precision touchpad is served by the pointer event "
                                "service only") &&
                         logged("multitouch device published: 05ac:0281, family 0x81, surface 147.48 x 96.00 mm, "
                                "frames as report 2 (0x31)")), "and both are logged");
        CHECK(bus->fDev->state == I2C_HID_S_RUNNING && bus->fTimer->armed, "and polling starts");
        CHECK(bus->fPtpArmed == armed, "touchpad mode is armed exactly when the switch held");
        CHECK(armed ? trackpad_identity(bus->fPointerStarted) : todays_identity(bus->fPointerStarted),
              "the identity follows the switch");
        if (s == "ptp-publish-armed")
            CHECK(F.mode == 3 && F.selective == 3 && F.requests == 6 &&
                  logged("precision touchpad enabled: report 4 (50 bytes), fingers 5, confidence yes, contact count yes, "
                         "scan time yes, buttons 1, 147.5 x 96.0 mm; contacts max 5, pad type 0; blob 257 bytes; "
                         "input mode 0 -> 3; surface and button switch on"), "the switch and its log line");
        if (s == "ptp-publish-unverified")
            CHECK(F.mode == 3 && logged("precision touchpad enabled, unverified"), "written, not read back");
        if (s == "ptp-publish-refused")
            CHECK(F.mode == 0 && F.sets_by_id[5] == 0 && logged("precision touchpad not enabled (refused: write)") &&
                  logged("mouse mode"), "refused: nothing after the failed write, mouse mode");
        if (s == "ptp-publish-readback")
            CHECK(F.mode == 0 && logged("precision touchpad not enabled (refused: readback 0)"), "the readback refuses it");
        if (s == "ptp-reinit") {
            Touch a = {1, 1, 1, 2000, 2000}, b = {1, 1, 2, 2600, 2000};
            feed(bus->fPointer, {a, b});
            for (int i = 0; i < 5; i++) { a.y -= 16; b.y -= 16; feed(bus->fPointer, {a, b}); }
            CHECK(!standin.scroll_fixed.empty() && standin.scroll_fixed.back().c == kHIDDispatchOptionPhaseChanged,
                  "a scroll is in progress");
            unsigned before = F.requests;
            F.mode = 0;                                   // the re-initialisation's RESET
            G.nack_commands = true;                        // the step's own poll fails at once
            bus->step();
            CHECK(F.mode == 0 && F.requests == before, "no re-apply without a re-initialisation");
            F.mode = 0;
            bus->fDev->stats.reinits = 1;
            bus->step();
            CHECK(F.mode == 3 && F.requests == before + 6, "a re-initialisation re-applies the switch (F10)");
            CHECK(standin.scroll_fixed.back().c == kHIDDispatchOptionPhaseEnded, "and ends the touch state");
            CHECK(logged("precision touchpad re-applied after re-initialisation 1: enabled"), "and says so");
            bus->step();
            CHECK(F.requests == before + 6, "once per re-initialisation");
            // F24: the device reset itself: report 1 arrives while armed; the next step re-applies,
            // once for the first such report, not for the second.
            F.mode = 0;
            uint8_t m1[5] = {1, 0, 3, 3, 0};
            bus->fPointer->handleReport(m1, 5);
            CHECK(bus->fPtpReapply && F.requests == before + 6, "report 1 while armed asks for a re-apply");
            bus->step();
            CHECK(F.mode == 3 && F.requests == before + 12 && !bus->fPtpReapply &&
                  logged("precision touchpad re-applied after mouse-mode reports: enabled"), "the step re-applies");
            bus->fPointer->handleReport(m1, 5);
            bus->step();
            CHECK(F.requests == before + 12, "not again for the second report");
        }
        bus->stop(bus->fProvider);
        bus->release();
    } else if (s == "yield-open-close") {
        // installed-fresh-desktop-20261021-v2: DriverKit's AppleUserHIDEventService opened both raw
        // HID devices about 2 s into the boot, our services yielded to it, and the touchpad was dead
        // (the generic driver makes no pointer motion from Precision Touchpad frames). Y1-Y5: only an
        // event driver holding the device open takes it, user clients never; closing gives it back;
        // an armed touchpad has no raw device at all.
        SnapI2CHIDBus *kb = ready_bus(a16_eckb_hid_desc, a16_eckb_report_desc, sizeof(a16_eckb_report_desc));
        kb->publish();
        CHECK(kb->fHID && kb->fRawPublished && kb->fKeyboard, "the keyboard keeps its raw HID device");
        IOService *dk = new IOService;
        dk->meta.name = "AppleUserHIDEventService";
        IOUserClient *uc = new IOUserClient;
        uc->meta.name = "IOHIDLibUserClient";
        auto keys = [&](std::vector<uint8_t> k) {
            uint8_t r[9] = {0x36};
            for (size_t i = 0; i < k.size(); i++) r[3 + i] = k[i];
            kb->fKeyboard->handleReport(r, 9);
        };
        G.nack_commands = true;                            // the steps' own polls fail at once
        CHECK(kb->fHID->handleOpen(uc, 0, nullptr), "a user client opens the device");
        kb->step();
        size_t before = standin.key_events.size();
        keys({0x04}); keys({});
        CHECK(standin.key_events.size() == before + 2, "a user client takes nothing: our keyboard dispatches");
        CHECK(kb->fHID->handleOpen(dk, 0, nullptr) && kb->fHID->handleOpen(dk, 0, nullptr),
              "an event driver opens it, twice");
        kb->step();
        before = standin.key_events.size();
        keys({0x04}); keys({});
        CHECK(standin.key_events.size() == before &&
              logged("keyboard event service stops dispatching: AppleUserHIDEventService opened the HID device"),
              "the keyboard yields to it (Y1): no doubled keys");
        CHECK(logged("services: keyboard yielded, pointer none; raw HID device published; event drivers open 1 last "
                     "AppleUserHIDEventService"), "the services line names it (D1)");
        kb->fHID->handleClose(uc, 0);
        kb->step();
        keys({0x04}); keys({});
        CHECK(standin.key_events.size() == before, "a user client closing gives nothing back");
        kb->fHID->handleClose(dk, 0);
        kb->step();
        keys({0x04}); keys({});
        CHECK(standin.key_events.size() == before + 2 &&
              logged("AppleUserHIDEventService closed the HID device; our services dispatch again") &&
              logged("keyboard event service dispatches again after 4 yielded reports"),
              "one close of a twice-opened client gives the keys back (Y3, Y4)");
        // The touchpad, armed: no raw device, so no driver can take it; its frames keep moving the pointer.
        SnapI2CHIDBus *tp = ready_bus(a16_tpad_hid_desc, a16_tpad_report_desc, sizeof(a16_tpad_report_desc));
        tp->publish();
        CHECK(tp->fPtpArmed && !tp->fHID && !tp->fRawPublished && tp->fPointer, "the armed touchpad has no raw device");
        Touch a = {1, 1, 1, 2000, 1500};
        feed(tp->fPointer, {a});
        for (int i = 0; i < 4; i++) { a.x += 32; feed(tp->fPointer, {a}); }
        CHECK(standin.pointer_fixed.size() == 4 && !strcmp(tp->fPointer->state(), "dispatching"),
              "and its frames move the pointer");
        CHECK(tp->fMT && tp->fMT->fSent == 5, "while every frame also goes to the multitouch device");
        CHECK(logged("touchpad frame 1: 1 contacts, 1 touching, 1 confident, buttons 0x0; dispatched so far 0 pointer, 0 "
                     "scroll") && logged("touchpad frame 5: 1 contacts, 1 touching, 1 confident, buttons 0x0; dispatched "
                     "so far 3 pointer"), "the first frames are logged as counts (D2)");
        tp->stop(tp->fProvider);
        tp->release();
        kb->stop(kb->fProvider);
        kb->release();
    } else if (s == "mt-handover" || s == "mt-other-driver") {
        // M1, M2, M3, M6, M7: the registry above the multitouch device decides the handover.
        SnapI2CHIDBus *tp = ready_bus(a16_tpad_hid_desc, a16_tpad_report_desc, sizeof(a16_tpad_report_desc));
        tp->publish();
        SnapI2CHIDMultitouch *mt = tp->fMT;
        CHECK(mt && tp->fPointer && tp->fPtpArmed, "an armed touchpad with its multitouch device");
        IOService *interface = new IOService, *driver = new IOService, *amd = new IOService, *client = new IOService;
        interface->meta.name = "IOHIDInterface";
        driver->meta.name = s == "mt-handover" ? "AppleMultitouchTrackpadHIDEventDriver" : "AppleUserHIDEventService";
        amd->meta.name = "AppleMultitouchDevice";
        client->meta.name = "AppleMultitouchDeviceUserClient";
        Touch a = {1, 1, 1, 2000, 1500};
        tp->fDev->stats.polls = 100;
        tp->noteMultitouch();
        CHECK(logged("multitouch stack: interface no, no driver, multitouch device no, frames consumer no"),
              "nothing above it yet: logged");
        mt->children.push_back(interface);
        interface->children.push_back(driver);
        unsigned sent = mt->fSent;
        tp->fDev->stats.polls = 200;
        tp->noteMultitouch();
        if (s == "mt-other-driver") {
            // M2: a generic driver on the interface: no kick, no handover; our pointer keeps the touchpad.
            CHECK(logged("another driver (no handover)") && mt->fSent == sent, "another driver: noted, no empty frame");
            feed(tp->fPointer, {a});
            a.x += 32;
            feed(tp->fPointer, {a});
            CHECK(standin.pointer_fixed.size() == 1 && !strcmp(tp->fPointer->state(), "dispatching"),
                  "and the pointer still moves");
        } else {
            CHECK(logged("Apple multitouch driver, multitouch device no") && mt->fSent == sent + 1 &&
                  logged("multitouch: empty frame 1, for the driver to build its device"),
                  "Apple's driver without its device: an empty frame (M3)");
            tp->fDev->stats.polls = 240;
            tp->noteMultitouch();
            CHECK(mt->fSent == sent + 1, "not again within a second");
            for (unsigned p = 400; p < 400 + 125 * 20; p += 125) {
                tp->fDev->stats.polls = p;
                tp->noteMultitouch();
            }
            CHECK(tp->fMTKicks == 10 && mt->fSent == sent + 10, "at most ten");
            driver->children.push_back(amd);
            tp->fDev->stats.polls = 3000;
            tp->noteMultitouch();
            feed(tp->fPointer, {a});
            a.x += 32;
            feed(tp->fPointer, {a});
            CHECK(standin.pointer_fixed.size() == 1, "device built, no consumer: our pointer still moves (M1)");
            amd->children.push_back(client);
            tp->fDev->stats.polls = 3100;
            tp->noteMultitouch();
            CHECK(logged("frames consumer yes") && logged("pointer hands the touchpad to the multitouch stack"),
                  "a frames consumer: the pointer hands over (M6)");
            size_t moves = standin.pointer_fixed.size(), reports = mt->fSent;
            for (int i = 0; i < 4; i++) { a.x += 32; feed(tp->fPointer, {a}); }
            CHECK(standin.pointer_fixed.size() == moves && mt->fSent == reports + 4,
                  "handed over: no pointer events of ours, every frame to the multitouch device");
            CHECK(!strcmp(tp->fPointer->state(), "handed over to the multitouch stack"), "and its state says so");
            amd->children.clear();
            tp->fDev->stats.polls = 3200;
            tp->noteMultitouch();
            CHECK(logged("pointer takes back the touchpad from the multitouch stack"), "the consumer gone: taken back (M7)");
            a.x += 32;
            feed(tp->fPointer, {a});
            a.x += 32;
            feed(tp->fPointer, {a});
            CHECK(standin.pointer_fixed.size() > moves, "and our pointer moves again");
        }
        tp->stop(tp->fProvider);
        tp->release();
    } else if (s == "mt-requests") {
        // M4, M14: the handshake from memory, the buffer length set to the reply, unknown reports refused,
        // set reports accepted, report 1's length query; the I2C device never sees any of it.
        SnapI2CHIDBus *tp = ready_bus(a16_tpad_hid_desc, a16_tpad_report_desc, sizeof(a16_tpad_report_desc));
        tp->publish();
        SnapI2CHIDMultitouch *mt = tp->fMT;
        CHECK(mt, "the multitouch device");
        unsigned requests = F.requests;
        IOBufferMemoryDescriptor *b = IOBufferMemoryDescriptor::withCapacity(0x201, 0);
        CHECK(mt->getReport(b, kIOHIDReportTypeFeature, 0xdb) == kIOReturnSuccess && b->getLength() == 74 &&
              b->data[0] == 0xdb && b->data[1] == 1, "0xDB: 74 bytes, the length set to them");
        CHECK(logged("multitouch getReport 1: type 2 id 0xdb length 74 -> 0x0"), "logged by type, ID, length, result");
        b->setLength(0x201);
        CHECK(mt->getReport(b, kIOHIDReportTypeFeature, 0xd9) == kIOReturnSuccess && b->getLength() == 17, "0xD9");
        CHECK(mt->getReport(b, kIOHIDReportTypeFeature, 0xc8) == kIOReturnUnsupported, "an unknown report: refused");
        CHECK(mt->getReport(b, kIOHIDReportTypeInput, 0x02) == kIOReturnUnsupported, "an input report: refused");
        IOBufferMemoryDescriptor *small = IOBufferMemoryDescriptor::withCapacity(8, 0);
        CHECK(mt->getReport(small, kIOHIDReportTypeFeature, 0xdb) == kIOReturnNoSpace, "a buffer too small: no space");
        IOBufferMemoryDescriptor *q = IOBufferMemoryDescriptor::withBytes("\x01\xd9", 2, 0);
        CHECK(mt->setReport(q, kIOHIDReportTypeFeature, 0x01) == kIOReturnSuccess, "report 1's query is accepted");
        b->setLength(0x201);
        CHECK(mt->getReport(b, kIOHIDReportTypeFeature, 0x01) == kIOReturnSuccess && b->getLength() == 5 &&
              b->data[1] == 0xd9 && b->data[3] == 16, "and answered with the length");
        IOBufferMemoryDescriptor *any = IOBufferMemoryDescriptor::withBytes("\x02\x01", 2, 0);
        CHECK(mt->setReport(any, kIOHIDReportTypeFeature, 0x02) == kIOReturnSuccess &&
              logged("multitouch setReport"), "other set reports: accepted, logged");
        CHECK(F.requests == requests, "none reaches the touchpad");
        b->release(); small->release(); q->release(); any->release();
        tp->stop(tp->fProvider);
        tp->release();
    } else if (s == "keyboard-no-ptp") {
        // F15: the keyboard bus publishes its keyboard service and sends no feature request.
        SnapI2CHIDBus *bus = ready_bus(a16_eckb_hid_desc, a16_eckb_report_desc, sizeof(a16_eckb_report_desc));
        bus->publish();
        CHECK(F.requests == 0 && !bus->fPtpArmed && !bus->fPointerStarted && bus->fKeyboardStarted,
              "keyboard only, no feature request");
        CHECK(standin.log.find("precision touchpad") == std::string::npos, "and no touchpad line");
        bus->stop(bus->fProvider);
        bus->release();
    } else if (s == "hid-diagnostics") {
        // The HID-stack hops v40 could not see: every handleReportWithTime result, every
        // set/get request, and the registry above the device with its matching properties.
        SnapI2CHIDBus *bus = new SnapI2CHIDBus;
        SnapI2CHIDDevice *hid = new SnapI2CHIDDevice;
        hid->fBus = bus;
        hid->fReport = IOBufferMemoryDescriptor::withCapacity(64, 0);
        const uint8_t report[9] = {0x36, 0, 0, 0x39, 0, 0, 0, 0, 0};
        for (int i = 0; i < 20; i++) hid->deliverReport(report, sizeof(report));
        CHECK(standin.reports == 20, "every report reaches handleReportWithTime");
        CHECK(logged("handleReportWithTime 16: id 54, 9 bytes -> 0x0") &&
              standin.log.find("handleReportWithTime 17:") == std::string::npos,
              "the first 16 results are logged, later successes are not");
        standin.report_result = kIOReturnNotReady;
        for (int i = 0; i < 300; i++) hid->deliverReport(report, sizeof(report));
        size_t failures_logged = 0;
        for (size_t at = 0; (at = standin.log.find("(failure ", at)) != std::string::npos; at++) failures_logged++;
        CHECK(failures_logged == 9, "failures are logged, rate-limited (8, then every 256th)");
        IOBufferMemoryDescriptor *led = IOBufferMemoryDescriptor::withBytes("\x36\x02", 2, 0);
        CHECK(hid->setReport(led, kIOHIDReportTypeOutput, 0x36) == kIOReturnOffline, "an LED report on a stopped bus");
        CHECK(logged("setReport 1: type 1 id 54 length 2 -> 0x2e5"), "is logged with type, id, length and result");
        CHECK(hid->setReport(led, kIOHIDReportTypeInput, 0x36) == kIOReturnUnsupported &&
              logged("setReport 2: type 0 id 54 length 2 -> 0x2c7"), "a refused type too");
        OSArray *pairs = new OSArray;
        for (auto pu : {std::pair<int, int>{1, 6}, {12, 1}, {65329, 118}}) {
            OSDictionary *d = new OSDictionary;
            d->setObject("DeviceUsagePage", OSNumber::withNumber(pu.first, 32));
            d->setObject("DeviceUsage", OSNumber::withNumber(pu.second, 32));
            pairs->items.push_back(d);
        }
        hid->properties["DeviceUsagePairs"] = pairs;
        hid->properties["PrimaryUsagePage"] = OSNumber::withNumber(1, 32);
        hid->properties["PrimaryUsage"] = OSNumber::withNumber(6, 32);
        hid->properties["Transport"] = OSString::withCString("I2C");
        hid->properties["Built-In"] = kOSBooleanTrue;
        hid->properties["VendorID"] = OSNumber::withNumber(0x0b05, 32);
        hid->properties["ProductID"] = OSNumber::withNumber(0x4b42, 32);
        IOService *interface = new IOService, *driver = new IOService;
        interface->meta.name = "IOHIDInterface";
        interface->open_ = true;
        interface->state = 6;
        driver->meta.name = "IOHIDEventDriver";
        driver->state = 6;
        interface->children.push_back(driver);
        hid->children.push_back(interface);
        hid->meta.name = "SnapI2CHIDDevice";
        hid->logRegistry("2 s");
        CHECK(logged("HID stack at 2 s: primary 1/6 pairs [1/6 12/1 65329/118] transport I2C built-in yes "
                     "vendor 0xb05 product 0x4b42"), "the matching properties are logged");
        CHECK(logged("SnapI2CHIDDevice: state 0x0") && logged("    IOHIDInterface: state 0x6 open") &&
              logged("      IOHIDEventDriver: state 0x6\n"), "and the clients above it, by class, state and open");
    } else if (s == "latency-waits") {
        // agents/input-latency T4: a transfer's wire time. Without the define, today's whole milliseconds.
        SnapI2CHIDBus::ioDelayUs(nullptr, 1193);                     // a 52-byte input read at 400 kHz
#if SNAP_I2C_HID_LATENCY
        CHECK(standin.sleep_ms == 1 && standin.sleeps == 1 && standin.delay_us == 193 && standin.delays == 1,
              "a 52-byte read waits 1 ms asleep and 193 us, not 2 ms");
#else
        CHECK(standin.sleep_ms == 2 && standin.delays == 0, "without the define: 2 ms of IOSleep, as b3d7fd99");
#endif
        standin.sleeps = standin.delays = 0; standin.sleep_ms = standin.delay_us = 0;
        SnapI2CHIDBus::ioDelayUs(nullptr, 186);                      // a status poll
        CHECK(standin.sleeps == 0 && standin.delay_us == 186, "a status poll is an IODelay below 1 ms, as before");
        standin.sleeps = standin.delays = 0; standin.sleep_ms = standin.delay_us = 0;
        SnapI2CHIDBus::ioDelayUs(nullptr, 2000);
        CHECK(standin.sleep_ms == 2 && standin.delays == 0, "whole milliseconds stay one IOSleep");
#if SNAP_I2C_HID_LATENCY
    } else if (s == "latency-bootarg") {
        // T1: snap_i2c_active_us: absent = 4000; 0 = the configured period throughout; below the floor = 2000.
        const struct { bool set; uint32_t value, want; } cases[] = {{false, 0, 4000}, {true, 0, 0}, {true, 1000, 2000},
                                                                     {true, 6000, 6000}};
        for (const auto &c : cases) {
            standin.boot_args.clear();
            if (c.set) standin.boot_args["snap_i2c_active_us"] = c.value;
            geni_reset();
            IOService *nub = keyboard_nub();
            SnapI2CHIDBus *bus = new SnapI2CHIDBus;
            CHECK(bus->start(nub), "the bus starts");
            CHECK(bus->fActiveUs == c.want, "the active period follows the boot-arg");
            bus->stop(nub);
            bus->release();
        }
    } else if (s == "latency-active" || s == "latency-slow-transfer" || s == "latency-slop") {
        // T1 T2 T3: the RUNNING schedule, on a bus whose transport is in RUNNING (the transfers are the transport
        // test's; here only what the glue arms after each step).
        IOService *nub = keyboard_nub();
        SnapI2CHIDBus *bus = new SnapI2CHIDBus;
        bus->fProvider = nub;
        bus->fDev = static_cast<struct i2c_hid_dev *>(IOMallocZero(sizeof(*bus->fDev)));
        bus->fDev->state = I2C_HID_S_RUNNING;
        bus->fCfg.poll_us = bus->fDev->cfg.poll_us = 8000;
        bus->fTimer = IOTimerEventSource::timerEventSource(bus, SnapI2CHIDBus::timerAction);
        bus->fActiveUs = 4000;
        uint64_t start = 1000000;                                    // us
        auto poll = [&](uint64_t took_us, bool report) {
            standin.now_ns = start * 1000u;
            const uint32_t before = bus->fDev->stats.reports;
            if (report) bus->fDev->stats.reports++;
            standin.now_ns += took_us * 1000u;
            bus->armNextStep(8000, start, before);
            const uint64_t due = bus->fTimer->due_ns / 1000u;
            start = due;                                             // the next poll starts when the timer fires
            return due;
        };
        if (s == "latency-active") {
            uint64_t s0 = start, due = poll(2300, false);
            CHECK(due == s0 + 8000, "idle: the next poll 8 ms after this one began, not after its 2.3 ms transfer");
            s0 = start; due = poll(2300, true);
            CHECK(due == s0 + 4000, "a report: the active period, 4 ms from this poll's start");
            const uint64_t report_at = s0 + 2300;
            unsigned active = 0;
            while (start < report_at + 500000 - 4000) { s0 = start; due = poll(1200, false); active += due == s0 + 4000; }
            CHECK(active >= 120, "the active period holds for 500 ms after the last report");
            s0 = start; due = poll(1200, false); s0 = start; due = poll(1200, false);
            CHECK(due == s0 + 8000, "then the configured 8 ms again");
            CHECK(bus->fActivePolls >= 120 && bus->fIdlePolls >= 2, "polls are counted by kind");
            // the active period never applies when it is not shorter than the configured one
            bus->fActiveUs = 9000; s0 = start; due = poll(1200, true);
            CHECK(due == s0 + 8000, "an active period longer than the configured one is not used");
            // snap_i2c_active_us=0 and every other state keep today's relative delay
            bus->fActiveUs = 0; standin.now_ns = 5000000000ull; bus->armNextStep(8000, 5000000, 0);
            CHECK(bus->fTimer->due_ns == 5000000000ull + 8000000u && !bus->fDeadlineUs, "active 0: today's 8 ms from now");
            bus->fActiveUs = 4000; bus->fDev->state = I2C_HID_S_RESET_WAIT; bus->armNextStep(10000, 5000000, 0);
            CHECK(bus->fTimer->due_ns == 5000000000ull + 10000000u, "outside RUNNING: today's relative delay");
        } else if (s == "latency-slow-transfer") {
            uint64_t s0 = start, due = poll(2000, false);
            CHECK(due == s0 + 8000, "a normal poll");
            s0 = start; due = poll(10000, false);                    // a 10 ms transfer: past its own deadline
            CHECK(due >= s0 + 10000 + 2000, "a step longer than the period leaves a quarter period (2 ms) after its end");
            s0 = start; due = poll(1000, false);
            CHECK(due == s0 + 8000, "and the schedule re-anchors on the next poll: no burst of catch-up polls");
            s0 = start; due = poll(40000, false);                    // far behind
            CHECK(due >= s0 + 40000 + 2000 && due <= s0 + 40000 + 8000, "far behind: one poll, not a burst");
        } else {
            // the timer fires 800 us late every time: the estimate converges and the poll is asked for early
            for (unsigned i = 0; i < 40; i++) {
                const uint64_t s0 = start;
                (void)poll(1200, false);
                const uint64_t fired = bus->fArmedForUs + 800;
                standin.now_ns = fired * 1000u;
                bus->noteWake(fired);
                start = fired;
                if (i == 39) {
                    const uint64_t lateness = fired > s0 + 8000 ? fired - (s0 + 8000) : (s0 + 8000) - fired;
                    CHECK(lateness * 10 < 8000, "the poll lands within 10% of its period");
                }
            }
            CHECK(bus->fSlopUs >= 700 && bus->fSlopUs <= 800, "the lateness estimate converges on 800 us");
            bus->fSlopUs = 5000;                                     // a huge estimate is capped at period / 8
            const uint64_t d0 = bus->fDeadlineUs;                   // this poll's deadline: the next is a period on
            standin.now_ns = start * 1000u + 1200000u;
            bus->armNextStep(8000, start, bus->fDev->stats.reports);
            CHECK(d0 && bus->fTimer->due_ns / 1000u == d0 + 8000 - 1000, "the lead is at most min(1 ms, period / 8)");
        }
        bus->fTimer->release();
        IOFree(bus->fDev, sizeof(*bus->fDev));
        bus->fDev = nullptr;
#endif
#if SNAP_I2C_HID_FNKEYS
    } else if (s.compare(0, 7, "fnkeys-") == 0) {
        if (!fnkeys_scenario(s)) {
            printf("unknown scenario %s\n", s.c_str());
            return 2;
        }
#endif
    } else {
        printf("unknown scenario %s\n", s.c_str());
        return 2;
    }
    printf("%s %s\n", failures ? "FAIL" : "PASS", s.c_str());
    return failures != 0;
}
