/* SPDX-License-Identifier: MIT */
/* The keyboard's Fn-key layer (drivers/snap-i2c-hid/src/hid-keyboard.c, SNAP_I2C_HID_FNKEYS). Part of
 * tools/test-snap-i2c-hid.c, included there in order when it is built with -DSNAP_I2C_HID_FNKEYS=1; not compiled on
 * its own. The usages each code must become are written out here from hid-keyboard.h's evidence, not read back
 * from the implementation's tables, so a wrong table entry fails a check. */

static struct hid_fnkeys_note fnotes[160];
static uint8_t fnote_raw[160][16];
static unsigned nfnotes;

static void fn_note(void *ctx, const struct hid_fnkeys_note *n)
{
    (void)ctx;
    if (nfnotes < 160) {
        fnotes[nfnotes] = *n;
        if (n->raw) {
            REQUIRE(n->raw_len <= 16);
            memcpy(fnote_raw[nfnotes], n->raw, n->raw_len);
            fnotes[nfnotes].raw = fnote_raw[nfnotes];
        }
    }
    nfnotes++;
}

static int fn_vendor(struct hid_fnkeys *fn, struct hid_kbd_state *st, const uint8_t codes[5])
{
    uint8_t r[6] = {0x5a, 0, 0, 0, 0, 0};
    memcpy(r + 1, codes, 5);
    return hid_fnkeys_translate(fn, st, r, 6, kbd_emit, NULL, fn_note, NULL);
}
static int fn_code(struct hid_fnkeys *fn, struct hid_kbd_state *st, uint8_t a, uint8_t b)
{
    const uint8_t codes[5] = {a, b, 0, 0, 0};
    return fn_vendor(fn, st, codes);
}
static int fn_keys(struct hid_fnkeys *fn, struct hid_kbd_state *st, uint8_t mods, const uint8_t *k, unsigned nk)
{
    uint8_t r[9] = {0x36, mods, 0, 0, 0, 0, 0, 0, 0};
    memcpy(r + 3, k, nk);
    return hid_fnkeys_translate(fn, st, r, 9, kbd_emit, NULL, fn_note, NULL);
}
static int fn_key(struct hid_fnkeys *fn, struct hid_kbd_state *st, uint8_t mods, uint8_t key)
{
    return fn_keys(fn, st, mods, &key, key ? 1u : 0u);
}
static int fn_consumer(struct hid_fnkeys *fn, struct hid_kbd_state *st, uint16_t usage)
{
    const uint8_t r[3] = {0x37, (uint8_t)usage, (uint8_t)(usage >> 8)};
    return hid_fnkeys_translate(fn, st, r, 3, kbd_emit, NULL, fn_note, NULL);
}
/* One key down then up, as exactly the two events (page, usage, 1), (page, usage, 0); 0/0: none. */
static int fn_pair(unsigned from, uint32_t page, uint32_t usage)
{
    if (!page && !usage)
        return nkev == from;
    return nkev == from + 2 && kev_is(from, page, usage, 1) && kev_is(from + 1, page, usage, 0);
}
static void fn_start(struct hid_fnkeys *fn, struct hid_kbd_state *st, uint32_t flags)
{
    REQUIRE(hid_fnkeys_init(fn, flags) == HID_FNKEYS_OK);
    memset(st, 0, sizeof(*st));
    nkev = 0;
    nfnotes = 0;
}

static void test_fnkeys_init(void)
{
    struct hid_fnkeys fn;
    uint16_t p, u;
    CHECK(hid_fnkeys_init(&fn, 0) == HID_FNKEYS_OK && fn.flags == 0);
    CHECK(hid_fnkeys_init(&fn, 0x20) == HID_FNKEYS_REFUSED_BITS && fn.flags == 0);
    CHECK(hid_fnkeys_init(&fn, 0x80000001u) == HID_FNKEYS_REFUSED_BITS && fn.flags == 0);
    CHECK(hid_fnkeys_init(&fn, 0x01 | 0x18) == HID_FNKEYS_REFUSED_ENCODING && fn.flags == 0);
    CHECK(hid_fnkeys_init(&fn, 0x04) == HID_FNKEYS_REFUSED_LOCK && fn.flags == 0);
    CHECK(hid_fnkeys_init(&fn, 0x06) == HID_FNKEYS_REFUSED_LOCK && fn.flags == 0);
    CHECK(hid_fnkeys_init(&fn, 0x08) == HID_FNKEYS_OK && fn.flags == 0);       /* an encoding alone: off */
    CHECK(hid_fnkeys_init(&fn, 0x05) == HID_FNKEYS_OK && fn.flags == 0x05);
    CHECK(hid_fnkeys_init(&fn, 0x17) == HID_FNKEYS_OK && fn.flags == 0x17);
    CHECK(hid_fnkeys_init(&fn, 0x02) == HID_FNKEYS_OK && fn.flags == 0x02 && !fn.lock && !fn.yielded);
    CHECK(strcmp(hid_fnkeys_init_name(HID_FNKEYS_REFUSED_BITS), hid_fnkeys_init_name(HID_FNKEYS_REFUSED_LOCK)) != 0);
    /* The three brightness encodings (hid-keyboard.h): top case is the MacBook keyboard's. */
    CHECK(hid_fnkeys_init(&fn, 0x01) == HID_FNKEYS_OK);
    hid_fnkeys_brightness(&fn, 0, &p, &u);
    CHECK(p == 0x00ff && u == 0x0005);
    hid_fnkeys_brightness(&fn, 1, &p, &u);
    CHECK(p == 0x00ff && u == 0x0004);
    CHECK(hid_fnkeys_init(&fn, 0x09) == HID_FNKEYS_OK);
    hid_fnkeys_brightness(&fn, 0, &p, &u);
    CHECK(p == 0xff01 && u == 0x0021);
    hid_fnkeys_brightness(&fn, 1, &p, &u);
    CHECK(p == 0xff01 && u == 0x0020);
    CHECK(hid_fnkeys_init(&fn, 0x11) == HID_FNKEYS_OK);
    hid_fnkeys_brightness(&fn, 0, &p, &u);
    CHECK(p == 0x000c && u == 0x0070);
    hid_fnkeys_brightness(&fn, 1, &p, &u);
    CHECK(p == 0x000c && u == 0x006f);
}

/* Report 90's codes: each one pressed and released alone. */
static void test_fnkeys_vendor(void)
{
    static const struct { uint8_t code; uint16_t page, usage; } mapped[] = {
        {0x10, 0x00ff, 0x0005}, {0x20, 0x00ff, 0x0004},      /* brightness down, up */
        {0xc7, 0x00ff, 0x0007}, {0xc4, 0x00ff, 0x0008}, {0xc5, 0x00ff, 0x0009},   /* keyboard light */
        {0x7c, 0x0001, 0x00a9},                              /* microphone mute */
    };
    static const uint8_t unmapped[] = {0x6b, 0x82, 0x85, 0x86, 0x4e, 0x7e, 0x5f, 0x8b, 0x9d, 0xcb, 0x38, 0x35, 0x01};
    struct hid_fnkeys fn;
    struct hid_kbd_state st;

    fn_start(&fn, &st, HID_FNKEYS_TRANSLATE);
    for (size_t i = 0; i < sizeof(mapped) / sizeof(mapped[0]); i++) {
        unsigned from = nkev;
        CHECK(fn_code(&fn, &st, mapped[i].code, 0) == HID_KBD_EVENTS);
        CHECK(fn_code(&fn, &st, 0, 0) == HID_KBD_EVENTS);
        CHECK(fn_pair(from, mapped[i].page, mapped[i].usage));
    }
    for (size_t i = 0; i < sizeof(unmapped); i++) {
        unsigned from = nkev, before = fn.unmapped;
        CHECK(fn_code(&fn, &st, unmapped[i], 0) == HID_KBD_EVENTS && fn.unmapped == before + 1);
        CHECK(fn_code(&fn, &st, 0, 0) == HID_KBD_EVENTS && nkev == from);
    }
    CHECK(fn.lock == 0 && fn.lock_toggles == 0);          /* 0x4E without HID_FNKEYS_HOST_LOCK: nothing */
    /* 0x00 and 0xFF are no code. */
    {
        unsigned before = fn.unmapped;
        const uint8_t none[5] = {0xff, 0xff, 0, 0xff, 0};
        nkev = 0;
        CHECK(fn_vendor(&fn, &st, none) == HID_KBD_EVENTS && nkev == 0 && fn.unmapped == before);
        CHECK(fn.vendor[0] == 0 && fn.vendor[1] == 0);
    }
    /* A code listed twice is one press; two codes are two; each is released when it leaves the array. */
    nkev = 0;
    CHECK(fn_code(&fn, &st, 0x10, 0x10) == HID_KBD_EVENTS && nkev == 1 && kev_is(0, 0xff, 5, 1));
    CHECK(fn_code(&fn, &st, 0x10, 0x20) == HID_KBD_EVENTS && nkev == 2 && kev_is(1, 0xff, 4, 1));
    CHECK(fn_code(&fn, &st, 0x10, 0x20) == HID_KBD_EVENTS && nkev == 2);          /* repeated: nothing */
    CHECK(fn_code(&fn, &st, 0x20, 0) == HID_KBD_EVENTS && nkev == 3 && kev_is(2, 0xff, 5, 0));
    /* Another length is refused and changes nothing: 0x20 stays down. */
    {
        static const uint8_t five[5] = {0x5a, 0, 0, 0, 0}, seven[7] = {0x5a, 0x10, 0, 0, 0, 0, 0};
        CHECK(hid_fnkeys_translate(&fn, &st, five, 5, kbd_emit, NULL, fn_note, NULL) == HID_KBD_BAD_LENGTH);
        CHECK(hid_fnkeys_translate(&fn, &st, seven, 7, kbd_emit, NULL, fn_note, NULL) == HID_KBD_BAD_LENGTH);
        CHECK(nkev == 3 && fn.vendor[0] == 0x20);
    }
    CHECK(fn_code(&fn, &st, 0, 0) == HID_KBD_EVENTS && nkev == 4 && kev_is(3, 0xff, 4, 0));
    /* The other encodings. */
    fn_start(&fn, &st, HID_FNKEYS_TRANSLATE | (HID_FNKEYS_BRIGHTNESS_APPLE_KEYBOARD << HID_FNKEYS_BRIGHTNESS_SHIFT));
    fn_code(&fn, &st, 0x10, 0);
    fn_code(&fn, &st, 0x20, 0);
    fn_code(&fn, &st, 0, 0);
    CHECK(nkev == 4 && kev_is(0, 0xff01, 0x21, 1) && kev_is(1, 0xff01, 0x21, 0) && kev_is(2, 0xff01, 0x20, 1));
    fn_start(&fn, &st, HID_FNKEYS_TRANSLATE | (HID_FNKEYS_BRIGHTNESS_CONSUMER << HID_FNKEYS_BRIGHTNESS_SHIFT));
    fn_code(&fn, &st, 0x10, 0);
    fn_code(&fn, &st, 0, 0);
    CHECK(fn_pair(0, 0x0c, 0x70));
    /* Without TRANSLATE (the raw log alone) report 90 dispatches nothing, as without the layer. */
    fn_start(&fn, &st, HID_FNKEYS_RAW_LOG);
    fn_code(&fn, &st, 0x10, 0);
    fn_code(&fn, &st, 0x20, 0x7c);
    fn_code(&fn, &st, 0, 0);
    CHECK(nkev == 0);
}

/* Reports 54 and 55 through the layer: brightness translated, everything else exactly hid_kbd_translate's. */
static void test_fnkeys_consumer_and_keys(void)
{
    struct hid_fnkeys fn;
    struct hid_kbd_state st;
    static const uint32_t flag_sets[] = {HID_FNKEYS_TRANSLATE, HID_FNKEYS_RAW_LOG,
                                         HID_FNKEYS_TRANSLATE | HID_FNKEYS_HOST_LOCK};

    fn_start(&fn, &st, HID_FNKEYS_TRANSLATE);
    fn_consumer(&fn, &st, 0x70);
    fn_consumer(&fn, &st, 0);
    CHECK(fn_pair(0, 0xff, 5));
    fn_consumer(&fn, &st, 0x6f);
    fn_consumer(&fn, &st, 0xe9);                          /* brightness up released before volume up */
    fn_consumer(&fn, &st, 0);
    CHECK(nkev == 6 && kev_is(2, 0xff, 4, 1) && kev_is(3, 0xff, 4, 0) && kev_is(4, 12, 0xe9, 1) &&
          kev_is(5, 12, 0xe9, 0));
    nkev = 0;
    fn_consumer(&fn, &st, 0xe2);
    fn_consumer(&fn, &st, 0xcd);
    fn_consumer(&fn, &st, 0);
    CHECK(nkev == 4 && kev_is(0, 12, 0xe2, 1) && kev_is(1, 12, 0xe2, 0) && kev_is(2, 12, 0xcd, 1));
    fn_start(&fn, &st, HID_FNKEYS_TRANSLATE | (HID_FNKEYS_BRIGHTNESS_CONSUMER << HID_FNKEYS_BRIGHTNESS_SHIFT));
    fn_consumer(&fn, &st, 0x70);
    fn_consumer(&fn, &st, 0);
    CHECK(fn_pair(0, 12, 0x70));

    /* Typing, F-keys and modifiers: the same events, in the same order, as without the layer (lock off). */
    for (size_t f = 0; f < sizeof(flag_sets) / sizeof(flag_sets[0]); f++) {
        static const struct { uint8_t mods, keys[3]; } script[] = {
            {0x00, {0x04}}, {0x00, {0}}, {0x02, {0x05, 0x06}}, {0x02, {0x06}}, {0x00, {0}}, {0x00, {0x3a}},
            {0x00, {0x3a, 0x45}}, {0x00, {0}}, {0x01, {0x3e}}, {0x05, {0x3e, 0x4f}}, {0x00, {0}}, {0x00, {0x29}},
            {0x00, {0x01, 0x01, 0x01}}, {0x00, {0x66}}, {0x00, {0}},
        };
        uint32_t want[64][3];
        unsigned nwant;
        struct hid_kbd_state plain;
        memset(&plain, 0, sizeof(plain));
        nkev = 0;
        for (size_t i = 0; i < sizeof(script) / sizeof(script[0]); i++)
            kbd_report(&plain, script[i].mods, script[i].keys, 3);
        nwant = nkev;
        REQUIRE(nwant <= 64);
        memcpy(want, kev, sizeof(want));
        fn_start(&fn, &st, flag_sets[f]);
        for (size_t i = 0; i < sizeof(script) / sizeof(script[0]); i++)
            fn_keys(&fn, &st, script[i].mods, script[i].keys, 3);
        CHECK(nkev == nwant && !memcmp(kev, want, sizeof(kev[0]) * nwant));
    }
}

/* HID_FNKEYS_HOST_LOCK: Fn+Esc (0x4E) swaps the F-row's hotkeys and F1-F12. */
static void test_fnkeys_lock(void)
{
    struct hid_fnkeys fn;
    struct hid_kbd_state st;
    static const struct { uint8_t code, fkey; } row[] = {
        {0xc7, 0x3d}, {0x10, 0x3e}, {0x20, 0x3f}, {0x6b, 0x42}, {0x7c, 0x43}, {0x82, 0x44}, {0x85, 0x44}, {0x86, 0x45},
    };
    static const struct { uint8_t fkey; uint16_t page, usage; } fkeys[] = {
        {0x3a, 0x0c, 0xe2}, {0x3b, 0x0c, 0xea}, {0x3c, 0x0c, 0xe9}, {0x3d, 0xff, 0x07}, {0x3e, 0xff, 0x05},
        {0x3f, 0xff, 0x04}, {0x40, 0xff, 0x06}, {0x41, 0, 0}, {0x42, 0, 0}, {0x43, 0x01, 0xa9}, {0x44, 0, 0},
        {0x45, 0, 0},
    };

    fn_start(&fn, &st, HID_FNKEYS_TRANSLATE | HID_FNKEYS_HOST_LOCK);
    fn_code(&fn, &st, 0x10, 0);
    fn_code(&fn, &st, 0, 0);
    fn_key(&fn, &st, 0, 0x3e);
    fn_key(&fn, &st, 0, 0);
    CHECK(nkev == 4 && kev_is(0, 0xff, 5, 1) && kev_is(2, 7, 0x3e, 1) && kev_is(3, 7, 0x3e, 0));   /* lock off */
    nkev = 0;
    CHECK(fn_code(&fn, &st, 0x4e, 0) == HID_KBD_EVENTS && fn.lock == 1 && fn.lock_toggles == 1 && nkev == 0);
    CHECK(fn_code(&fn, &st, 0x4e, 0) == HID_KBD_EVENTS && fn.lock == 1 && fn.lock_toggles == 1);   /* held: once */
    CHECK(fn_code(&fn, &st, 0, 0) == HID_KBD_EVENTS && fn.lock == 1 && nkev == 0);     /* not again on release */
    for (size_t i = 0; i < sizeof(row) / sizeof(row[0]); i++) {
        unsigned from = nkev;
        fn_code(&fn, &st, row[i].code, 0);
        fn_code(&fn, &st, 0, 0);
        CHECK(fn_pair(from, 7, row[i].fkey));
    }
    {
        unsigned from = nkev;                             /* off the F-row: still its function */
        fn_code(&fn, &st, 0xc4, 0);
        fn_code(&fn, &st, 0, 0);
        CHECK(fn_pair(from, 0xff, 0x08));
        from = nkev;
        fn_consumer(&fn, &st, 0xe2);
        fn_consumer(&fn, &st, 0x70);
        fn_consumer(&fn, &st, 0);
        CHECK(nkev == from + 4 && kev_is(from, 7, 0x3a, 1) && kev_is(from + 1, 7, 0x3a, 0) &&
              kev_is(from + 2, 7, 0x3e, 1) && kev_is(from + 3, 7, 0x3e, 0));
    }
    for (size_t i = 0; i < sizeof(fkeys) / sizeof(fkeys[0]); i++) {
        unsigned from = nkev;
        fn_key(&fn, &st, 0, fkeys[i].fkey);
        fn_key(&fn, &st, 0, 0);
        CHECK(fn_pair(from, fkeys[i].page, fkeys[i].usage));
    }
    {
        unsigned from = nkev;                             /* everything else unchanged */
        fn_key(&fn, &st, 0x02, 0x04);
        fn_key(&fn, &st, 0, 0);
        CHECK(nkev == from + 4 && kev_is(from, 7, 0xe1, 1) && kev_is(from + 1, 7, 4, 1));
    }
    /* A key held while the lock flips is released as what it was pressed as. */
    nkev = 0;
    CHECK(fn.lock == 1);
    fn_code(&fn, &st, 0x10, 0);                           /* F5 */
    fn_key(&fn, &st, 0, 0x3f);                            /* brightness up */
    fn_code(&fn, &st, 0x10, 0x4e);                        /* lock off while both are down */
    CHECK(fn.lock == 0 && fn.lock_toggles == 2);
    fn_code(&fn, &st, 0, 0);
    fn_key(&fn, &st, 0, 0);
    CHECK(nkev == 4 && kev_is(0, 7, 0x3e, 1) && kev_is(1, 0xff, 4, 1) && kev_is(2, 7, 0x3e, 0) &&
          kev_is(3, 0xff, 4, 0));
    nkev = 0;
    fn_code(&fn, &st, 0x10, 0);
    fn_code(&fn, &st, 0, 0);
    CHECK(fn_pair(0, 0xff, 5));                           /* and the lock is off again */
}

/* Yielding to an event driver: reports 54 and 55 are its, report 90 stays ours. */
static void test_fnkeys_yield(void)
{
    struct hid_fnkeys fn;
    struct hid_kbd_state st;
    fn_start(&fn, &st, HID_FNKEYS_TRANSLATE);
    fn_key(&fn, &st, 0x02, 0x04);
    fn_consumer(&fn, &st, 0x70);
    fn_code(&fn, &st, 0x20, 0);
    CHECK(nkev == 4);
    nkev = 0;
    hid_fnkeys_release_keyboard(&fn, &st, kbd_emit, NULL);
    CHECK(nkev == 3 && kev_is(0, 7, 0xe1, 0) && kev_is(1, 7, 4, 0) && kev_is(2, 0xff, 5, 0));
    fn.yielded = 1;
    nkev = 0;
    CHECK(fn_key(&fn, &st, 0, 0x05) == HID_KBD_IGNORED && fn_consumer(&fn, &st, 0x6f) == HID_KBD_IGNORED && nkev == 0);
    CHECK(fn_code(&fn, &st, 0x10, 0) == HID_KBD_EVENTS && nkev == 2 && kev_is(0, 0xff, 4, 0) && kev_is(1, 0xff, 5, 1));
    nkev = 0;
    hid_fnkeys_release_all(&fn, &st, kbd_emit, NULL);
    CHECK(nkev == 1 && kev_is(0, 0xff, 5, 0) && fn.vendor[0] == 0);
    nkev = 0;
    hid_fnkeys_release_all(&fn, &st, kbd_emit, NULL);
    CHECK(nkev == 0);
    fn.yielded = 0;                                       /* resumed from a clean state, as the glue does */
    memset(&st, 0, sizeof(st));
    fn_key(&fn, &st, 0, 0x05);
    CHECK(nkev == 1 && kev_is(0, 7, 5, 1));
}

/* The raw log: what it names and, above all, what it never names. */
static void test_fnkeys_notes(void)
{
    struct hid_fnkeys fn;
    struct hid_kbd_state st;

    /* Every key that types a character, alone and with Shift, Control, Option: no note. */
    fn_start(&fn, &st, HID_FNKEYS_TRANSLATE | HID_FNKEYS_RAW_LOG);
    for (unsigned mods = 0; mods < 4; mods++)
        for (unsigned k = 0x04; k <= 0x65; k++) {
            if (k >= 0x3a && k <= 0x53)
                continue;
            fn_key(&fn, &st, (uint8_t)(mods == 0 ? 0 : mods == 1 ? 0x02 : mods == 2 ? 0x01 : 0x04), (uint8_t)k);
            fn_key(&fn, &st, 0, 0);
        }
    {
        static const uint8_t many[6] = {0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
        fn_keys(&fn, &st, 0x22, many, 6);                 /* Shift and a burst in one report: no chord */
        fn_keys(&fn, &st, 0, NULL, 0);
    }
    CHECK(nfnotes == 0);
    /* F1-F12 and the navigation band: one note per transition, with what was dispatched. */
    for (unsigned k = 0x3a; k <= 0x45; k++) {
        unsigned from = nfnotes;
        fn_key(&fn, &st, 0x01, (uint8_t)k);
        fn_key(&fn, &st, 0x00, 0);
        CHECK(nfnotes == from + 2 && fnotes[from].kind == HID_FNKEYS_NOTE_KEY && fnotes[from].code == k &&
              fnotes[from].down == 1 && fnotes[from].mods == 0x01 && fnotes[from].out_page == 7 &&
              fnotes[from].out_usage == k && !fnotes[from].raw && fnotes[from + 1].down == 0);
    }
    nfnotes = 0;
    fn_key(&fn, &st, 0, 0x4a);
    fn_key(&fn, &st, 0, 0);
    CHECK(nfnotes == 2 && fnotes[0].kind == HID_FNKEYS_NOTE_KEY && fnotes[0].code == 0x4a);
    /* F23 with Shift and GUI (Windows' Copilot key): past the logical maximum, named, not dispatched. */
    nfnotes = 0;
    nkev = 0;
    fn_key(&fn, &st, 0x0a, 0x72);
    fn_key(&fn, &st, 0x00, 0);
    CHECK(nfnotes == 2 && fnotes[0].kind == HID_FNKEYS_NOTE_RANGE && fnotes[0].code == 0x72 && fnotes[0].down == 1 &&
          fnotes[0].mods == 0x0a && fnotes[1].kind == HID_FNKEYS_NOTE_RANGE && fnotes[1].down == 0);
    CHECK(nkev == 4 && kev_is(0, 7, 0xe1, 1) && kev_is(1, 7, 0xe3, 1));   /* only the modifiers */
    /* GUI and a key down in one report: a chord. GUI first, then the key: no chord. */
    nfnotes = 0;
    fn_key(&fn, &st, 0x08, 0x13);
    fn_key(&fn, &st, 0x00, 0);
    CHECK(nfnotes == 1 && fnotes[0].kind == HID_FNKEYS_NOTE_CHORD && fnotes[0].code == 0x13 && fnotes[0].mods == 0x08);
    nfnotes = 0;
    fn_key(&fn, &st, 0x80, 0);
    fn_key(&fn, &st, 0x80, 0x16);
    fn_key(&fn, &st, 0x00, 0);
    CHECK(nfnotes == 0);
    /* Report 90: its bytes and what each code became. */
    nfnotes = 0;
    fn_code(&fn, &st, 0x10, 0x6b);
    fn_code(&fn, &st, 0, 0);
    CHECK(nfnotes == 4 && fnotes[0].kind == HID_FNKEYS_NOTE_VENDOR && fnotes[0].code == 0x10 && fnotes[0].down &&
          fnotes[0].out_page == 0xff && fnotes[0].out_usage == 5 && fnotes[0].raw_len == 6 &&
          !memcmp(fnotes[0].raw, "\x5a\x10\x6b\x00\x00\x00", 6));
    CHECK(fnotes[1].code == 0x6b && fnotes[1].out_page == 0 && fnotes[1].out_usage == 0);
    CHECK(fnotes[2].code == 0x10 && !fnotes[2].down && fnotes[3].code == 0x6b && !fnotes[3].down);
    /* Report 55, an unknown report, and report 90 at another length. */
    nfnotes = 0;
    fn_consumer(&fn, &st, 0xe9);
    fn_consumer(&fn, &st, 0);
    {
        static const uint8_t unknown[5] = {0x07, 1, 2, 3, 4}, five[5] = {0x5a, 0x10, 0, 0, 0};
        CHECK(hid_fnkeys_translate(&fn, &st, unknown, 5, kbd_emit, NULL, fn_note, NULL) == HID_KBD_IGNORED);
        CHECK(hid_fnkeys_translate(&fn, &st, five, 5, kbd_emit, NULL, fn_note, NULL) == HID_KBD_BAD_LENGTH);
    }
    CHECK(nfnotes == 4 && fnotes[0].kind == HID_FNKEYS_NOTE_CONSUMER && fnotes[0].code == 0xe9 &&
          fnotes[0].out_page == 12 && fnotes[0].out_usage == 0xe9);
    CHECK(fnotes[2].kind == HID_FNKEYS_NOTE_REPORT && fnotes[2].id == 7 && fnotes[2].code == 5 &&
          fnotes[2].raw_len == 5 && !memcmp(fnotes[2].raw, "\x07\x01\x02\x03\x04", 5));
    CHECK(fnotes[3].kind == HID_FNKEYS_NOTE_REPORT && fnotes[3].id == 0x5a && fnotes[3].code == 5);
    /* Yielded: notes from the device's own state, with nothing of ours dispatched; still no characters. */
    fn.yielded = 1;
    nfnotes = 0;
    nkev = 0;
    fn_key(&fn, &st, 0, 0x3e);
    fn_key(&fn, &st, 0, 0x04);
    fn_key(&fn, &st, 0, 0);
    CHECK(nkev == 0 && nfnotes == 2 && fnotes[0].kind == HID_FNKEYS_NOTE_KEY && fnotes[0].code == 0x3e &&
          fnotes[0].out_page == 0 && fnotes[1].down == 0);
    fn.yielded = 0;
    /* The host lock's flips. */
    fn_start(&fn, &st, HID_FNKEYS_TRANSLATE | HID_FNKEYS_RAW_LOG | HID_FNKEYS_HOST_LOCK);
    fn_code(&fn, &st, 0x4e, 0);
    CHECK(nfnotes == 2 && fnotes[0].kind == HID_FNKEYS_NOTE_LOCK && fnotes[0].down == 1 &&
          fnotes[1].kind == HID_FNKEYS_NOTE_VENDOR && fnotes[1].code == 0x4e);
    /* Without HID_FNKEYS_RAW_LOG: no note at all. */
    fn_start(&fn, &st, HID_FNKEYS_TRANSLATE | HID_FNKEYS_HOST_LOCK);
    fn_key(&fn, &st, 0x08, 0x3e);
    fn_key(&fn, &st, 0x0a, 0x72);
    fn_code(&fn, &st, 0x10, 0x4e);
    fn_consumer(&fn, &st, 0xe9);
    {
        static const uint8_t unknown[3] = {0x07, 1, 2};
        hid_fnkeys_translate(&fn, &st, unknown, 3, kbd_emit, NULL, fn_note, NULL);
    }
    CHECK(nfnotes == 0);
}

static void test_fnkeys_rate(void)
{
    struct hid_fnkeys_rate rate;
    unsigned allowed = 0;
    memset(&rate, 0, sizeof(rate));
    for (unsigned i = 0; i < 40; i++)
        allowed += (unsigned)hid_fnkeys_rate_allow(&rate, 1000000);
    CHECK(allowed == HID_FNKEYS_RATE_BURST && rate.dropped == 40 - HID_FNKEYS_RATE_BURST);
    CHECK(!hid_fnkeys_rate_allow(&rate, 1000000 + HID_FNKEYS_RATE_REFILL_US - 1));
    CHECK(hid_fnkeys_rate_allow(&rate, 1000000 + HID_FNKEYS_RATE_REFILL_US));
    CHECK(!hid_fnkeys_rate_allow(&rate, 1000000 + HID_FNKEYS_RATE_REFILL_US + 1));
    CHECK(!hid_fnkeys_rate_allow(&rate, 900000));                    /* time going back refills nothing */
    allowed = 0;
    for (unsigned i = 0; i < 40; i++)                                /* a long pause refills only the burst */
        allowed += (unsigned)hid_fnkeys_rate_allow(&rate, 60000000);
    CHECK(allowed == HID_FNKEYS_RATE_BURST);
    /* The lifetime cap holds whatever the time. */
    {
        uint64_t t = 60000000;
        while (rate.lines < HID_FNKEYS_RATE_LIFETIME) {
            t += HID_FNKEYS_RATE_REFILL_US;
            REQUIRE(hid_fnkeys_rate_allow(&rate, t));
        }
        CHECK(!hid_fnkeys_rate_allow(&rate, t + 3600000000ull) && rate.lines == HID_FNKEYS_RATE_LIFETIME);
    }
}

/* Report 90 end to end: the A16 keyboard model sends it through the GENI model and the transport, which delivers it
 * (its 6 bytes are what the descriptor declares), and the layer turns it into brightness. */
static void test_fnkeys_transport(void)
{
    static const uint8_t down[] = {0x5a, 0x20, 0, 0, 0, 0}, up[] = {0x5a, 0, 0, 0, 0, 0};
    struct hid_fnkeys fn;
    struct hid_kbd_state st;
    begin_keyboard(GENI_I2C_IRQ_EVENTS);
    run_until(&DEV, I2C_HID_S_READY, 64);
    CHECK(i2c_hid_run(&DEV) == I2C_HID_R_OK);
    CHECK(hid_rdesc_report_bytes(&DEV.rinfo, HID_REPORT_INPUT, HID_KBD_REPORT_VENDOR) == HID_KBD_VENDOR_BYTES);
    dev_push(&KBD, down, sizeof(down));
    dev_push(&KBD, up, sizeof(up));
    poll_ticks(&DEV, 2);
    CHECK(ndelivered == 2 && delivered_len[0] == 6 && delivered_len[1] == 6);
    fn_start(&fn, &st, HID_FNKEYS_TRANSLATE);
    for (uint32_t i = 0; i < ndelivered; i++)
        hid_fnkeys_translate(&fn, &st, delivered[i], delivered_len[i], kbd_emit, NULL, NULL, NULL);
    CHECK(fn_pair(0, 0xff, 4));
    check_clean();
}

static void test_fnkeys(void)
{
    test_fnkeys_init();
    test_fnkeys_vendor();
    test_fnkeys_consumer_and_keys();
    test_fnkeys_lock();
    test_fnkeys_yield();
    test_fnkeys_notes();
    test_fnkeys_rate();
    test_fnkeys_transport();
}
