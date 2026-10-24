/* SPDX-License-Identifier: MIT */
/* The PM4 validator: register writes, state loads, draws, copies, events, dispatch
 * and packet checks.
 * Part of compat/adreno-ib-command.c's translation unit, included in order; not compiled on its own. */
/* ---- validation -------------------------------------------------------------------------------------------------- */
/* An address field whose dwords are at package offsets lo/hi (hi may be NONE): null (no address bits and no
 * relocation half on either dword), or exactly the relocation whose halves are lo and hi. *reloc: index or -1. */
static int match_field(struct adreno_ib_work *w, uint32_t lo, uint32_t hi, const struct field *f, int32_t *reloc)
{
    const uint8_t *p = w->package;
    int32_t i = find_lo(w, lo);
    *reloc = -1;
    if (i < 0) {
        if ((rd32(p + lo) & f->lo_address) || target(w, lo) ||
            (hi != NONE && ((rd32(p + hi) & f->hi_address) || target(w, hi))))
            return fail(w, ADRENO_IB_E_ADDRESS, lo);
        return 0;
    }
    const struct adreno_ib_reloc *r = &w->relocs[i];
    if (r->hi != hi || (hi != NONE && r->hi_bits != f->hi_bits) || r->align_log2 < f->align ||
        !(f->kinds & KIND(r->kind)) || (f->write && !(r->access & ADRENO_IB_ACCESS_WRITE)) ||
        (rd32(p + lo) & ((1u << r->align_log2) - 1u) & ~f->lo_other))
        return fail(w, ADRENO_IB_E_ADDRESS, lo);
    w->used[i] |= (uint8_t)(1u | (hi != NONE ? 2u : 0u));
    *reloc = i;
    return 0;
}

/* A T# array in the package data area: every descriptor's BASE, FLAG/U and V address pairs are null or relocated
 * (BASE_HI width), and no other descriptor dword carries a relocation half (design R3, defence in depth). */
static int check_textures(struct adreno_ib_work *w, int32_t i, uint64_t count, uint32_t at)
{
    const struct adreno_ib_reloc *r = &w->relocs[i];
    if (r->kind != ADRENO_IB_RELOC_PACKAGE || r->offset < w->data_offset) return fail(w, ADRENO_IB_E_ADDRESS, at);
    if (count > r->length / 64) return fail(w, ADRENO_IB_E_BOUNDS, at);
    for (uint64_t k = 0; k < count; k++) {
        const uint32_t base = (uint32_t)(r->offset + 64 * k);
        for (uint32_t d = 0; d < 16; d++) {
            if (d == A8XX_DESC_A8XX_TEX_MEMOBJ_0 || d == A8XX_DESC_A8XX_TEX_MEMOBJ_4 || d == A8XX_DESC_A8XX_TEX_MEMOBJ_8) {
                const struct field f = {
                    d == A8XX_DESC_A8XX_TEX_MEMOBJ_0 ? 0xffffffffu : A8XX_DESC_A8XX_TEX_MEMOBJ_4__FLAG_LO__MASK,
                    d == A8XX_DESC_A8XX_TEX_MEMOBJ_0 ? 0 : ~A8XX_DESC_A8XX_TEX_MEMOBJ_4__FLAG_LO__MASK,
                    A8XX_DESC_A8XX_TEX_MEMOBJ_1__BASE_HI__MASK, ADRENO_IB_HI_BITS_DESC, ADRENO_IB_ALIGN_LOG2_TEXTURE,
                    READ_KINDS, 0};
                int32_t j;
                int e = match_field(w, base + 4 * d, base + 4 * d + 4, &f, &j);
                if (e) return e;
                d++;   /* the high half belongs to the pair */
                continue;
            }
            if (target(w, base + 4 * d)) return fail(w, ADRENO_IB_E_RELOC, base + 4 * d);
        }
    }
    return 0;
}

/* Native CS storage contract (docs/USERSPACE-GRAPHICS-20261019.md): 1..ADRENO_IB_CS_STORAGE_MAX slots, each a zero
 * hole or a linear, single-layer 2D RGBA32F/RGBA16F/RGBA8 (WZYX) or BGRA8 (WXYZ) image with identity swizzle (MPS's
 * image integral: hole + RGBA32F; CoreImage: one BGRA8 or RGBA16F image). A table relocation is PACKAGE/READ; every
 * live image BASE is RESOURCE/WRITE. */
#define ADRENO_IB_CS_STORAGE_MAX 8u
#define ADRENO_IB_CS_TEXTURE_MAX 8u
#if ADRENO_IB_CS_SAMPLERS
_Static_assert(ADRENO_IB_CS_SAMPLER_UNITS_MAX <= ADRENO_IB_CS_TEXTURE_MAX,
               "a CS sampler table is never larger than the T# table it samples");
static uint32_t cs_sampler_units = 1u;
void adreno_ib_set_cs_sampler_units(uint32_t units)
{
    cs_sampler_units = units && units <= ADRENO_IB_CS_SAMPLER_UNITS_MAX ? units : 1u;
}
#define ADRENO_IB_CS_SAMPLER_UNITS cs_sampler_units
#else
#define ADRENO_IB_CS_SAMPLER_UNITS 1u
#endif
static int check_storage_images(struct adreno_ib_work *w, int32_t i, uint64_t count, uint32_t at)
{
    const struct adreno_ib_reloc *table = &w->relocs[i];
    if (table->kind != ADRENO_IB_RELOC_PACKAGE || table->offset < w->data_offset)
        return fail(w, ADRENO_IB_E_ADDRESS, at);
    if (!count || count > ADRENO_IB_CS_STORAGE_MAX || count > table->length / 64)
        return fail(w, ADRENO_IB_E_BOUNDS, at);
    for (uint64_t k = 0; k < count; k++) {
        const uint32_t base = (uint32_t)(table->offset + 64 * k);
        uint32_t d[16], nonzero = 0;
        for (unsigned n = 0; n < 16; n++) { d[n] = rd32(w->package + base + 4 * n); nonzero |= d[n]; }
        if (!nonzero) {
            for (unsigned n = 0; n < 16; n++)
                if (target(w, base + 4 * n)) return fail(w, ADRENO_IB_E_RELOC, base + 4 * n);
            continue;
        }
        const struct field image = {A8XX_DESC_A8XX_TEX_MEMOBJ_0__BASE_LO__MASK, 0,
            A8XX_DESC_A8XX_TEX_MEMOBJ_1__BASE_HI__MASK, ADRENO_IB_HI_BITS_DESC,
            ADRENO_IB_ALIGN_LOG2_TEXTURE, KIND(ADRENO_IB_RELOC_RESOURCE), 1};
        int32_t image_reloc;
        int e = match_field(w, base, base + 4, &image, &image_reloc);
        if (e) return e;
        if (image_reloc < 0) return fail(w, ADRENO_IB_E_ADDRESS, base);
        for (unsigned n = 2; n < 16; n++)
            if (target(w, base + 4 * n)) return fail(w, ADRENO_IB_E_RELOC, base + 4 * n);
#define DESC_GET(n, field) ((d[n] & A8XX_DESC_A8XX_TEX_MEMOBJ_##n##__##field##__MASK) >> \
                           A8XX_DESC_A8XX_TEX_MEMOBJ_##n##__##field##__SHIFT)
        const uint32_t width = DESC_GET(2, WIDTH), height = DESC_GET(2, HEIGHT);
        const uint64_t pitch_bits = DESC_GET(6, TEX_LINE_OFFSET), pitch = pitch_bits / 8;
        const uint64_t bytes = pitch * height;
        static const struct { uint32_t fmt, swap, cpp; } formats[] = {
            {A8XX_E_FMT6_32_32_32_32_FLOAT, A8XX_E_WZYX, 16}, {A8XX_E_FMT6_16_16_16_16_FLOAT, A8XX_E_WZYX, 8},
            {A8XX_E_FMT6_8_8_8_8_UNORM, A8XX_E_WZYX, 4}, {A8XX_E_FMT6_8_8_8_8_UNORM, A8XX_E_WXYZ, 4}};
        const uint32_t identity = A8XX_DESC_A8XX_TEX_MEMOBJ_3__SWIZ_X(A8XX_E_A8XX_SWIZ_X) |
            A8XX_DESC_A8XX_TEX_MEMOBJ_3__SWIZ_Y(A8XX_E_A8XX_SWIZ_Y) |
            A8XX_DESC_A8XX_TEX_MEMOBJ_3__SWIZ_Z(A8XX_E_A8XX_SWIZ_Z) |
            A8XX_DESC_A8XX_TEX_MEMOBJ_3__SWIZ_W(A8XX_E_A8XX_SWIZ_W);
        uint32_t cpp = 0;
        for (unsigned f = 0; f < sizeof formats / sizeof formats[0]; f++)
            if (d[3] == (A8XX_DESC_A8XX_TEX_MEMOBJ_3__FMT(formats[f].fmt) |
                         A8XX_DESC_A8XX_TEX_MEMOBJ_3__SWAP(formats[f].swap) | identity))
                cpp = formats[f].cpp;
        const uint32_t type = A8XX_DESC_A8XX_TEX_MEMOBJ_1__TYPE(A8XX_E_A6XX_TEX_2D) |
                              A8XX_DESC_A8XX_TEX_MEMOBJ_1__DEPTH(1);
        if ((d[0] & ~A8XX_DESC_A8XX_TEX_MEMOBJ_0__BASE_LO__MASK) ||
            (d[1] & ~A8XX_DESC_A8XX_TEX_MEMOBJ_1__BASE_HI__MASK) != type ||
            !width || width > 16384 || !height || height > 16384 || DESC_GET(2, SAMPLES) != A8XX_E_MSAA_ONE ||
            !cpp || d[4] || d[5] || !pitch || pitch_bits % 8 || pitch % 64 ||
            pitch < (uint64_t)width * cpp || DESC_GET(6, MIPLVLS) || DESC_GET(6, MIN_LINE_OFFSET) > 2 ||
            pitch % (64u << DESC_GET(6, MIN_LINE_OFFSET)) ||
            d[7] != A8XX_DESC_A8XX_TEX_MEMOBJ_7__ARRAY_SLICE_OFFSET((bytes + 4095) & ~4095ull))
            return fail(w, ADRENO_IB_E_PACKET, base);
        for (unsigned n = 8; n < 16; n++)
            if (d[n]) return fail(w, ADRENO_IB_E_PACKET, base + 4 * n);
        if (bytes > w->relocs[image_reloc].length) return fail(w, ADRENO_IB_E_BOUNDS, base);
#undef DESC_GET
    }
    return 0;
}

static void compute_register(struct adreno_ib_work *w, uint32_t reg, uint32_t value)
{
    unsigned index;
    if (reg >= A8XX_REG_SP_CS_NDRANGE_0 && reg <= A8XX_REG_SP_CS_NDRANGE_6) {
        index = reg - A8XX_REG_SP_CS_NDRANGE_0;
        w->cs_ndrange[index] = value; w->cs_seen |= 1u << index;
    } else if (reg == A8XX_REG_SP_CS_NDRANGE_7) {
        w->cs_ndrange[7] = value; w->cs_seen |= 1u << 7;
    } else if (reg >= A8XX_REG_SP_CS_KERNEL_GROUP_X && reg <= A8XX_REG_SP_CS_KERNEL_GROUP_Z) {
        index = reg - A8XX_REG_SP_CS_KERNEL_GROUP_X;
        w->cs_groups[index] = value; w->cs_seen |= 1u << (8 + index);
    }
}

/* One register write: `reg` takes the package dword at `at`. next_reg/next_at describe the packet's next write
 * (next_at NONE if there is none); *pair is set when that write was validated as this address's high half. */
static int reg_write(struct adreno_ib_work *w, uint32_t reg, uint32_t at, uint32_t next_reg, uint32_t next_at, int *pair)
{
    const struct adreno_ib_tables *t = w->tables;
    *pair = 0;
    if (reg >= ADRENO_IB_REG_LIMIT || !bit_get(t->allowed, reg)) return fail(w, ADRENO_IB_E_REGISTER, at);
    compute_register(w, reg, rd32(w->package + at));
    if (!bit_get(t->address, reg)) return 0;
    uint32_t half = 0;
    const struct a8xx_reg_info *row = address_row(t, reg, &half);
    struct field f;
    int textures;
    if (!row || !register_field(row->offset, &f, &textures)) return fail(w, ADRENO_IB_E_REGISTER, at);
    if (half) {   /* a high half that no relocated low half claimed: it must be null */
        if (rd32(w->package + at) || target(w, at)) return fail(w, ADRENO_IB_E_ADDRESS, at);
        return 0;
    }
    const uint32_t hi = next_at != NONE && next_reg == reg + 1 ? next_at : NONE;
    int32_t i;
    int e = match_field(w, at, hi, &f, &i);
    if (e) return e;
    if (i < 0) return 0;   /* null: a following high-half write is checked on its own */
    if (hi == NONE || next_reg >= ADRENO_IB_REG_LIMIT || !bit_get(t->allowed, next_reg))
        return fail(w, ADRENO_IB_E_ADDRESS, at);   /* a relocated register is written whole, in one packet */
    *pair = 1;
    if (textures) {
        const struct adreno_ib_reloc *r = &w->relocs[i];
        if (r->length % 64) return fail(w, ADRENO_IB_E_BOUNDS, at);
        return textures == 2 ? check_storage_images(w, i, r->length / 64, at) :
                               check_textures(w, i, r->length / 64, at);
    }
    return 0;
}

static int bunch(struct adreno_ib_work *w, uint32_t at, uint32_t count, int noncontext)
{
    const uint8_t *p = w->package;
    uint32_t first = 0;
    if (noncontext) {
        if (count < 2 || rd32(p + at) != 1 || rd32(p + at + 4)) return fail(w, ADRENO_IB_E_PACKET, at - 4);
        first = 2;
    }
    if (count < first + 2 || (count - first) % 2) return fail(w, ADRENO_IB_E_PACKET, at - 4);
    const uint32_t pairs = (count - first) / 2;
    for (uint32_t k = 0; k < pairs; k++) {
        const uint32_t reg_at = at + 4 * (first + 2 * k);
        uint32_t next_reg = 0, next_at = NONE;
        if (k + 1 < pairs) { next_reg = rd32(p + reg_at + 8); next_at = reg_at + 12; }
        int pair;
        int e = reg_write(w, rd32(p + reg_at), reg_at + 4, next_reg, next_at, &pair);
        if (e) return e;
        k += (uint32_t)pair;
    }
    return 0;
}

static int load_state(struct adreno_ib_work *w, uint32_t op, uint32_t at, uint32_t count)
{
    const uint8_t *p = w->package;
    if (count < 3) return fail(w, ADRENO_IB_E_PACKET, at - 4);
    const uint32_t w0 = rd32(p + at);
    const uint32_t type = (w0 & A8XX_PKT_CP_LOAD_STATE6_0__STATE_TYPE__MASK) >> A8XX_PKT_CP_LOAD_STATE6_0__STATE_TYPE__SHIFT;
    const uint32_t src = (w0 & A8XX_PKT_CP_LOAD_STATE6_0__STATE_SRC__MASK) >> A8XX_PKT_CP_LOAD_STATE6_0__STATE_SRC__SHIFT;
    const uint32_t block = (w0 & A8XX_PKT_CP_LOAD_STATE6_0__STATE_BLOCK__MASK) >> A8XX_PKT_CP_LOAD_STATE6_0__STATE_BLOCK__SHIFT;
    const uint32_t units = (w0 & A8XX_PKT_CP_LOAD_STATE6_0__NUM_UNIT__MASK) >> A8XX_PKT_CP_LOAD_STATE6_0__NUM_UNIT__SHIFT;
    const uint32_t ext_lo = at + 4 * A8XX_PKT_CP_LOAD_STATE6_1, ext_hi = at + 4 * A8XX_PKT_CP_LOAD_STATE6_2;
    if (type == A8XX_E_ST6_UBO && src == A8XX_E_SS6_DIRECT) {
        const int shader_block = op == A8XX_E_CP_LOAD_STATE6_GEOM ? block == A8XX_E_SB6_VS_SHADER :
                                 (block == A8XX_E_SB6_FS_SHADER || block == A8XX_E_SB6_CS_SHADER);
        if (!shader_block ||
            count != 3 + 2 * units || rd32(p + ext_lo) || rd32(p + ext_hi) || target(w, ext_lo) || target(w, ext_hi))
            return fail(w, ADRENO_IB_E_PACKET, at - 4);
        if (block == A8XX_E_SB6_CS_SHADER) {
            uint32_t dst = (w0 & A8XX_PKT_CP_LOAD_STATE6_0__DST_OFF__MASK) >> A8XX_PKT_CP_LOAD_STATE6_0__DST_OFF__SHIFT;
            if (!units || units > 2 || dst > 2 - units) return fail(w, ADRENO_IB_E_PACKET, at);
        }
        const struct field ubo = {0xffffffffu, 0, A8XX_DESC_A6XX_UBO_1__BASE_HI__MASK, ADRENO_IB_HI_BITS_DESC,
                                  ADRENO_IB_ALIGN_LOG2_UBO, KIND(ADRENO_IB_RELOC_RESOURCE) | KIND(ADRENO_IB_RELOC_PACKAGE), 0};
        for (uint32_t k = 0; k < units; k++) {
            const uint32_t lo = at + 12 + 8 * k, hi = lo + 4;
            int32_t i;
            int e = match_field(w, lo, hi, &ubo, &i);
            if (e) return e;
            if (i < 0) {   /* an unused slot is the all-zero descriptor (a sized null UBO would fault the SMMU) */
                if (rd32(p + hi)) return fail(w, ADRENO_IB_E_ADDRESS, hi);
                continue;
            }
            const uint64_t size = (uint64_t)((rd32(p + hi) & A8XX_DESC_A6XX_UBO_1__SIZE__MASK) >>
                                             A8XX_DESC_A6XX_UBO_1__SIZE__SHIFT) * 16;
            if (size > w->relocs[i].length) return fail(w, ADRENO_IB_E_BOUNDS, lo);
        }
        return 0;
    }
    const int cs_uav = block == A8XX_E_SB6_CS_SHADER && type == A8XX_E_ST6_UAV;
    const int texture_load = (block == A8XX_E_SB6_FS_TEX || block == A8XX_E_SB6_CS_TEX) &&
                             (type == A8XX_E_ST6_SHADER || type == A8XX_E_ST6_CONSTANTS);
    if (src == A8XX_E_SS6_INDIRECT && op == A8XX_E_CP_LOAD_STATE6_FRAG && (texture_load || cs_uav)) {
        if (count != 3) return fail(w, ADRENO_IB_E_PACKET, at - 4);
        /* CS samplers: one unit (ADRENO_IB_CS_SAMPLERS: up to adreno_ib_set_cs_sampler_units' count, bounded by the
         * relocation below). CS T#s: 1..ADRENO_IB_CS_TEXTURE_MAX units (CoreImage's T#1 with a null T#0), each
         * checked by check_textures below. */
        if (block == A8XX_E_SB6_CS_TEX &&
            (!units || units > (type == A8XX_E_ST6_CONSTANTS ? ADRENO_IB_CS_TEXTURE_MAX : ADRENO_IB_CS_SAMPLER_UNITS) ||
             (w0 & A8XX_PKT_CP_LOAD_STATE6_0__DST_OFF__MASK)))
            return fail(w, ADRENO_IB_E_PACKET, at);
        const struct field ext = {A8XX_PKT_CP_LOAD_STATE6_1__EXT_SRC_ADDR__MASK, 0, 0xffffffffu, ADRENO_IB_HI_BITS_REG64,
                                  ADRENO_IB_ALIGN_LOG2_LOAD_STATE, KIND(ADRENO_IB_RELOC_PACKAGE), 0};
        int32_t i;
        int e = match_field(w, ext_lo, ext_hi, &ext, &i);
        if (e) return e;
        if (i < 0) return fail(w, ADRENO_IB_E_ADDRESS, ext_lo);   /* an indirect load needs a source */
        if (cs_uav) {
            if (w0 & A8XX_PKT_CP_LOAD_STATE6_0__DST_OFF__MASK) return fail(w, ADRENO_IB_E_PACKET, at);
            return check_storage_images(w, i, units, ext_lo);
        }
        if (type == A8XX_E_ST6_CONSTANTS) return check_textures(w, i, units, ext_lo);
        if ((uint64_t)units * 16 > w->relocs[i].length) return fail(w, ADRENO_IB_E_BOUNDS, ext_lo);
        return 0;
    }
    return fail(w, ADRENO_IB_E_PACKET, at - 4);
}

static int draw(struct adreno_ib_work *w, uint32_t at, uint32_t count)
{
    const uint8_t *p = w->package;
    if (!count) return fail(w, ADRENO_IB_E_PACKET, at - 4);
    const uint32_t d0 = rd32(p + at);
    const uint32_t prim = (d0 & A8XX_PKT_CP_DRAW_INDX_OFFSET_0__PRIM_TYPE__MASK) >> A8XX_PKT_CP_DRAW_INDX_OFFSET_0__PRIM_TYPE__SHIFT;
    const uint32_t source = (d0 & A8XX_PKT_CP_DRAW_INDX_OFFSET_0__SOURCE_SELECT__MASK) >>
                            A8XX_PKT_CP_DRAW_INDX_OFFSET_0__SOURCE_SELECT__SHIFT;
    const uint32_t vis = (d0 & A8XX_PKT_CP_DRAW_INDX_OFFSET_0__VIS_CULL__MASK) >> A8XX_PKT_CP_DRAW_INDX_OFFSET_0__VIS_CULL__SHIFT;
    const uint32_t size = (d0 & A8XX_PKT_CP_DRAW_INDX_OFFSET_0__INDEX_SIZE__MASK) >> A8XX_PKT_CP_DRAW_INDX_OFFSET_0__INDEX_SIZE__SHIFT;
    const uint32_t patch = (d0 & A8XX_PKT_CP_DRAW_INDX_OFFSET_0__PATCH_TYPE__MASK) >> A8XX_PKT_CP_DRAW_INDX_OFFSET_0__PATCH_TYPE__SHIFT;
    const uint32_t known = A8XX_PKT_CP_DRAW_INDX_OFFSET_0__PRIM_TYPE__MASK | A8XX_PKT_CP_DRAW_INDX_OFFSET_0__SOURCE_SELECT__MASK |
                           A8XX_PKT_CP_DRAW_INDX_OFFSET_0__VIS_CULL__MASK | A8XX_PKT_CP_DRAW_INDX_OFFSET_0__INDEX_SIZE__MASK |
                           A8XX_PKT_CP_DRAW_INDX_OFFSET_0__PATCH_TYPE__MASK;   /* GS/TESS enables stay clear */
    const int prim_ok = prim == A8XX_E_DI_PT_TRILIST || prim == A8XX_E_DI_PT_TRISTRIP || prim == A8XX_E_DI_PT_TRIFAN ||
                        prim == A8XX_E_DI_PT_LINELIST || prim == A8XX_E_DI_PT_LINESTRIP || prim == A8XX_E_DI_PT_POINTLIST;
    if ((d0 & ~known) || !prim_ok || vis > A8XX_E_USE_VISIBILITY || patch != A8XX_E_TESS_QUADS)
        return fail(w, ADRENO_IB_E_PACKET, at - 4);
    if (count == 3)
        return source == A8XX_E_DI_SRC_SEL_AUTO_INDEX && size == A8XX_E_INDEX4_SIZE_8_BIT ? 0 :
               fail(w, ADRENO_IB_E_PACKET, at - 4);
    if (count != 7 || source != A8XX_E_DI_SRC_SEL_DMA ||
        (size != A8XX_E_INDEX4_SIZE_16_BIT && size != A8XX_E_INDEX4_SIZE_32_BIT))
        return fail(w, ADRENO_IB_E_PACKET, at - 4);
    const struct field index = {0xffffffffu, 0, 0xffffffffu, ADRENO_IB_HI_BITS_REG64,
                                size == A8XX_E_INDEX4_SIZE_16_BIT ? ADRENO_IB_ALIGN_LOG2_INDEX16 : 2,
                                KIND(ADRENO_IB_RELOC_RESOURCE) | KIND(ADRENO_IB_RELOC_PACKAGE), 0};
    const uint32_t base = at + 4 * A8XX_PKT_A5XX_CP_DRAW_INDX_OFFSET_INDX_BASE;
    int32_t i;
    int e = match_field(w, base, base + 4, &index, &i);
    if (e) return e;
    if (i < 0) return fail(w, ADRENO_IB_E_ADDRESS, base);
    const uint64_t indices = rd32(p + at + 4 * A8XX_PKT_A5XX_CP_DRAW_INDX_OFFSET_6);
    if (indices * (size == A8XX_E_INDEX4_SIZE_16_BIT ? 2u : 4u) > w->relocs[i].length)
        return fail(w, ADRENO_IB_E_BOUNDS, at + 4 * A8XX_PKT_A5XX_CP_DRAW_INDX_OFFSET_6);
    return 0;
}

/* CP_MEMCPY is an ordered resource copy, never an arbitrary physical write. */
static int memory_copy(struct adreno_ib_work *w, uint32_t at, uint32_t count)
{
    if (count != 5) return fail(w, ADRENO_IB_E_PACKET, at - 4);
    const uint64_t bytes = (uint64_t)rd32(w->package + at) * 4;
    if (!bytes || target(w, at)) return fail(w, ADRENO_IB_E_PACKET, at);
    const struct field source = {0xffffffffu, 0, 0xffffffffu, ADRENO_IB_HI_BITS_REG64, 2,
                                  KIND(ADRENO_IB_RELOC_RESOURCE), 0};
    const struct field destination = {0xffffffffu, 0, 0xffffffffu, ADRENO_IB_HI_BITS_REG64, 2,
                                       KIND(ADRENO_IB_RELOC_RESOURCE), 1};
    int32_t src, dst;
    int e = match_field(w, at + 4, at + 8, &source, &src);
    if (e) return e;
    e = match_field(w, at + 12, at + 16, &destination, &dst);
    if (e) return e;
    if (src < 0 || dst < 0 || !(w->relocs[src].access & ADRENO_IB_ACCESS_READ))
        return fail(w, ADRENO_IB_E_ADDRESS, at);
    if (bytes > w->relocs[src].length || bytes > w->relocs[dst].length)
        return fail(w, ADRENO_IB_E_BOUNDS, at);
    const uint64_t src_address = (uint64_t)rd32(w->package + at + 4) |
                                (uint64_t)rd32(w->package + at + 8) << 32;
    const uint64_t dst_address = (uint64_t)rd32(w->package + at + 12) |
                                (uint64_t)rd32(w->package + at + 16) << 32;
    if (src_address > UINT64_MAX - bytes || dst_address > UINT64_MAX - bytes ||
        (src_address < dst_address + bytes && dst_address < src_address + bytes))
        return fail(w, ADRENO_IB_E_BOUNDS, at);
    return 0;
}

static int event_allowed(uint32_t event)
{
    switch (event) {
    case A8XX_E_CCU_CLEAN_COLOR: case A8XX_E_CCU_CLEAN_DEPTH: case A8XX_E_CCU_INVALIDATE_COLOR:
    case A8XX_E_CCU_INVALIDATE_DEPTH: case A8XX_E_CACHE_CLEAN: case A8XX_E_CACHE_INVALIDATE7:
    case A8XX_E_LRZ_CACHE_FLUSH: case A8XX_E_DUMMY_EVENT: case A8XX_E_SUBPASS_FENCE: case A8XX_E_DEBUG_LABEL:
        return 1;
    }
    return 0;
}

static int compute_dispatch(struct adreno_ib_work *w, uint32_t at, uint32_t count)
{
    if (count != 4 || rd32(w->package + at) || w->cs_seen != 0x7ffu)
        return fail(w, ADRENO_IB_E_PACKET, at - 4);
    const uint32_t d = w->cs_ndrange[0];
    const uint32_t local[3] = {
        ((d & A8XX_REG_SP_CS_NDRANGE_0__LOCALSIZEX__MASK) >> A8XX_REG_SP_CS_NDRANGE_0__LOCALSIZEX__SHIFT) + 1,
        ((d & A8XX_REG_SP_CS_NDRANGE_0__LOCALSIZEY__MASK) >> A8XX_REG_SP_CS_NDRANGE_0__LOCALSIZEY__SHIFT) + 1,
        ((d & A8XX_REG_SP_CS_NDRANGE_0__LOCALSIZEZ__MASK) >> A8XX_REG_SP_CS_NDRANGE_0__LOCALSIZEZ__SHIFT) + 1};
    const uint32_t dim = (d & A8XX_REG_SP_CS_NDRANGE_0__KERNELDIM__MASK) >> A8XX_REG_SP_CS_NDRANGE_0__KERNELDIM__SHIFT;
    const uint32_t last = A8XX_REG_SP_CS_NDRANGE_7__LOCALSIZEX(local[0] - 1) |
                         A8XX_REG_SP_CS_NDRANGE_7__LOCALSIZEY(local[1] - 1) |
                         A8XX_REG_SP_CS_NDRANGE_7__LOCALSIZEZ(local[2] - 1);
    if (!dim || dim > 3 || (uint64_t)local[0] * local[1] * local[2] > 1024 || w->cs_ndrange[7] != last)
        return fail(w, ADRENO_IB_E_PACKET, at - 4);
    for (unsigned axis = 0; axis < 3; axis++) {
        uint32_t groups = rd32(w->package + at + 4 * (axis + 1));
        uint64_t global = (uint64_t)groups * local[axis];
        if (!groups || groups != w->cs_groups[axis] || global > UINT32_MAX ||
            global != w->cs_ndrange[1 + 2 * axis] || w->cs_ndrange[2 + 2 * axis] ||
            (axis >= dim && (groups != 1 || local[axis] != 1)))
            return fail(w, ADRENO_IB_E_PACKET, at + 4 * (axis + 1));
    }
    w->cs_seen = 0;                   /* every later dispatch must provide a fresh full geometry */
    return 0;
}

static int packet7(struct adreno_ib_work *w, uint32_t op, uint32_t at, uint32_t count)
{
    const uint8_t *p = w->package;
    const uint32_t v = count ? rd32(p + at) : 0;
    int ok = 0;
    switch (op) {
    case A8XX_E_CP_NOP: return 0;   /* skipped by the CP; a relocation inside it is never consumed */
    case A8XX_E_CP_WAIT_FOR_IDLE: case A8XX_E_CP_CCHE_INVALIDATE:
    case A8XX_E_CP_WAIT_MEM_WRITES: ok = !count; break;
    case A8XX_E_CP_SET_MODE: ok = count == 1 && v <= 1; break;
    case A8XX_E_CP_THREAD_CONTROL:
        ok = count == 1 && (v & A8XX_PKT_CP_THREAD_CONTROL_0__THREAD__MASK) &&
             !(v & ~(A8XX_PKT_CP_THREAD_CONTROL_0__THREAD__MASK | A8XX_PKT_CP_THREAD_CONTROL_0__CONCURRENT_BIN_DISABLE__MASK |
                     A8XX_PKT_CP_THREAD_CONTROL_0__SYNC_THREADS__MASK));
        break;
    case A8XX_E_CP_SET_MARKER:
        ok = count == 1 && (v == A8XX_PKT_A8XX_CP_SET_MARKER_0__MODE(A8XX_E_RM6_DIRECT_RENDER) ||
                            v == A8XX_PKT_A8XX_CP_SET_MARKER_0__MODE(A8XX_E_RM6_BLIT2DSCALE) ||
                            v == A8XX_PKT_A8XX_CP_SET_MARKER_0__MODE(A8XX_E_RM6_COMPUTE));
        break;
    case A8XX_E_CP_SKIP_IB2_ENABLE_GLOBAL: case A8XX_E_CP_SKIP_IB2_ENABLE_LOCAL: case A8XX_E_CP_SET_VISIBILITY_OVERRIDE:
        ok = count == 1 && v <= 1;
        break;
    case A8XX_E_CP_EVENT_WRITE7:   /* the event alone: no memory write, no IRQ, no sample counts */
        ok = count == 1 && !(v & ~A8XX_PKT_CP_EVENT_WRITE7_0__EVENT__MASK) &&
             event_allowed((v & A8XX_PKT_CP_EVENT_WRITE7_0__EVENT__MASK) >> A8XX_PKT_CP_EVENT_WRITE7_0__EVENT__SHIFT);
        break;
    case A8XX_E_CP_SET_DRAW_STATE:   /* only "disable all groups": a group would run an unvalidated IB */
        ok = count == 3 && v == A8XX_PKT_CP_SET_DRAW_STATE__0__DISABLE_ALL_GROUPS__MASK && !rd32(p + at + 4) &&
             !rd32(p + at + 8);
        break;
    case A8XX_E_CP_BLIT: ok = count == 1 && v == A8XX_PKT_CP_BLIT_0__OP(A8XX_E_BLIT_OP_SCALE); break;
    case A8XX_E_CP_CONTEXT_REG_BUNCH: return bunch(w, at, count, 0);
    case A8XX_E_CP_NON_CONTEXT_REG_BUNCH: return bunch(w, at, count, 1);
    case A8XX_E_CP_LOAD_STATE6_GEOM: case A8XX_E_CP_LOAD_STATE6_FRAG: return load_state(w, op, at, count);
    case A8XX_E_CP_DRAW_INDX_OFFSET: return draw(w, at, count);
    case A8XX_E_CP_EXEC_CS: return compute_dispatch(w, at, count);
    case A8XX_E_CP_MEMCPY: return memory_copy(w, at, count);
    }
    return ok ? 0 : fail(w, ADRENO_IB_E_PACKET, at - 4);
}

int adreno_ib_validate(struct adreno_ib_work *w)
{
    if (!w || !w->tables) return ADRENO_LIST_E_ARGUMENT;
    if (!w->package_bytes) return fail(w, ADRENO_IB_E_FORMAT, 0);
    const uint8_t *p = w->package;
    const uint32_t n = w->command.ib_dwords;
    w->cs_seen = 0;
    for (uint32_t i = 0; i < w->command.reloc_count; i++) w->used[i] = 0;
    for (uint32_t at = 0; at < n;) {
        const uint32_t h = rd32(p + 4ull * at), payload = at + 1;
        if ((h & 0xf0000000u) == A8XX_E_CP_TYPE4_PKT) {
            const uint32_t count = h & A8XX_PKT4_COUNT_MASK, reg = (h >> 8) & A8XX_PKT4_REG_MASK;
            if (h != a8xx_pkt4_hdr(reg, count) || !count || count > n - payload)
                return fail(w, ADRENO_IB_E_PACKET, 4ull * at);
            for (uint32_t k = 0; k < count; k++) {
                int pair;
                int e = reg_write(w, reg + k, 4 * (payload + k), reg + k + 1,
                                  k + 1 < count ? 4 * (payload + k + 1) : NONE, &pair);
                if (e) return e;
                k += (uint32_t)pair;
            }
            at = payload + count;
            continue;
        }
        if ((h & 0xf0000000u) == A8XX_E_CP_TYPE7_PKT) {
            const uint32_t count = h & A8XX_PKT7_COUNT_MASK, op = (h >> 16) & A8XX_PKT7_OPCODE_MASK;
            if (h != a8xx_pkt7_hdr(op, count) || count > n - payload) return fail(w, ADRENO_IB_E_PACKET, 4ull * at);
            int e = packet7(w, op, 4 * payload, count);
            if (e) return e;
            at = payload + count;
            continue;
        }
        return fail(w, ADRENO_IB_E_PACKET, 4ull * at);
    }
    /* Every relocation half inside the IB must have been claimed by an address field above. */
    const uint64_t ib = 4ull * n;
    for (uint32_t i = 0; i < w->command.reloc_count; i++) {
        const struct adreno_ib_reloc *r = &w->relocs[i];
        if ((r->lo < ib && !(w->used[i] & 1)) || (r->hi != NONE && r->hi < ib && !(w->used[i] & 2)))
            return fail(w, ADRENO_IB_E_RELOC, i);
    }
    return 0;
}

/* ---- submission ------------------------------------------------------------------------------------------------- */
int adreno_ib_resource_range(const struct adreno_resource *r, uint64_t offset, uint64_t bytes, uint64_t *address)
{
    if (!r || !address) return ADRENO_RESOURCE_E_STATE;
    *address = 0;
    if (r->flags != (ADRENO_RESOURCE_RESERVED | ADRENO_RESOURCE_PINNED) || !r->length || !r->logical_length ||
        r->logical_length > r->length || r->mapped_length != r->length)
        return ADRENO_RESOURCE_E_STATE;
    if (!bytes || offset > r->logical_length || bytes > r->logical_length - offset ||
        r->address < ADRENO_WINDOW_BASE || r->address >= ADRENO_WINDOW_END || r->length > ADRENO_WINDOW_END - r->address)
        return ADRENO_RESOURCE_E_RANGE;
    *address = r->address + offset;
    return 0;
}

int adreno_ib_classify(const struct adreno_ib_reply *r)
{
    if (!r) return ADRENO_SUBMIT_E_UNCERTAIN;
    if (!r->status) return r->marker && r->wptr < RING_LIMIT ? 0 : ADRENO_SUBMIT_E_UNCERTAIN;
    if (r->marker) return ADRENO_SUBMIT_E_UNCERTAIN;   /* a failure never carries a completion marker */
    switch (r->status) {
    case ADRENO_IB_E_GPU_ERROR: return ADRENO_IB_E_GPU_ERROR;
#if ADRENO_GPU_RECOVER
    case ADRENO_IB_E_RESET: case ADRENO_IB_E_RESET_FAULT: return (int)r->status;
#endif
    case ADRENO_E_PARAMS: case ADRENO_E_WINDOW: case ADRENO_E_TARGET: case ADRENO_E_CX: case ADRENO_E_GX:
    case ADRENO_E_HALT: case ADRENO_E_CB0: case ADRENO_E_FAULT: case ADRENO_E_SQE: case ADRENO_E_RING:
    case ADRENO_IB_E_BUSY: case ADRENO_IB_E_STICKY:
        return ADRENO_SUBMIT_E_INACTIVE;   /* adreno-guest.h: refused before any ring write */
    }
    return ADRENO_SUBMIT_E_UNCERTAIN;      /* ADRENO_IB_E_UNCERTAIN and anything undocumented */
}

