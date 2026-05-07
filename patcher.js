// Valheim KeyManager DRM Bypasser
//
// License: MIT


// Magic byte patterns
// IL patcher falls back to this.
const magicPatterns = [
    {
        pattern: "012B01160D092C0820E54959C8252B06",
        offset: 6,
        patchValue: 0x2D
    }
];

function h(x) {
    return x.match(/.{1,2}/g).map(v => parseInt(v, 16));
}

function fnd(buf, p) {
    for (let i = 0; i <= buf.length - p.length; i++) {
        let m = 1;
        for (let j = 0; j < p.length; j++) {
            if (buf[i + j] != p[j]) { m = 0; break; }
        }
        if (m) return i;
    }
    return -1;
}

// IL-level .NET assembly patcher

// Known identifiers in KeyManager DRM
const KM_NS       = "KeyManager";
const KM_TYPE     = "KeyManager";
const KM_CHECK    = "CheckAllowed";
const KM_LIC_TYPE = "hLMfzAbLmwherEVpUSIwXsUbDQAVA";
const KM_ABORT    = "DdTLCbDRTTpbVzNKpUBDJoCGHzNQ";
const KM_LOGGER   = "KLaieQNEwJKtgTCxmbpdGBVwcqCzA";

// IL opcodes
const IL_RET      = 0x2A;
const IL_LDC_I4_2 = 0x18;

// CorElementType values used in method signatures
const ET_VOID      = 0x01;
const ET_I4        = 0x08;
const ET_VALUETYPE = 0x11;
const ET_CLASS     = 0x12;

// Binary reading helpers
function u8(b, o)  { return b[o]; }
function u16(b, o) { return (b[o] | (b[o + 1] << 8)) >>> 0; }
function u32(b, o) { return (b[o] | (b[o+1]<<8) | (b[o+2]<<16) | (b[o+3]<<24)) >>> 0; }
function rdIdx(b, o, sz) { return sz === 4 ? u32(b, o) : u16(b, o); }

// Read null-terminated UTF-8 string from byte array
function nulStr(b, off) {
    let e = off;
    while (e < b.length && b[e] !== 0) e++;
    return new TextDecoder().decode(b.slice(off, e));
}

// Read ECMA-335 compressed unsigned integer (II.23.2)
function rdCompInt(b, pos) {
    if (pos >= b.length) return { val: 0, next: pos + 1 };
    const v = b[pos];
    if ((v & 0x80) === 0) return { val: v, next: pos + 1 };
    if ((v & 0xC0) === 0x80) {
        const val = pos + 1 < b.length ? ((v & 0x3F) << 8) | b[pos + 1] : 0;
        return { val, next: pos + 2 };
    }
    const val = ((v & 0x1F) << 24) |
                (pos + 1 < b.length ? b[pos + 1] << 16 : 0) |
                (pos + 2 < b.length ? b[pos + 2] << 8  : 0) |
                (pos + 3 < b.length ? b[pos + 3]       : 0);
    return { val: val >>> 0, next: pos + 4 };
}

// Convert RVA to file offset using the section table
function rva2off(sects, rva) {
    for (const s of sects) {
        const limit = s.va + (s.vs > 0 ? s.vs : s.rs);
        if (rva >= s.va && rva < limit)
            return s.rp + (rva - s.va);
    }
    return -1;
}

// PE header parsing
// Returns { sects, cliRVA } or null if not a .NET PE file
function parsePE(b) {
    if (b.length < 0x40) return null;
    const peOff = u32(b, 0x3C);
    if (peOff + 4 > b.length || u32(b, peOff) !== 0x00004550) return null;
    const coffOff  = peOff + 4;
    const numSects = u16(b, coffOff + 2);
    const optHdrSz = u16(b, coffOff + 16);
    const optOff   = coffOff + 20;
    const pe32plus = u16(b, optOff) === 0x20B;
    // CLI header is data directory entry #14
    const ddOff    = optOff + (pe32plus ? 112 : 96);
    const cliRVA   = u32(b, ddOff + 14 * 8);
    if (!cliRVA) return null;
    const sectBase = optOff + optHdrSz;
    const sects = [];
    for (let i = 0; i < numSects; i++) {
        const s = sectBase + i * 40;
        sects.push({ va: u32(b,s+12), vs: u32(b,s+8), rp: u32(b,s+20), rs: u32(b,s+16) });
    }
    return { sects, cliRVA };
}

// ECMA-335 metadata parsing
// Returns a context object or null if not a valid managed assembly
function parseMeta(b, sects, cliRVA) {
    const cliOff = rva2off(sects, cliRVA);
    if (cliOff < 0) return null;
    const mdRVA = u32(b, cliOff + 8);
    const mdOff = rva2off(sects, mdRVA);
    if (mdOff < 0 || u32(b, mdOff) !== 0x424A5342) return null; // "BSJB"
    const vLen  = u32(b, mdOff + 12);
    const vPad  = (vLen + 3) & ~3;
    const numSt = u16(b, mdOff + 16 + vPad + 2);
    let pos = mdOff + 16 + vPad + 4;
    let strBase = -1, tblBase = -1, blobBase = -1;
    for (let i = 0; i < numSt; i++) {
        const relOff = u32(b, pos); pos += 4;
        /* size */     u32(b, pos); pos += 4;
        const nStart = pos;
        while (pos < b.length && b[pos] !== 0) pos++;
        const name = new TextDecoder().decode(b.slice(nStart, pos));
        pos++; // null terminator
        // Align name field to 4-byte boundary from its start
        pos = nStart + (((pos - nStart) + 3) & ~3);
        const abs = mdOff + relOff;
        if      (name === "#Strings")           strBase  = abs;
        else if (name === "#~" || name === "#-") tblBase  = abs;
        else if (name === "#Blob")              blobBase = abs;
    }
    if (strBase < 0 || tblBase < 0) return null;
    // HeapSizes flags: bit0=#Strings 4-byte idx, bit1=#GUID 4-byte, bit2=#Blob 4-byte
    const hs  = b[tblBase + 6];
    const ss  = (hs & 1) ? 4 : 2;
    const gs  = (hs & 2) ? 4 : 2;
    const bs  = (hs & 4) ? 4 : 2;
    const vlo = u32(b, tblBase + 8);
    const vhi = u32(b, tblBase + 12);
    const rc  = new Array(64).fill(0);
    let rp = tblBase + 24;
    for (let t = 0; t < 64; t++) {
        const bit = t < 32 ? (vlo >>> t) & 1 : (vhi >>> (t - 32)) & 1;
        if (bit) { rc[t] = u32(b, rp); rp += 4; }
    }
    return { b, sects, strBase, tblBase, blobBase, tblData: rp, ss, bs, gs, rc };
}

// Compute metadata table row sizes and starting file offsets (ECMA-335 II.22)
function buildTblInfo(ctx) {
    const { rc, ss, bs, gs } = ctx;
    // Simple table index: 2 bytes unless the table has >65535 rows
    const si = t => rc[t] > 65535 ? 4 : 2;
    // Coded index: bits = tag width, ts = participating table IDs (-1 = unused slot)
    const ci = (bits, ts) => {
        const mx = Math.max(...ts.map(t => t < 0 ? 0 : (rc[t] || 0)));
        return mx < (1 << (16 - bits)) ? 2 : 4;
    };
    // Pre-compute all coded index sizes
    const tdo = ci(2, [0x02,0x01,0x1B]);                                          // TypeDefOrRef
    const hco = ci(2, [0x04,0x08,0x17]);                                          // HasConstant
    const hca = ci(5, [0x06,0x04,0x01,0x02,0x08,0x09,0x0A,0x00,0x0E,0x17,0x14,    // HasCustomAttribute
                       0x11,0x1A,0x1B,0x20,0x23,0x26,0x27,0x28,0x2A,0x2C,0x2B]);
    const hfm = ci(1, [0x04,0x08]);                                               // HasFieldMarshal
    const hds = ci(2, [0x02,0x06,0x20]);                                          // HasDeclSecurity
    const mrp = ci(3, [0x02,0x01,0x1A,0x06,0x1B]);                                // MemberRefParent
    const hse = ci(1, [0x14,0x17]);                                               // HasSemantics
    const mdr = ci(1, [0x06,0x0A]);                                               // MethodDefOrRef
    const mfw = ci(1, [0x04,0x06]);                                               // MemberForwarded
    const imp = ci(2, [0x26,0x23,0x27]);                                          // Implementation
    const cat = ci(3, [-1,-1,0x06,0x0A,-1]);                                      // CustomAttributeType
    const rsc = ci(2, [0x00,0x1A,0x23,0x01]);                                     // ResolutionScope
    const tmd = ci(1, [0x02,0x06]);                                               // TypeOrMethodDef
    
    // Row sizes indexed by table number (ECMA-335 II.22.*)
    const rs = new Array(64).fill(0);
    rs[0x00] = 2+ss+gs+gs+gs;                 // Module
    rs[0x01] = rsc+ss+ss;                     // TypeRef
    rs[0x02] = 4+ss+ss+tdo+si(0x04)+si(0x06); // TypeDef
    rs[0x03] = si(0x04);                      // FieldPtr (ENC)
    rs[0x04] = 2+ss+bs;                       // Field
    rs[0x05] = si(0x06);                      // MethodPtr (ENC)
    rs[0x06] = 4+2+2+ss+bs+si(0x08);          // MethodDef
    rs[0x07] = si(0x08);                      // ParamPtr (ENC)
    rs[0x08] = 2+2+ss;                        // Param
    rs[0x09] = si(0x02)+tdo;                  // InterfaceImpl
    rs[0x0A] = mrp+ss+bs;                     // MemberRef
    rs[0x0B] = 2+hco+bs;                      // Constant
    rs[0x0C] = hca+cat+bs;                    // CustomAttribute
    rs[0x0D] = hfm+bs;                        // FieldMarshal
    rs[0x0E] = 2+hds+bs;                      // DeclSecurity
    rs[0x0F] = 2+4+si(0x02);                  // ClassLayout
    rs[0x10] = 4+si(0x04);                    // FieldLayout
    rs[0x11] = bs;                            // StandAloneSig
    rs[0x12] = si(0x02)+si(0x14);             // EventMap
    rs[0x13] = si(0x14);                      // EventPtr (ENC)
    rs[0x14] = 2+ss+tdo;                      // Event
    rs[0x15] = si(0x02)+si(0x17);             // PropertyMap
    rs[0x16] = si(0x17);                      // PropertyPtr (ENC)
    rs[0x17] = 2+ss+bs;                       // Property
    rs[0x18] = 2+si(0x06)+hse;                // MethodSemantics
    rs[0x19] = si(0x02)+mdr+mdr;              // MethodImpl
    rs[0x1A] = ss;                            // ModuleRef
    rs[0x1B] = bs;                            // TypeSpec
    rs[0x1C] = 2+mfw+ss+si(0x1A);             // ImplMap
    rs[0x1D] = 4+si(0x04);                    // FieldRVA
    rs[0x1E] = 8;                             // ENCLog (Token + FuncCode)
    rs[0x1F] = 4;                             // ENCMap (Token)
    rs[0x20] = 4+2+2+2+2+4+bs+ss+ss;          // Assembly
    rs[0x21] = 4;                             // AssemblyProcessor
    rs[0x22] = 4+4+4;                         // AssemblyOS
    rs[0x23] = 2+2+2+2+4+bs+ss+ss+bs;         // AssemblyRef
    rs[0x24] = 4+si(0x23);                    // AssemblyRefProcessor
    rs[0x25] = 4+4+4+si(0x23);                // AssemblyRefOS
    rs[0x26] = 4+ss+bs;                       // File
    rs[0x27] = 4+4+ss+ss+imp;                 // ExportedType
    rs[0x28] = 4+4+ss+imp;                    // ManifestResource
    rs[0x29] = si(0x02)+si(0x02);             // NestedClass
    rs[0x2A] = 2+2+tmd+ss;                    // GenericParam
    rs[0x2B] = mdr+bs;                        // MethodSpec
    rs[0x2C] = si(0x2A)+tdo;                  // GenericParamConstraint

    // Compute starting file offset for each table's data
    const tblOffs = new Array(64).fill(-1);
    let off = ctx.tblData;
    for (let t = 0; t < 64; t++) {
        if (rc[t] > 0) { tblOffs[t] = off; off += rc[t] * rs[t]; }
    }
    return { rs, tblOffs, tdo, rsc, mrp };
}

// Metadata table row readers

function rdStr(ctx, idx) { return nulStr(ctx.b, ctx.strBase + idx); }

// Read blob bytes from #Blob heap
function rdBlob(ctx, idx) {
    if (ctx.blobBase < 0) return null;
    const pos = ctx.blobBase + idx;
    if (pos >= ctx.b.length) return null;
    const { val: len, next } = rdCompInt(ctx.b, pos);
    return ctx.b.slice(next, next + len);
}

// Read TypeDef row (1-based index)
function rdTypeDef(ctx, ti, idx1) {
    const { b, ss, rc } = ctx;
    const { rs, tblOffs, tdo } = ti;
    if (tblOffs[0x02] < 0 || idx1 < 1 || idx1 > rc[0x02]) return null;
    let p = tblOffs[0x02] + (idx1 - 1) * rs[0x02];
    const flags   = u32(b, p); p += 4;
    const nameIdx = rdIdx(b, p, ss); p += ss;
    const nsIdx   = rdIdx(b, p, ss); p += ss;
    const exRaw   = rdIdx(b, p, tdo); p += tdo;
    const fsi = rc[0x04] > 65535 ? 4 : 2;
    const msi = rc[0x06] > 65535 ? 4 : 2;
    const fieldList  = rdIdx(b, p, fsi); p += fsi;
    const methodList = rdIdx(b, p, msi);
    return {
        flags,
        name: rdStr(ctx, nameIdx), ns: rdStr(ctx, nsIdx),
        extendsTag: exRaw & 0x3, extendsIdx: exRaw >> 2,
        fieldList, methodList
    };
}

// Return the exclusive-end MethodDef index for a given TypeDef
function methodEnd(ctx, ti, tdIdx1) {
    if (tdIdx1 < ctx.rc[0x02]) {
        const next = rdTypeDef(ctx, ti, tdIdx1 + 1);
        return next ? next.methodList : ctx.rc[0x06] + 1;
    }
    return ctx.rc[0x06] + 1;
}

// Read MethodDef row (1-based index)
function rdMethodDef(ctx, ti, idx1) {
    const { b, ss, bs, rc } = ctx;
    const { rs, tblOffs } = ti;
    if (tblOffs[0x06] < 0 || idx1 < 1 || idx1 > rc[0x06]) return null;
    let p = tblOffs[0x06] + (idx1 - 1) * rs[0x06];
    const rva       = u32(b, p); p += 4;
    const implFlags = u16(b, p); p += 2;
    const flags     = u16(b, p); p += 2;
    const nameIdx   = rdIdx(b, p, ss); p += ss;
    const sigIdx    = rdIdx(b, p, bs);
    return { rva, implFlags, flags, name: rdStr(ctx, nameIdx), sigIdx };
}

// Read TypeRef row (1-based index)
function rdTypeRef(ctx, ti, idx1) {
    const { b, ss, rc } = ctx;
    const { rs, tblOffs, rsc } = ti;
    if (tblOffs[0x01] < 0 || idx1 < 1 || idx1 > rc[0x01]) return null;
    let p = tblOffs[0x01] + (idx1 - 1) * rs[0x01] + rsc; // skip ResolutionScope
    const nameIdx = rdIdx(b, p, ss); p += ss;
    const nsIdx   = rdIdx(b, p, ss);
    return { name: rdStr(ctx, nameIdx), ns: rdStr(ctx, nsIdx) };
}

// Read MemberRef row (1-based index)
function rdMemberRef(ctx, ti, idx1) {
    const { b, ss, bs, rc } = ctx;
    const { rs, tblOffs, mrp } = ti;
    if (tblOffs[0x0A] < 0 || idx1 < 1 || idx1 > rc[0x0A]) return null;
    let p = tblOffs[0x0A] + (idx1 - 1) * rs[0x0A];
    const parentRaw = rdIdx(b, p, mrp); p += mrp;
    const nameIdx   = rdIdx(b, p, ss);  p += ss;
    const sigIdx    = rdIdx(b, p, bs);
    // MemberRefParent tag: 0=TypeDef, 1=TypeRef, 2=ModuleRef, 3=MethodDef, 4=TypeSpec
    return { parentTag: parentRaw & 0x7, parentIdx: parentRaw >> 3, name: rdStr(ctx, nameIdx), sigIdx };
}

// Read NestedClass row (1-based index)
function rdNestedClass(ctx, ti, idx1) {
    const { b, rc } = ctx;
    const { rs, tblOffs } = ti;
    if (tblOffs[0x29] < 0 || idx1 < 1 || idx1 > rc[0x29]) return null;
    const ncsi = rc[0x02] > 65535 ? 4 : 2;
    const p = tblOffs[0x29] + (idx1 - 1) * rs[0x29];
    return { nested: rdIdx(b, p, ncsi), enclosing: rdIdx(b, p + ncsi, ncsi) };
}

// Signature parsing

// Parse a method signature blob (ECMA-335 II.23.2.1)
// Returns { retType, retToken, paramCount, paramTokens } or null
function rdMethodSig(blob) {
    if (!blob || blob.length < 2) return null;
    let pos = 0;
    const cc = blob[pos++];
    if (cc & 0x10) { const gp = rdCompInt(blob, pos); pos = gp.next; } // GENERIC: skip GenParamCount
    const { val: paramCount, next: p1 } = rdCompInt(blob, pos); pos = p1;
    if (pos >= blob.length) return null;
    const retType = blob[pos++];
    let retToken = null;
    if ((retType === ET_VALUETYPE || retType === ET_CLASS) && pos < blob.length) {
        const r = rdCompInt(blob, pos); pos = r.next;
        // TypeDefOrRefEncoded: bits 1:0 = tag, bits N:2 = 1-based row index
        retToken = { tag: r.val & 0x3, idx: r.val >> 2 };
    }
    const paramTokens = [];
    for (let i = 0; i < paramCount && pos < blob.length; i++) {
        const pt = blob[pos++];
        if ((pt === ET_VALUETYPE || pt === ET_CLASS) && pos < blob.length) {
            const r = rdCompInt(blob, pos); pos = r.next;
            paramTokens.push({ elemType: pt, tag: r.val & 0x3, idx: r.val >> 2 });
        } else {
            paramTokens.push({ elemType: pt });
        }
    }
    return { retType, retToken, paramCount, paramTokens };
}

// Analysis helpers

// Check whether a TypeDefOrRef coded reference points to (ns, name)
function typeRefMatch(ctx, ti, tag, idx1, ns, name) {
    if (tag === 1) { // TypeRef
        const tr = rdTypeRef(ctx, ti, idx1);
        return tr && tr.ns === ns && tr.name === name;
    }
    if (tag === 0) { // TypeDef
        const td = rdTypeDef(ctx, ti, idx1);
        return td && td.ns === ns && td.name === name;
    }
    return false;
}

// Check whether a TypeDef (1-based index) is an enum type
// Enums are sealed value types whose base class is System.Enum
function isEnumTypeDef(ctx, ti, tdIdx1) {
    const td = rdTypeDef(ctx, ti, tdIdx1);
    if (!td) return false;
    if (!(td.flags & 0x100)) return false; // TypeAttributes.Sealed
    return typeRefMatch(ctx, ti, td.extendsTag, td.extendsIdx, "System", "Enum");
}

// Build a Map<nestedTypeIdx1, enclosingTypeIdx1> from the NestedClass table
function buildNestingMap(ctx, ti) {
    const map = new Map();
    for (let i = 1; i <= ctx.rc[0x29]; i++) {
        const nc = rdNestedClass(ctx, ti, i);
        if (nc) map.set(nc.nested, nc.enclosing);
    }
    return map;
}

// Find the full 4-byte metadata token for the System.Action default constructor
// Returns the token integer or -1 if not found
function findActionCtorToken(ctx, ti) {
    // Step 1: find TypeRef row for System.Action
    let actionTRIdx = -1;
    for (let i = 1; i <= ctx.rc[0x01]; i++) {
        const tr = rdTypeRef(ctx, ti, i);
        if (tr && tr.ns === "System" && tr.name === "Action") { actionTRIdx = i; break; }
    }
    if (actionTRIdx < 0) return -1;
    // Step 2: find MemberRef whose parent is that TypeRef and whose name is ".ctor"
    for (let i = 1; i <= ctx.rc[0x0A]; i++) {
        const mr = rdMemberRef(ctx, ti, i);
        if (!mr) continue;
        if (mr.parentTag !== 1 || mr.parentIdx !== actionTRIdx) continue; // parent must be TypeRef
        if (mr.name !== ".ctor") continue;
        return (0x0A << 24) | i; // MemberRef metadata token
    }
    return -1;
}

// Method body helpers

// Return the start-of-code offset and code size for a method body RVA
// Handles both tiny (1-byte header) and fat (12-byte header) formats
function methodBodyInfo(ctx, rva) {
    if (!rva) return null;
    const off = rva2off(ctx.sects, rva);
    if (off < 0) return null;
    const b = ctx.b;
    const firstByte = b[off];
    if ((firstByte & 0x3) === 0x2) { // Tiny format
        return { codeOff: off + 1, codeSize: firstByte >> 2 };
    }
    if ((firstByte & 0x3) === 0x3) { // Fat format
        const hdrWords = (b[off + 1] >> 4) & 0xF;
        return { codeOff: off + hdrWords * 4, codeSize: u32(b, off + 4) };
    }
    return null;
}

// Overwrite the first bytes of a method body with the given patch bytes
// This makes the method return immediately (prepend ret / ldc.i4.2 + ret)
function patchBody(ctx, rva, patchBytes) {
    const info = methodBodyInfo(ctx, rva);
    if (!info || info.codeSize < patchBytes.length) return false;
    for (let i = 0; i < patchBytes.length; i++)
        ctx.b[info.codeOff + i] = patchBytes[i];
    return true;
}

// Scan the IL bytes of a method body for the ldftn + newobj System.Action pattern
// (ECMA-335: ldftn = FE 06 <4-byte token>, newobj = 73 <4-byte token>)
// Returns an array of ldftn target tokens found adjacent to the given ctor token
function scanForActionPattern(ctx, rva, actionCtorToken) {
    const info = methodBodyInfo(ctx, rva);
    if (!info) return [];
    const b = ctx.b;
    const { codeOff, codeSize } = info;
    const end = codeOff + codeSize - 10;
    const found = [];
    for (let i = codeOff; i < end; i++) {
        if (b[i] !== 0xFE || b[i + 1] !== 0x06) continue; // ldftn prefix+opcode
        const ldftnToken  = u32(b, i + 2);
        if (b[i + 6] !== 0x73) continue;                  // newobj opcode
        const newobjToken = u32(b, i + 7);
        if (newobjToken === actionCtorToken) found.push(ldftnToken);
    }
    return found;
}

// Structural searches

// Find abort-scheduler methods by structural analysis:
// Any method that returns System.Action and whose body contains
// `ldftn <target> + newobj System.Action` where <target> is a static,
// parameterless, void method declared in the same type.
function findAbortsByStructure(ctx, ti, actionCtorToken) {
    if (actionCtorToken < 0) return [];
    const results = [];
    const seen = new Set();
    for (let tdIdx = 1; tdIdx <= ctx.rc[0x02]; tdIdx++) {
        const td = rdTypeDef(ctx, ti, tdIdx);
        if (!td) continue;
        const mEnd = methodEnd(ctx, ti, tdIdx);
        for (let mdIdx = td.methodList; mdIdx < mEnd; mdIdx++) {
            const md = rdMethodDef(ctx, ti, mdIdx);
            if (!md || !md.rva) continue;
            // The scanning method must return System.Action (CLASS reference)
            const sig = rdMethodSig(rdBlob(ctx, md.sigIdx));
            if (!sig || sig.retType !== ET_CLASS || !sig.retToken) continue;
            if (!typeRefMatch(ctx, ti, sig.retToken.tag, sig.retToken.idx, "System", "Action")) continue;
            // Scan its IL for the ldftn+newobj pattern
            for (const tok of scanForActionPattern(ctx, md.rva, actionCtorToken)) {
                if ((tok >>> 24) !== 0x06) continue; // only MethodDef tokens (table 0x06)
                const targetIdx = tok & 0x00FFFFFF;
                if (seen.has(targetIdx)) continue;
                const tgt = rdMethodDef(ctx, ti, targetIdx);
                if (!tgt || !tgt.rva) continue;
                if (!(tgt.flags & 0x10)) continue; // must be static
                // Target must live in the same type
                const tgtEnd = methodEnd(ctx, ti, tdIdx);
                if (targetIdx < td.methodList || targetIdx >= tgtEnd) continue;
                // Target must be void with no parameters
                const tgtSig = rdMethodSig(rdBlob(ctx, tgt.sigIdx));
                if (!tgtSig || tgtSig.retType !== ET_VOID || tgtSig.paramCount !== 0) continue;
                seen.add(targetIdx);
                results.push({ mdIdx: targetIdx, rva: tgt.rva, typeIdx: tdIdx });
            }
        }
    }
    return results;
}

// Find fatal-logger methods by structural analysis:
// In types known to contain the abort scheduler, find static void methods
// with exactly one parameter whose type is an enum nested in that same type.
function findLoggersByStructure(ctx, ti, nestingMap, abortTypeIdxs) {
    if (abortTypeIdxs.size === 0) return [];
    const results = [];
    const seen = new Set();
    for (let tdIdx = 1; tdIdx <= ctx.rc[0x02]; tdIdx++) {
        if (!abortTypeIdxs.has(tdIdx)) continue;
        const td = rdTypeDef(ctx, ti, tdIdx);
        if (!td) continue;
        const mEnd = methodEnd(ctx, ti, tdIdx);
        for (let mdIdx = td.methodList; mdIdx < mEnd; mdIdx++) {
            if (seen.has(mdIdx)) continue;
            const md = rdMethodDef(ctx, ti, mdIdx);
            if (!md || !md.rva) continue;
            if (!(md.flags & 0x10)) continue;                 // must be static
            if (md.name === ".ctor" || md.name === ".cctor") continue;
            const sig = rdMethodSig(rdBlob(ctx, md.sigIdx));
            if (!sig || sig.retType !== ET_VOID) continue;    // must return void
            if (sig.paramCount !== 1 || sig.paramTokens.length < 1) continue;
            const param = sig.paramTokens[0];
            if (param.elemType !== ET_VALUETYPE) continue;    // must be a value type (enum)
            // Param type must be a TypeDef that is an enum nested in this same type
            if (param.tag !== 0) continue;                    // TypeDef reference only
            if (!isEnumTypeDef(ctx, ti, param.idx)) continue;
            if (nestingMap.get(param.idx) !== tdIdx) continue; // must be nested in this type
            seen.add(mdIdx);
            results.push({ mdIdx, rva: md.rva });
        }
    }
    return results;
}

// Main IL patcher

function patchIL(buf) {
    const report = {
        keyManagerDetected: false,
        checkAllowedPatched: 0,
        abortSchedulerPatched: 0,
        fatalLoggerSilenced: 0,
        total: 0,
        warnings: []
    };

    const pe = parsePE(buf);
    if (!pe) return null; // Not a PE file

    const ctx = parseMeta(buf, pe.sects, pe.cliRVA);
    if (!ctx) return null; // Not a managed .NET assembly

    const ti = buildTblInfo(ctx);

    // 1. Detect KeyManager namespace and patch CheckAllowed
    // prepend `ldc.i4.2; ret`
    const seenCheck = new Set();
    for (let tdIdx = 1; tdIdx <= ctx.rc[0x02]; tdIdx++) {
        const td = rdTypeDef(ctx, ti, tdIdx);
        if (!td) continue;
        if (td.ns === KM_NS && td.name === KM_TYPE) report.keyManagerDetected = true;
        if (td.ns !== KM_NS || td.name !== KM_TYPE) continue;
        const mEnd = methodEnd(ctx, ti, tdIdx);
        for (let mdIdx = td.methodList; mdIdx < mEnd; mdIdx++) {
            const md = rdMethodDef(ctx, ti, mdIdx);
            if (!md || !md.rva || md.name !== KM_CHECK) continue;
            const sig = rdMethodSig(rdBlob(ctx, md.sigIdx));
            if (!sig || sig.retType !== ET_I4) continue; // must return int32
            if (seenCheck.has(mdIdx)) continue;
            seenCheck.add(mdIdx);
            if (patchBody(ctx, md.rva, [IL_LDC_I4_2, IL_RET]))
                report.checkAllowedPatched++;
        }
    }

    // 2. Patch abort scheduler
    // prepend `ret`
    const abortTypeIdxs = new Set();
    const seenAbort = new Set();

    // 2a. Structural approach: find the method wrapped in a System.Action getter
    const actionCtorToken = findActionCtorToken(ctx, ti);
    for (const { mdIdx, rva, typeIdx } of findAbortsByStructure(ctx, ti, actionCtorToken)) {
        if (seenAbort.has(mdIdx)) continue;
        seenAbort.add(mdIdx);
        if (patchBody(ctx, rva, [IL_RET])) {
            report.abortSchedulerPatched++;
            abortTypeIdxs.add(typeIdx);
        }
    }

    // 2b. Literal name approach
    for (let tdIdx = 1; tdIdx <= ctx.rc[0x02]; tdIdx++) {
        const td = rdTypeDef(ctx, ti, tdIdx);
        if (!td || td.name !== KM_LIC_TYPE) continue;
        const mEnd = methodEnd(ctx, ti, tdIdx);
        for (let mdIdx = td.methodList; mdIdx < mEnd; mdIdx++) {
            const md = rdMethodDef(ctx, ti, mdIdx);
            if (!md || !md.rva || md.name !== KM_ABORT) continue;
            if (seenAbort.has(mdIdx)) continue;
            seenAbort.add(mdIdx);
            if (patchBody(ctx, md.rva, [IL_RET])) {
                report.abortSchedulerPatched++;
                abortTypeIdxs.add(tdIdx);
            }
        }
    }

    // 3. Patch fatal logger
    // prepend `ret`
    const seenLogger = new Set();

    // 3a. Structural approach: static void(enum) methods in abort-scheduler types
    const nestingMap = buildNestingMap(ctx, ti);
    for (const { mdIdx, rva } of findLoggersByStructure(ctx, ti, nestingMap, abortTypeIdxs)) {
        if (seenLogger.has(mdIdx)) continue;
        seenLogger.add(mdIdx);
        if (patchBody(ctx, rva, [IL_RET]))
            report.fatalLoggerSilenced++;
    }

    // 3b. Literal name approach
    for (let tdIdx = 1; tdIdx <= ctx.rc[0x02]; tdIdx++) {
        const td = rdTypeDef(ctx, ti, tdIdx);
        if (!td || td.name !== KM_LIC_TYPE) continue;
        const mEnd = methodEnd(ctx, ti, tdIdx);
        for (let mdIdx = td.methodList; mdIdx < mEnd; mdIdx++) {
            const md = rdMethodDef(ctx, ti, mdIdx);
            if (!md || !md.rva || md.name !== KM_LOGGER) continue;
            if (seenLogger.has(mdIdx)) continue;
            seenLogger.add(mdIdx);
            if (patchBody(ctx, md.rva, [IL_RET]))
                report.fatalLoggerSilenced++;
        }
    }

    report.total = report.checkAllowedPatched + report.abortSchedulerPatched + report.fatalLoggerSilenced;
    buildWarnings(report);
    return report;
}

// Build warning messages
function buildWarnings(report) {
    if (!report.keyManagerDetected) {
        if (report.total === 0)
            report.warnings.push(
                "No KeyManager namespace found in file. Nothing to patch." +
                " (This mod may not use KeyManager DRM, or it may be obfuscated/optimized in a way that hides it from this tool.)");
        return;
    }
    if (report.checkAllowedPatched === 0)
        report.warnings.push(
            "KeyManager namespace was found in file, but CheckAllowed was not patched." +
            " The protection has likely been updated or obfuscated." +
            " The patched mod .dll may still abort at runtime.");
    if (report.abortSchedulerPatched === 0)
        report.warnings.push(
            "Abort scheduler was not found." +
            " Periodic license checks in the mod may still trigger Application.Quit.");
    if (report.fatalLoggerSilenced === 0)
        report.warnings.push(
            "Fatal error logger was not silenced. This is a cosmetic issue only. " +
            "You may still see [Fatal: KeyManager ...] output in the BepInEx console.");
}
