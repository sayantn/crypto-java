/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.hash;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import org.asterisk.crypto.Tested;
import org.asterisk.crypto.helper.AbstractDigestEngine;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.interfaces.Digest;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum Sha2 implements Digest {

    @Tested
    SHA_256 {

        private static final ValueLayout.OfInt LAYOUT = Tools.BIG_ENDIAN_32_BIT;

        @Override
        public Engine start() {
            return new AbstractDigestEngine(64) {

                private final int[] state = {
                    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
                }, expand = new int[64];

                private long msglen = 0;

                @Override
                protected void ingestOneBlock(MemorySegment input, long offset) {
                    extract(input, offset, 16);

                    expand();

                    compress();

                    msglen += 64;

                }

                private void extract(MemorySegment input, long offset, int n) {
                    for (int i = 0; i < n; i++) {
                        expand[i] = input.get(LAYOUT, offset + 4 * i);
                    }
                }

                private void expand() {
                    for (int i = 16; i < 64; i++) {
                        expand[i] = gamma1(expand[i - 2]) + expand[i - 7] + gamma0(expand[i - 15]) + expand[i - 16];
                    }
                }

                private void compress() {
                    int a = state[0], b = state[1], c = state[2], d = state[3], e = state[4], f = state[5], g = state[6], h = state[7];
                    int t0, t1;

                    for (int r = 0; r < 64;) {
                        t0 = h + sigma1(e) + ch(e, f, g) + RCON_32[r] + expand[r];
                        t1 = sigma0(a) + maj(a, b, c);
                        d += t0;
                        h = t0 + t1;

                        r++;

                        t0 = g + sigma1(d) + ch(d, e, f) + RCON_32[r] + expand[r];
                        t1 = sigma0(h) + maj(h, a, b);
                        c += t0;
                        g = t0 + t1;

                        r++;

                        t0 = f + sigma1(c) + ch(c, d, e) + RCON_32[r] + expand[r];
                        t1 = sigma0(g) + maj(g, h, a);
                        b += t0;
                        f = t0 + t1;

                        r++;

                        t0 = e + sigma1(b) + ch(b, c, d) + RCON_32[r] + expand[r];
                        t1 = sigma0(f) + maj(f, g, h);
                        a += t0;
                        e = t0 + t1;

                        r++;

                        t0 = d + sigma1(a) + ch(a, b, c) + RCON_32[r] + expand[r];
                        t1 = sigma0(e) + maj(e, f, g);
                        h += t0;
                        d = t0 + t1;

                        r++;

                        t0 = c + sigma1(h) + ch(h, a, b) + RCON_32[r] + expand[r];
                        t1 = sigma0(d) + maj(d, e, f);
                        g += t0;
                        c = t0 + t1;

                        r++;

                        t0 = b + sigma1(g) + ch(g, h, a) + RCON_32[r] + expand[r];
                        t1 = sigma0(c) + maj(c, d, e);
                        f += t0;
                        b = t0 + t1;

                        r++;

                        t0 = a + sigma1(f) + ch(f, g, h) + RCON_32[r] + expand[r];
                        t1 = sigma0(b) + maj(b, c, d);
                        e += t0;
                        a = t0 + t1;

                        r++;
                    }
                    state[0] += a;
                    state[1] += b;
                    state[2] += c;
                    state[3] += d;
                    state[4] += e;
                    state[5] += f;
                    state[6] += g;
                    state[7] += h;
                }

                @Override
                protected void ingestLastBlock(MemorySegment input, int length) {
                    if (length == 64) {
                        ingestOneBlock(input, 0);
                        length = 0;
                    }

                    msglen += length;
                    int l2 = (int) (msglen >>> 29);
                    int l1 = (int) (msglen << 3);

                    if (length >= 56) {
                        Tools.ozpad(input, length);

                        extract(input, 0, 16);
                        expand();
                        compress();

                        input.asSlice(0, 56).fill((byte) 0);
                    } else {
                        Tools.ozpad(input.asSlice(0, 56), length);
                    }

                    extract(input, 0, 14);

                    expand[14] = l2;
                    expand[15] = l1;

                    expand();
                    compress();

                }

                @Override
                protected void digestOneBlock(byte[] dest, int offset) {
                    Tools.store32BE(state[0], dest, offset + 0);
                    Tools.store32BE(state[1], dest, offset + 4);
                    Tools.store32BE(state[2], dest, offset + 8);
                    Tools.store32BE(state[3], dest, offset + 12);
                    Tools.store32BE(state[4], dest, offset + 16);
                    Tools.store32BE(state[5], dest, offset + 20);
                    Tools.store32BE(state[6], dest, offset + 24);
                    Tools.store32BE(state[7], dest, offset + 28);
                }

                @Override
                public Digest getAlgorithm() {
                    return Sha2.SHA_256;
                }

            };
        }

        @Override
        public int digestSize() {
            return 32;
        }

        @Override
        public int blockSize() {
            return 64;
        }

    }, @Tested
    SHA_224 {

        private static final ValueLayout.OfInt LAYOUT = Tools.BIG_ENDIAN_32_BIT;

        @Override
        public Engine start() {
            return new AbstractDigestEngine(64) {

                private final int[] state = {
                    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
                    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
                }, expand = new int[64];

                private long msglen = 0;

                @Override
                protected void ingestOneBlock(MemorySegment input, long offset) {
                    extract(input, offset, 16);

                    expand();

                    compress();

                    msglen += 64;

                }

                private void extract(MemorySegment input, long offset, int n) {
                    for (int i = 0; i < n; i++) {
                        expand[i] = input.get(LAYOUT, offset + 4 * i);
                    }
                }

                private void expand() {
                    for (int i = 16; i < 64; i++) {
                        expand[i] = gamma1(expand[i - 2]) + expand[i - 7] + gamma0(expand[i - 15]) + expand[i - 16];
                    }
                }

                private void compress() {
                    int a = state[0], b = state[1], c = state[2], d = state[3], e = state[4], f = state[5], g = state[6], h = state[7];
                    int t0, t1;

                    for (int r = 0; r < 64;) {
                        t0 = h + sigma1(e) + ch(e, f, g) + RCON_32[r] + expand[r];
                        t1 = sigma0(a) + maj(a, b, c);
                        d += t0;
                        h = t0 + t1;

                        r++;

                        t0 = g + sigma1(d) + ch(d, e, f) + RCON_32[r] + expand[r];
                        t1 = sigma0(h) + maj(h, a, b);
                        c += t0;
                        g = t0 + t1;

                        r++;

                        t0 = f + sigma1(c) + ch(c, d, e) + RCON_32[r] + expand[r];
                        t1 = sigma0(g) + maj(g, h, a);
                        b += t0;
                        f = t0 + t1;

                        r++;

                        t0 = e + sigma1(b) + ch(b, c, d) + RCON_32[r] + expand[r];
                        t1 = sigma0(f) + maj(f, g, h);
                        a += t0;
                        e = t0 + t1;

                        r++;

                        t0 = d + sigma1(a) + ch(a, b, c) + RCON_32[r] + expand[r];
                        t1 = sigma0(e) + maj(e, f, g);
                        h += t0;
                        d = t0 + t1;

                        r++;

                        t0 = c + sigma1(h) + ch(h, a, b) + RCON_32[r] + expand[r];
                        t1 = sigma0(d) + maj(d, e, f);
                        g += t0;
                        c = t0 + t1;

                        r++;

                        t0 = b + sigma1(g) + ch(g, h, a) + RCON_32[r] + expand[r];
                        t1 = sigma0(c) + maj(c, d, e);
                        f += t0;
                        b = t0 + t1;

                        r++;

                        t0 = a + sigma1(f) + ch(f, g, h) + RCON_32[r] + expand[r];
                        t1 = sigma0(b) + maj(b, c, d);
                        e += t0;
                        a = t0 + t1;

                        r++;
                    }
                    state[0] += a;
                    state[1] += b;
                    state[2] += c;
                    state[3] += d;
                    state[4] += e;
                    state[5] += f;
                    state[6] += g;
                    state[7] += h;
                }

                @Override
                protected void ingestLastBlock(MemorySegment input, int length) {
                    if (length == 64) {
                        ingestOneBlock(input, 0);
                        length = 0;
                    }

                    msglen += length;
                    int l2 = (int) (msglen >>> 29);
                    int l1 = (int) (msglen << 3);

                    if (length >= 56) {
                        Tools.ozpad(input, length);

                        extract(input, 0, 16);
                        expand();
                        compress();

                        input.asSlice(0, 56).fill((byte) 0);
                    } else {
                        Tools.ozpad(input.asSlice(0, 56), length);
                    }

                    extract(input, 0, 14);

                    expand[14] = l2;
                    expand[15] = l1;

                    expand();
                    compress();

                }

                @Override
                protected void digestOneBlock(byte[] dest, int offset) {
                    Tools.store32BE(state[0], dest, offset + 0);
                    Tools.store32BE(state[1], dest, offset + 4);
                    Tools.store32BE(state[2], dest, offset + 8);
                    Tools.store32BE(state[3], dest, offset + 12);
                    Tools.store32BE(state[4], dest, offset + 16);
                    Tools.store32BE(state[5], dest, offset + 20);
                    Tools.store32BE(state[6], dest, offset + 24);
                }

                @Override
                public Digest getAlgorithm() {
                    return Sha2.SHA_224;
                }

            };
        }

        @Override
        public int digestSize() {
            return 28;
        }

        @Override
        public int blockSize() {
            return 64;
        }

    },
    @Tested
    SHA_512 {

        private static final ValueLayout.OfLong LAYOUT = Tools.BIG_ENDIAN_64_BIT;

        @Override
        public Engine start() {
            return new AbstractDigestEngine(128) {

                private final long[] state = {
                    0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
                    0x510e527fade682d1L, 0x9b05688c2b3e6c1fL, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
                }, expand = new long[80];

                private long msglen = 0;

                @Override
                protected void ingestOneBlock(MemorySegment input, long offset) {
                    extract(input, offset, 16);

                    expand();

                    compress();

                    msglen += 128;

                }

                private void extract(MemorySegment input, long offset, int n) {
                    for (int i = 0; i < n; i++) {
                        expand[i] = input.get(LAYOUT, offset + 8 * i);
                    }
                }

                private void expand() {
                    for (int i = 16; i < 80; i++) {
                        expand[i] = gamma1(expand[i - 2]) + expand[i - 7] + gamma0(expand[i - 15]) + expand[i - 16];
                    }
                }

                private void compress() {
                    long a = state[0], b = state[1], c = state[2], d = state[3], e = state[4], f = state[5], g = state[6], h = state[7];
                    long t0, t1;

                    for (int r = 0; r < 80;) {
                        t0 = h + sigma1(e) + ch(e, f, g) + RCON_64[r] + expand[r];
                        t1 = sigma0(a) + maj(a, b, c);
                        d += t0;
                        h = t0 + t1;

                        r++;

                        t0 = g + sigma1(d) + ch(d, e, f) + RCON_64[r] + expand[r];
                        t1 = sigma0(h) + maj(h, a, b);
                        c += t0;
                        g = t0 + t1;

                        r++;

                        t0 = f + sigma1(c) + ch(c, d, e) + RCON_64[r] + expand[r];
                        t1 = sigma0(g) + maj(g, h, a);
                        b += t0;
                        f = t0 + t1;

                        r++;

                        t0 = e + sigma1(b) + ch(b, c, d) + RCON_64[r] + expand[r];
                        t1 = sigma0(f) + maj(f, g, h);
                        a += t0;
                        e = t0 + t1;

                        r++;

                        t0 = d + sigma1(a) + ch(a, b, c) + RCON_64[r] + expand[r];
                        t1 = sigma0(e) + maj(e, f, g);
                        h += t0;
                        d = t0 + t1;

                        r++;

                        t0 = c + sigma1(h) + ch(h, a, b) + RCON_64[r] + expand[r];
                        t1 = sigma0(d) + maj(d, e, f);
                        g += t0;
                        c = t0 + t1;

                        r++;

                        t0 = b + sigma1(g) + ch(g, h, a) + RCON_64[r] + expand[r];
                        t1 = sigma0(c) + maj(c, d, e);
                        f += t0;
                        b = t0 + t1;

                        r++;

                        t0 = a + sigma1(f) + ch(f, g, h) + RCON_64[r] + expand[r];
                        t1 = sigma0(b) + maj(b, c, d);
                        e += t0;
                        a = t0 + t1;

                        r++;
                    }
                    state[0] += a;
                    state[1] += b;
                    state[2] += c;
                    state[3] += d;
                    state[4] += e;
                    state[5] += f;
                    state[6] += g;
                    state[7] += h;
                }

                @Override
                protected void ingestLastBlock(MemorySegment input, int length) {
                    if (length == 128) {
                        ingestOneBlock(input, 0);
                        length = 0;
                    }

                    msglen += length;
                    long l2 = msglen >>> 61;
                    long l1 = msglen << 3;

                    if (length >= 112) {
                        Tools.ozpad(input, length);

                        extract(input, 0, 16);
                        expand();
                        compress();

                        input.asSlice(0, 112).fill((byte) 0);
                    } else {
                        Tools.ozpad(input.asSlice(0, 112), length);
                    }

                    extract(input, 0, 14);

                    expand[14] = l2;
                    expand[15] = l1;

                    expand();
                    compress();

                }

                @Override
                protected void digestOneBlock(byte[] dest, int offset) {
                    Tools.store64BE(state[0], dest, offset + 0);
                    Tools.store64BE(state[1], dest, offset + 8);
                    Tools.store64BE(state[2], dest, offset + 16);
                    Tools.store64BE(state[3], dest, offset + 24);
                    Tools.store64BE(state[4], dest, offset + 32);
                    Tools.store64BE(state[5], dest, offset + 40);
                    Tools.store64BE(state[6], dest, offset + 48);
                    Tools.store64BE(state[7], dest, offset + 56);
                }

                @Override
                public Digest getAlgorithm() {
                    return Sha2.SHA_512;
                }

            };
        }

        @Override
        public int digestSize() {
            return 64;
        }

        @Override
        public int blockSize() {
            return 128;
        }
    }, @Tested
    SHA_384 {

        private static final ValueLayout.OfLong LAYOUT = Tools.BIG_ENDIAN_64_BIT;

        @Override
        public Engine start() {
            return new AbstractDigestEngine(128) {

                private final long[] state = {
                    0xcbbb9d5dc1059ed8L, 0x629a292a367cd507L, 0x9159015a3070dd17L, 0x152fecd8f70e5939L,
                    0x67332667ffc00b31L, 0x8eb44a8768581511L, 0xdb0c2e0d64f98fa7L, 0x47b5481dbefa4fa4L
                }, expand = new long[80];

                private long msglen = 0;

                @Override
                protected void ingestOneBlock(MemorySegment input, long offset) {
                    extract(input, offset, 16);

                    expand();

                    compress();

                    msglen += 128;

                }

                private void extract(MemorySegment input, long offset, int n) {
                    for (int i = 0; i < n; i++) {
                        expand[i] = input.get(LAYOUT, offset + 8 * i);
                    }
                }

                private void expand() {
                    for (int i = 16; i < 80; i++) {
                        expand[i] = gamma1(expand[i - 2]) + expand[i - 7] + gamma0(expand[i - 15]) + expand[i - 16];
                    }
                }

                private void compress() {
                    long a = state[0], b = state[1], c = state[2], d = state[3], e = state[4], f = state[5], g = state[6], h = state[7];
                    long t0, t1;

                    for (int r = 0; r < 80;) {
                        t0 = h + sigma1(e) + ch(e, f, g) + RCON_64[r] + expand[r];
                        t1 = sigma0(a) + maj(a, b, c);
                        d += t0;
                        h = t0 + t1;

                        r++;

                        t0 = g + sigma1(d) + ch(d, e, f) + RCON_64[r] + expand[r];
                        t1 = sigma0(h) + maj(h, a, b);
                        c += t0;
                        g = t0 + t1;

                        r++;

                        t0 = f + sigma1(c) + ch(c, d, e) + RCON_64[r] + expand[r];
                        t1 = sigma0(g) + maj(g, h, a);
                        b += t0;
                        f = t0 + t1;

                        r++;

                        t0 = e + sigma1(b) + ch(b, c, d) + RCON_64[r] + expand[r];
                        t1 = sigma0(f) + maj(f, g, h);
                        a += t0;
                        e = t0 + t1;

                        r++;

                        t0 = d + sigma1(a) + ch(a, b, c) + RCON_64[r] + expand[r];
                        t1 = sigma0(e) + maj(e, f, g);
                        h += t0;
                        d = t0 + t1;

                        r++;

                        t0 = c + sigma1(h) + ch(h, a, b) + RCON_64[r] + expand[r];
                        t1 = sigma0(d) + maj(d, e, f);
                        g += t0;
                        c = t0 + t1;

                        r++;

                        t0 = b + sigma1(g) + ch(g, h, a) + RCON_64[r] + expand[r];
                        t1 = sigma0(c) + maj(c, d, e);
                        f += t0;
                        b = t0 + t1;

                        r++;

                        t0 = a + sigma1(f) + ch(f, g, h) + RCON_64[r] + expand[r];
                        t1 = sigma0(b) + maj(b, c, d);
                        e += t0;
                        a = t0 + t1;

                        r++;
                    }
                    state[0] += a;
                    state[1] += b;
                    state[2] += c;
                    state[3] += d;
                    state[4] += e;
                    state[5] += f;
                    state[6] += g;
                    state[7] += h;
                }

                @Override
                protected void ingestLastBlock(MemorySegment input, int length) {
                    if (length == 128) {
                        ingestOneBlock(input, 0);
                        length = 0;
                    }

                    msglen += length;
                    long l2 = msglen >>> 61;
                    long l1 = msglen << 3;

                    if (length >= 112) {
                        Tools.ozpad(input, length);

                        extract(input, 0, 16);
                        expand();
                        compress();

                        input.asSlice(0, 112).fill((byte) 0);
                    } else {
                        Tools.ozpad(input.asSlice(0, 112), length);
                    }

                    extract(input, 0, 14);

                    expand[14] = l2;
                    expand[15] = l1;

                    expand();
                    compress();

                }

                @Override
                protected void digestOneBlock(byte[] dest, int offset) {
                    Tools.store64BE(state[0], dest, offset + 0);
                    Tools.store64BE(state[1], dest, offset + 8);
                    Tools.store64BE(state[2], dest, offset + 16);
                    Tools.store64BE(state[3], dest, offset + 24);
                    Tools.store64BE(state[4], dest, offset + 32);
                    Tools.store64BE(state[5], dest, offset + 40);
                }

                @Override
                public Digest getAlgorithm() {
                    return Sha2.SHA_384;
                }

            };
        }

        @Override
        public int digestSize() {
            return 48;
        }

        @Override
        public int blockSize() {
            return 128;
        }
    };

    private static final int[] RCON_32 = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    public static final long[] RCON_64 = {
        0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL,
        0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L,
        0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
        0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 0xc19bf174cf692694L,
        0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
        0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
        0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L,
        0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL, 0x142929670a0e6e70L,
        0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
        0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL,
        0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L,
        0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
        0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L,
        0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L,
        0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
        0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL,
        0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L,
        0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
        0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL,
        0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L
    };

    private static long ch(long x, long y, long z) {
        return z ^ (x & (y ^ z));
    }

    private static long maj(long x, long y, long z) {
        return ((x | y) & z) | (x & y);
    }

    private static long sigma0(long x) {
        return Long.rotateRight(x, 28) ^ Long.rotateRight(x, 34) ^ Long.rotateRight(x, 39);
    }

    private static long sigma1(long x) {
        return Long.rotateRight(x, 14) ^ Long.rotateRight(x, 18) ^ Long.rotateRight(x, 41);
    }

    private static long gamma0(long x) {
        return Long.rotateRight(x, 1) ^ Long.rotateRight(x, 8) ^ (x >>> 7);
    }

    private static long gamma1(long x) {
        return Long.rotateRight(x, 19) ^ Long.rotateRight(x, 61) ^ (x >>> 6);
    }

    private static int ch(int x, int y, int z) {
        return z ^ (x & (y ^ z));
    }

    private static int maj(int x, int y, int z) {
        return ((x | y) & z) | (x & y);
    }

    private static int sigma0(int x) {
        return Integer.rotateRight(x, 2) ^ Integer.rotateRight(x, 13) ^ Integer.rotateRight(x, 22);
    }

    private static int sigma1(int x) {
        return Integer.rotateRight(x, 6) ^ Integer.rotateRight(x, 11) ^ Integer.rotateRight(x, 25);
    }

    private static int gamma0(int x) {
        return Integer.rotateRight(x, 7) ^ Integer.rotateRight(x, 18) ^ (x >>> 3);
    }

    private static int gamma1(int x) {
        return Integer.rotateRight(x, 17) ^ Integer.rotateRight(x, 19) ^ (x >>> 10);
    }

}
