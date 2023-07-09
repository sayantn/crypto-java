/*
 * Copyright (C) 2023 Sayantan Chakraborty
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
package org.asterisk.crypto.hash;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.SegmentScope;
import java.lang.foreign.ValueLayout;
import org.asterisk.crypto.helper.AbstractDigestEngine;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.Digest;
import org.asterisk.crypto.Mac;

/**
 *
 * @author Sayantan Chakraborty
 */
public class Skein implements Digest, Mac {

    private static final ValueLayout.OfLong LAYOUT = Tools.LITTLE_ENDIAN_64_BIT;

    private static final long T_CFG = 4L << 56, T_MSG = 48L << 56, T_OUT = 63L << 56;
    private static final long LAST = 1L << 63, FIRST = 1L << 62, NOT_FIRST = ~FIRST;

    private static final long CFG = 0x0133414853L;

    private static final long C_240 = 0x1bd11bdaa9fc1a22L;

    private static void threefish256(long[] key, long[] tweak, long[] src, long[] dst) {
        long x0 = src[0] + key[0], x1 = src[1] + key[1] + tweak[0], x2 = src[2] + key[2] + tweak[1], x3 = src[3] + key[3];

        key[4] = C_240 ^ key[0] ^ key[1] ^ key[2] ^ key[3];
        tweak[2] = tweak[0] ^ tweak[1];

        for (int r = 1; r < 18; r += 2) {
            x0 += x1;
            x1 = Long.rotateLeft(x1, 14) ^ x0;
            x2 += x3;
            x3 = Long.rotateLeft(x3, 16) ^ x2;

            x0 += x3;
            x3 = Long.rotateLeft(x3, 52) ^ x0;
            x2 += x1;
            x1 = Long.rotateLeft(x1, 57) ^ x2;

            x0 += x1;
            x1 = Long.rotateLeft(x1, 23) ^ x0;
            x2 += x3;
            x3 = Long.rotateLeft(x3, 40) ^ x2;

            x0 += x3;
            x3 = Long.rotateLeft(x3, 5) ^ x0;
            x2 += x1;
            x1 = Long.rotateLeft(x1, 37) ^ x2;

            x0 += key[r + 0];
            x1 += key[r + 1] + tweak[r + 0];
            x2 += key[r + 2] + tweak[r + 1];
            x3 += key[r + 3] + r;

            key[r + 4] = key[r - 1];
            tweak[r + 2] = tweak[r - 1];

            x0 += x1;
            x1 = Long.rotateLeft(x1, 25) ^ x0;
            x2 += x3;
            x3 = Long.rotateLeft(x3, 33) ^ x2;

            x0 += x3;
            x3 = Long.rotateLeft(x3, 46) ^ x0;
            x2 += x1;
            x1 = Long.rotateLeft(x1, 12) ^ x2;

            x0 += x1;
            x1 = Long.rotateLeft(x1, 58) ^ x0;
            x2 += x3;
            x3 = Long.rotateLeft(x3, 22) ^ x2;

            x0 += x3;
            x3 = Long.rotateLeft(x3, 32) ^ x0;
            x2 += x1;
            x1 = Long.rotateLeft(x1, 32) ^ x2;

            x0 += key[r + 1];
            x1 += key[r + 2] + tweak[r + 1];
            x2 += key[r + 3] + tweak[r + 2];
            x3 += key[r + 4] + r + 1;

            key[r + 5] = key[r];
            tweak[r + 3] = tweak[r];
        }

        dst[0] = x0;
        dst[1] = x1;
        dst[2] = x2;
        dst[3] = x3;
    }

    private static void threefish512(long[] key, long[] tweak, long[] src, long[] dst) {
        long x0 = src[0] + key[0], x1 = src[1] + key[1], x2 = src[2] + key[2], x3 = src[3] + key[3];
        long x4 = src[4] + key[4], x5 = src[5] + key[5] + tweak[0], x6 = src[6] + key[6] + tweak[1], x7 = src[7] + key[7];

        key[8] = C_240 ^ key[0] ^ key[1] ^ key[2] ^ key[3] ^ key[4] ^ key[5] ^ key[6] ^ key[7];
        tweak[2] = tweak[0] ^ tweak[1];

        for (int r = 1; r < 18; r += 2) {
            x0 += x1;
            x1 = Long.rotateLeft(x1, 46) ^ x0;
            x2 += x3;
            x3 = Long.rotateLeft(x3, 36) ^ x2;
            x4 += x5;
            x5 = Long.rotateLeft(x5, 19) ^ x4;
            x6 += x7;
            x7 = Long.rotateLeft(x7, 37) ^ x6;

            x2 += x1;
            x1 = Long.rotateLeft(x1, 33) ^ x2;
            x4 += x7;
            x7 = Long.rotateLeft(x7, 27) ^ x4;
            x6 += x5;
            x5 = Long.rotateLeft(x5, 14) ^ x6;
            x0 += x3;
            x3 = Long.rotateLeft(x3, 42) ^ x0;

            x4 += x1;
            x1 = Long.rotateLeft(x1, 17) ^ x4;
            x6 += x3;
            x3 = Long.rotateLeft(x3, 49) ^ x6;
            x0 += x5;
            x5 = Long.rotateLeft(x5, 36) ^ x0;
            x2 += x7;
            x7 = Long.rotateLeft(x7, 39) ^ x2;

            x6 += x1;
            x1 = Long.rotateLeft(x1, 44) ^ x6;
            x0 += x7;
            x7 = Long.rotateLeft(x7, 9) ^ x0;
            x2 += x5;
            x5 = Long.rotateLeft(x5, 54) ^ x2;
            x4 += x3;
            x3 = Long.rotateLeft(x3, 56) ^ x4;

            x0 += key[r + 0];
            x1 += key[r + 1];
            x2 += key[r + 2];
            x3 += key[r + 3];
            x4 += key[r + 4];
            x5 += key[r + 5] + tweak[r + 0];
            x6 += key[r + 6] + tweak[r + 1];
            x7 += key[r + 7] + r;

            key[r + 8] = key[r - 1];
            tweak[r + 2] = tweak[r - 1];

            x0 += x1;
            x1 = Long.rotateLeft(x1, 39) ^ x0;
            x2 += x3;
            x3 = Long.rotateLeft(x3, 30) ^ x2;
            x4 += x5;
            x5 = Long.rotateLeft(x5, 34) ^ x4;
            x6 += x7;
            x7 = Long.rotateLeft(x7, 24) ^ x6;

            x2 += x1;
            x1 = Long.rotateLeft(x1, 13) ^ x2;
            x4 += x7;
            x7 = Long.rotateLeft(x7, 50) ^ x4;
            x6 += x5;
            x5 = Long.rotateLeft(x5, 10) ^ x6;
            x0 += x3;
            x3 = Long.rotateLeft(x3, 17) ^ x0;

            x4 += x1;
            x1 = Long.rotateLeft(x1, 25) ^ x4;
            x6 += x3;
            x3 = Long.rotateLeft(x3, 29) ^ x6;
            x0 += x5;
            x5 = Long.rotateLeft(x5, 39) ^ x0;
            x2 += x7;
            x7 = Long.rotateLeft(x7, 43) ^ x2;

            x6 += x1;
            x1 = Long.rotateLeft(x1, 8) ^ x6;
            x0 += x7;
            x7 = Long.rotateLeft(x7, 35) ^ x0;
            x2 += x5;
            x5 = Long.rotateLeft(x5, 56) ^ x2;
            x4 += x3;
            x3 = Long.rotateLeft(x7, 22) ^ x4;

            x0 += key[r + 1];
            x1 += key[r + 2];
            x2 += key[r + 3];
            x3 += key[r + 4];
            x4 += key[r + 5];
            x5 += key[r + 6] + tweak[r + 1];
            x6 += key[r + 7] + tweak[r + 2];
            x7 += key[r + 8] + r + 1;

            key[r + 9] = key[r];
            tweak[r + 3] = tweak[r];
        }

        dst[0] = x0;
        dst[1] = x1;
        dst[2] = x2;
        dst[3] = x3;
        dst[4] = x4;
        dst[5] = x5;
        dst[6] = x6;
        dst[7] = x7;

    }

    private static void threefish1024(long[] key, long[] tweak, long[] src, long[] dst) {
        long x0 = src[0] + key[0], x1 = src[1] + key[1], x2 = src[2] + key[2], x3 = src[3] + key[3];
        long x4 = src[4] + key[4], x5 = src[5] + key[5], x6 = src[6] + key[6], x7 = src[7] + key[7];
        long x8 = src[0] + key[8], x9 = src[1] + key[9], x10 = src[2] + key[10], x11 = src[3] + key[11];
        long x12 = src[4] + key[12], x13 = src[5] + key[13] + tweak[0], x14 = src[6] + key[14] + tweak[1], x15 = src[7] + key[15];

        key[8] = C_240
                ^ key[0] ^ key[1] ^ key[2] ^ key[3]
                ^ key[4] ^ key[5] ^ key[6] ^ key[7]
                ^ key[8] ^ key[9] ^ key[10] ^ key[11]
                ^ key[12] ^ key[13] ^ key[14] ^ key[15];
        tweak[2] = tweak[0] ^ tweak[1];

        for (int r = 1; r < 20; r += 2) {
            x0 += x1;
            x1 = Long.rotateLeft(x1, 24) ^ x0;
            x2 += x3;
            x3 = Long.rotateLeft(x3, 13) ^ x2;
            x4 += x5;
            x5 = Long.rotateLeft(x5, 8) ^ x4;
            x6 += x7;
            x7 = Long.rotateLeft(x7, 47) ^ x6;
            x8 += x9;
            x9 = Long.rotateLeft(x9, 8) ^ x8;
            x10 += x11;
            x11 = Long.rotateLeft(x11, 17) ^ x10;
            x12 += x13;
            x13 = Long.rotateLeft(x13, 22) ^ x12;
            x14 += x15;
            x15 = Long.rotateLeft(x15, 37) ^ x14;

            x0 += x9;
            x9 = Long.rotateLeft(x9, 38) ^ x0;
            x2 += x13;
            x13 = Long.rotateLeft(x13, 19) ^ x2;
            x6 += x11;
            x11 = Long.rotateLeft(x11, 10) ^ x6;
            x4 += x15;
            x15 = Long.rotateLeft(x15, 55) ^ x4;
            x10 += x7;
            x7 = Long.rotateLeft(x7, 49) ^ x10;
            x12 += x3;
            x3 = Long.rotateLeft(x3, 18) ^ x12;
            x14 += x5;
            x5 = Long.rotateLeft(x5, 23) ^ x14;
            x8 += x1;
            x1 = Long.rotateLeft(x1, 52) ^ x8;

            x0 += x7;
            x7 = Long.rotateLeft(x7, 33) ^ x0;
            x2 += x5;
            x5 = Long.rotateLeft(x5, 4) ^ x2;
            x4 += x3;
            x3 = Long.rotateLeft(x3, 51) ^ x4;
            x6 += x1;
            x1 = Long.rotateLeft(x1, 13) ^ x6;
            x12 += x15;
            x15 = Long.rotateLeft(x15, 34) ^ x12;
            x14 += x13;
            x13 = Long.rotateLeft(x13, 41) ^ x14;
            x8 += x11;
            x11 = Long.rotateLeft(x11, 59) ^ x8;
            x10 += x9;
            x9 = Long.rotateLeft(x9, 17) ^ x10;

            x0 += x15;
            x15 = Long.rotateLeft(x15, 5) ^ x0;
            x2 += x11;
            x11 = Long.rotateLeft(x11, 20) ^ x2;
            x6 += x13;
            x13 = Long.rotateLeft(x13, 48) ^ x6;
            x4 += x9;
            x9 = Long.rotateLeft(x9, 41) ^ x4;
            x14 += x1;
            x1 = Long.rotateLeft(x1, 47) ^ x14;
            x8 += x5;
            x5 = Long.rotateLeft(x5, 28) ^ x8;
            x10 += x3;
            x3 = Long.rotateLeft(x3, 16) ^ x10;
            x12 += x7;
            x7 = Long.rotateLeft(x7, 25) ^ x12;

            x0 += key[r + 0];
            x1 += key[r + 1];
            x2 += key[r + 2];
            x3 += key[r + 3];
            x4 += key[r + 4];
            x5 += key[r + 5];
            x6 += key[r + 6];
            x7 += key[r + 7];
            x8 += key[r + 8];
            x9 += key[r + 9];
            x10 += key[r + 10];
            x11 += key[r + 11];
            x12 += key[r + 12];
            x13 += key[r + 13] + tweak[r + 0];
            x14 += key[r + 14] + tweak[r + 1];
            x15 += key[r + 15] + r;

            key[r + 16] = key[r - 1];
            tweak[r + 2] = tweak[r - 1];

            x0 += x1;
            x1 = Long.rotateLeft(x1, 41) ^ x0;
            x2 += x3;
            x3 = Long.rotateLeft(x3, 9) ^ x2;
            x4 += x5;
            x5 = Long.rotateLeft(x5, 37) ^ x4;
            x6 += x7;
            x7 = Long.rotateLeft(x7, 31) ^ x6;
            x8 += x9;
            x9 = Long.rotateLeft(x9, 12) ^ x8;
            x10 += x11;
            x11 = Long.rotateLeft(x11, 47) ^ x10;
            x12 += x13;
            x13 = Long.rotateLeft(x13, 44) ^ x12;
            x14 += x15;
            x15 = Long.rotateLeft(x15, 30) ^ x14;

            x0 += x9;
            x9 = Long.rotateLeft(x9, 16) ^ x0;
            x2 += x13;
            x13 = Long.rotateLeft(x13, 34) ^ x2;
            x6 += x11;
            x11 = Long.rotateLeft(x11, 56) ^ x6;
            x4 += x15;
            x15 = Long.rotateLeft(x15, 51) ^ x4;
            x10 += x7;
            x7 = Long.rotateLeft(x7, 4) ^ x10;
            x12 += x3;
            x3 = Long.rotateLeft(x3, 53) ^ x12;
            x14 += x5;
            x5 = Long.rotateLeft(x5, 42) ^ x14;
            x8 += x1;
            x1 = Long.rotateLeft(x1, 41) ^ x8;

            x0 += x7;
            x7 = Long.rotateLeft(x7, 31) ^ x0;
            x2 += x5;
            x5 = Long.rotateLeft(x5, 44) ^ x2;
            x4 += x3;
            x3 = Long.rotateLeft(x3, 47) ^ x4;
            x6 += x1;
            x1 = Long.rotateLeft(x1, 46) ^ x6;
            x12 += x15;
            x15 = Long.rotateLeft(x15, 19) ^ x12;
            x14 += x13;
            x13 = Long.rotateLeft(x13, 42) ^ x14;
            x8 += x11;
            x11 = Long.rotateLeft(x11, 44) ^ x8;
            x10 += x9;
            x9 = Long.rotateLeft(x9, 25) ^ x10;

            x0 += x15;
            x15 = Long.rotateLeft(x15, 9) ^ x0;
            x2 += x11;
            x11 = Long.rotateLeft(x11, 48) ^ x2;
            x6 += x13;
            x13 = Long.rotateLeft(x13, 35) ^ x6;
            x4 += x9;
            x9 = Long.rotateLeft(x9, 52) ^ x4;
            x14 += x1;
            x1 = Long.rotateLeft(x1, 23) ^ x14;
            x8 += x5;
            x5 = Long.rotateLeft(x5, 31) ^ x8;
            x10 += x3;
            x3 = Long.rotateLeft(x3, 37) ^ x10;
            x12 += x7;
            x7 = Long.rotateLeft(x7, 30) ^ x12;

            x0 += key[r + 1];
            x1 += key[r + 2];
            x2 += key[r + 3];
            x3 += key[r + 4];
            x4 += key[r + 5];
            x5 += key[r + 6];
            x6 += key[r + 7];
            x7 += key[r + 8];
            x8 += key[r + 9];
            x9 += key[r + 10];
            x10 += key[r + 11];
            x11 += key[r + 12];
            x12 += key[r + 13];
            x13 += key[r + 14] + tweak[r + 1];
            x14 += key[r + 15] + tweak[r + 2];
            x15 += key[r + 16] + r + 1;

            key[r + 17] = key[r];
            tweak[r + 3] = tweak[r];
        }

        dst[0] = x0;
        dst[1] = x1;
        dst[2] = x2;
        dst[3] = x3;
        dst[4] = x4;
        dst[5] = x5;
        dst[6] = x6;
        dst[7] = x7;
        dst[8] = x8;
        dst[9] = x9;
        dst[10] = x10;
        dst[11] = x11;
        dst[12] = x12;
        dst[13] = x13;
        dst[14] = x14;
        dst[15] = x15;
    }

    public static Skein skein256(int outputSize) {
        if ((outputSize & 7) != 0) {
            throw new IllegalArgumentException("This implementaion only supports byte-length outputs");
        }
        return new Skein(outputSize >>> 3, Type.SKEIN_256);
    }

    public static Skein skein512(int outputSize) {
        if ((outputSize & 7) != 0) {
            throw new IllegalArgumentException("This implementaion only supports byte-length outputs");
        }
        return new Skein(outputSize >>> 3, Type.SKEIN_512);
    }

    public static Skein skein1024(int outputSize) {
        if ((outputSize & 7) != 0) {
            throw new IllegalArgumentException("This implementaion only supports byte-length outputs");
        }
        return new Skein(outputSize >>> 3, Type.SKEIN_1024);
    }

    private final int outputLength;
    private volatile long[] precomputedState;
    private final Type type;

    private Skein(int outputLength, Type type) {
        this.outputLength = outputLength;
        this.type = type;
    }

    private long[] precomputed256() {
        assert type == Type.SKEIN_256;
        var state = precomputedState;
        if (state == null) {
            synchronized (this) {
                state = precomputedState;
                if (state == null) {
                    state = new long[23];
                    cfgUbi256(state, new long[4], new long[21]);
                    precomputedState = state;
                }
            }
        }
        return state;
    }

    private long[] precomputed512() {
        assert type == Type.SKEIN_512;
        var state = precomputedState;
        if (state == null) {
            synchronized (this) {
                state = precomputedState;
                if (state == null) {
                    state = new long[27];
                    cfgUbi512(state, new long[8], new long[21]);
                    precomputedState = state;
                }
            }
        }
        return state;
    }

    private long[] precomputed1024() {
        assert type == Type.SKEIN_1024;
        var state = precomputedState;
        if (state == null) {
            synchronized (this) {
                state = precomputedState;
                if (state == null) {
                    state = new long[37];
                    cfgUbi1024(state, new long[16], new long[23]);
                    precomputedState = state;
                }
            }
        }
        return state;
    }

    private void cfgUbi256(long[] state, long[] data, long[] tweak) {
        data[0] = CFG;
        data[1] = outputLength;
        tweak[0] = 32;
        tweak[1] = T_CFG | FIRST | LAST;
        threefish256(state, tweak, data, state);
        state[0] ^= data[0];
        state[1] ^= data[1];
    }

    private void cfgUbi512(long[] state, long[] data, long[] tweak) {
        data[0] = CFG;
        data[1] = outputLength;
        tweak[0] = 64;
        tweak[1] = T_CFG | FIRST | LAST;
        threefish512(state, tweak, data, state);
        state[0] ^= data[0];
        state[1] ^= data[1];
    }

    private void cfgUbi1024(long[] state, long[] data, long[] tweak) {
        data[0] = CFG;
        data[1] = outputLength;
        tweak[0] = 128;
        tweak[1] = T_CFG | FIRST | LAST;
        threefish1024(state, tweak, data, state);
        state[0] ^= data[0];
        state[1] ^= data[1];
    }

    @Override
    public Digest.Engine start() {
        var internal = switch (type) {
            case SKEIN_256 ->
                new Skein256Engine(precomputed256(), new long[21]);
            case SKEIN_512 ->
                new Skein512Engine(precomputed512(), new long[21]);
            case SKEIN_1024 ->
                new Skein1024Engine(precomputed1024(), new long[23]);
        };
        return new AbstractDigestEngine(type.blockSize()) {

            @Override
            protected void ingestOneBlock(MemorySegment input, long offset) {
                internal.ingestOneBlock(input, offset);
            }

            @Override
            protected void ingestLastBlock(MemorySegment input, int length) {
                internal.ingestLastBlock(input, length);
            }

            @Override
            protected void getDigest(byte[] dest, int offset) {
                internal.output(dest, offset, outputLength);
            }

            @Override
            public Digest getAlgorithm() {
                return Skein.this;
            }
        };
    }

    @Override
    public Mac.Engine start(byte[] key) {

        SkeinEngine internal = switch (type) {
            case SKEIN_256 -> {
                long[] state = new long[23], data = new long[8], tweak = new long[21];

                tweak[0] = 32;
                tweak[1] = FIRST | LAST;

                data[0] = Tools.load32LE(key, 0);
                data[1] = Tools.load32LE(key, 8);
                data[2] = Tools.load32LE(key, 16);
                data[3] = Tools.load32LE(key, 24);

                threefish256(state, tweak, data, state);

                state[0] ^= data[0];
                state[1] ^= data[1];
                state[2] ^= data[2];
                state[3] ^= data[3];

                cfgUbi256(state, data, tweak);

                yield new Skein256Engine(state, tweak);
            }
            case SKEIN_512 -> {
                long[] state = new long[27], data = new long[8], tweak = new long[21];

                tweak[0] = 64;
                tweak[1] = FIRST | LAST;

                data[0] = Tools.load32LE(key, 0);
                data[1] = Tools.load32LE(key, 8);
                data[2] = Tools.load32LE(key, 16);
                data[3] = Tools.load32LE(key, 24);
                data[4] = Tools.load32LE(key, 32);
                data[5] = Tools.load32LE(key, 40);
                data[6] = Tools.load32LE(key, 48);
                data[7] = Tools.load32LE(key, 56);

                threefish512(state, tweak, data, state);

                state[0] ^= data[0];
                state[1] ^= data[1];
                state[2] ^= data[2];
                state[3] ^= data[3];
                state[4] ^= data[4];
                state[5] ^= data[5];
                state[6] ^= data[6];
                state[7] ^= data[7];

                cfgUbi512(state, data, tweak);

                yield new Skein512Engine(state, tweak);
            }
            case SKEIN_1024 -> {
                long[] state = new long[37], data = new long[16], tweak = new long[23];

                tweak[0] = 64;
                tweak[1] = FIRST | LAST;

                data[0] = Tools.load32LE(key, 0);
                data[1] = Tools.load32LE(key, 8);
                data[2] = Tools.load32LE(key, 16);
                data[3] = Tools.load32LE(key, 24);
                data[4] = Tools.load32LE(key, 32);
                data[5] = Tools.load32LE(key, 40);
                data[6] = Tools.load32LE(key, 48);
                data[7] = Tools.load32LE(key, 56);
                data[8] = Tools.load32LE(key, 64);
                data[9] = Tools.load32LE(key, 72);
                data[10] = Tools.load32LE(key, 80);
                data[11] = Tools.load32LE(key, 88);
                data[12] = Tools.load32LE(key, 96);
                data[13] = Tools.load32LE(key, 104);
                data[14] = Tools.load32LE(key, 112);
                data[15] = Tools.load32LE(key, 120);

                threefish1024(state, tweak, data, state);

                state[0] ^= data[0];
                state[1] ^= data[1];
                state[2] ^= data[2];
                state[3] ^= data[3];
                state[4] ^= data[4];
                state[5] ^= data[5];
                state[6] ^= data[6];
                state[7] ^= data[7];
                state[8] ^= data[8];
                state[9] ^= data[9];
                state[10] ^= data[10];
                state[11] ^= data[11];
                state[12] ^= data[12];
                state[13] ^= data[13];
                state[14] ^= data[14];
                state[15] ^= data[15];

                cfgUbi1024(state, data, tweak);

                yield new Skein1024Engine(state, tweak);
            }
        };

        return new Mac.Engine() {

            private final int blockSize = type.blockSize();
            private final MemorySegment buffer = MemorySegment.allocateNative(blockSize, SegmentScope.auto());
            private int position = 0;

            @Override
            public final void ingest(MemorySegment input) {
                long offset = 0, length = input.byteSize();
                if (position > 0) {
                    int take = (int) Math.min(length, blockSize - position);
                    MemorySegment.copy(input, offset, buffer, position, take);
                    offset += take;
                    length -= take;
                    position += take;
                    if (position == blockSize && length > 0) {
                        internal.ingestOneBlock(buffer, 0);
                        position = 0;
                    }
                }
                while (length > blockSize) {
                    internal.ingestOneBlock(input, offset);
                    offset += blockSize;
                    length -= blockSize;
                }
                if (length > 0) {
                    MemorySegment.copy(input, offset, buffer, 0, length);
                    position = (int) length;
                }
            }

            @Override
            public void authenticateTo(byte[] tag, int offset, int length) {
                if (length != outputLength) {
                    throw new IllegalArgumentException(length + " bytes requested from " + getAlgorithm());
                }
                internal.ingestLastBlock(buffer, position);
                internal.output(tag, offset, length);
            }

            @Override
            public Mac getAlgorithm() {
                return Skein.this;
            }
        };
    }

    @Override
    public int digestSize() {
        return outputLength;
    }

    @Override
    public int blockSize() {
        return type.blockSize();
    }

    @Override
    public int tagLength() {
        return outputLength;
    }

    @Override
    public int keyLength() {
        return type.blockSize();
    }

    @Override
    public String toString() {
        return "Skein-" + (type.blockSize() * 8) + "-" + (outputLength * 8);
    }

    private static interface SkeinEngine {

        void ingestOneBlock(MemorySegment input, long offset);

        void ingestLastBlock(MemorySegment input, int length);

        void output(byte[] output, int offset, int length);
    }

    private static class Skein256Engine implements SkeinEngine {

        private final long[] state, data = new long[4], tweak;

        private Skein256Engine(long[] state, long[] tweak) {
            this.state = state;
            this.tweak = tweak;
            tweak[0] = 0;
            tweak[1] = T_MSG | FIRST;
        }

        @Override
        public void ingestOneBlock(MemorySegment input, long offset) {
            tweak[0] += 32;

            data[0] = input.get(LAYOUT, offset + 0);
            data[1] = input.get(LAYOUT, offset + 8);
            data[2] = input.get(LAYOUT, offset + 16);
            data[3] = input.get(LAYOUT, offset + 24);

            threefish256(state, tweak, data, state);

            state[0] ^= data[0];
            state[1] ^= data[1];
            state[2] ^= data[2];
            state[3] ^= data[3];

            tweak[1] &= NOT_FIRST;
        }

        @Override
        public void ingestLastBlock(MemorySegment input, int length) {
            Tools.zeropad(input, length);
            tweak[0] += length;
            tweak[1] |= LAST;

            data[0] = input.get(LAYOUT, 0);
            data[1] = input.get(LAYOUT, 8);
            data[2] = input.get(LAYOUT, 16);
            data[3] = input.get(LAYOUT, 24);

            threefish256(state, tweak, data, state);

            state[0] ^= data[0];
            state[1] ^= data[1];
            state[2] ^= data[2];
            state[3] ^= data[3];

            tweak[0] = 8;
            tweak[1] = T_OUT | FIRST | LAST;
        }

        private void digestBlock(byte[] dest, int offset, int index) {
            data[0] = index;
            data[1] = 0;
            data[2] = 0;
            data[3] = 0;

            threefish256(state, tweak, data, data);

            Tools.store64LE(data[0], dest, offset + 0);
            Tools.store64LE(data[1], dest, offset + 8);
            Tools.store64LE(data[2], dest, offset + 16);
            Tools.store64LE(data[3], dest, offset + 24);
        }

        @Override
        public void output(byte[] dest, int offset, int length) {
            int index = 0;
            while (length >= 32) {
                digestBlock(dest, offset, index++);
                offset += 32;
                length -= 32;
            }
            if (length > 0) {
                byte[] temp = new byte[32];
                digestBlock(temp, 0, index);
                System.arraycopy(temp, 0, dest, offset, length);
            }
        }

    }

    private static class Skein512Engine implements SkeinEngine {

        private final long[] state, data = new long[8], tweak;

        private Skein512Engine(long[] state, long[] tweak) {
            this.state = state;
            this.tweak = tweak;
            tweak[0] = 0;
            tweak[1] = T_MSG | FIRST;
        }

        @Override
        public void ingestOneBlock(MemorySegment input, long offset) {
            tweak[0] += 64;

            data[0] = input.get(LAYOUT, offset + 0);
            data[1] = input.get(LAYOUT, offset + 8);
            data[2] = input.get(LAYOUT, offset + 16);
            data[3] = input.get(LAYOUT, offset + 24);
            data[4] = input.get(LAYOUT, offset + 32);
            data[5] = input.get(LAYOUT, offset + 40);
            data[6] = input.get(LAYOUT, offset + 48);
            data[7] = input.get(LAYOUT, offset + 56);

            threefish512(state, tweak, data, state);

            state[0] ^= data[0];
            state[1] ^= data[1];
            state[2] ^= data[2];
            state[3] ^= data[3];
            state[4] ^= data[4];
            state[5] ^= data[5];
            state[6] ^= data[6];
            state[7] ^= data[7];

            tweak[1] &= NOT_FIRST;
        }

        @Override
        public void ingestLastBlock(MemorySegment input, int length) {
            Tools.zeropad(input, length);
            tweak[0] += length;
            tweak[1] |= LAST;

            data[0] = input.get(LAYOUT, 0);
            data[1] = input.get(LAYOUT, 8);
            data[2] = input.get(LAYOUT, 16);
            data[3] = input.get(LAYOUT, 24);
            data[4] = input.get(LAYOUT, 32);
            data[5] = input.get(LAYOUT, 40);
            data[6] = input.get(LAYOUT, 48);
            data[7] = input.get(LAYOUT, 56);

            threefish512(state, tweak, data, state);

            state[0] ^= data[0];
            state[1] ^= data[1];
            state[2] ^= data[2];
            state[3] ^= data[3];
            state[4] ^= data[4];
            state[5] ^= data[5];
            state[6] ^= data[6];
            state[7] ^= data[7];

            tweak[0] = 8;
            tweak[1] = T_OUT | FIRST | LAST;
        }

        private void digestBlock(byte[] dest, int offset, int index) {
            data[0] = index;
            data[1] = 0;
            data[2] = 0;
            data[3] = 0;
            data[4] = 0;
            data[5] = 0;
            data[6] = 0;
            data[7] = 0;

            threefish512(state, tweak, data, data);

            Tools.store64LE(data[0], dest, offset + 0);
            Tools.store64LE(data[1], dest, offset + 8);
            Tools.store64LE(data[2], dest, offset + 16);
            Tools.store64LE(data[3], dest, offset + 24);
            Tools.store64LE(data[4], dest, offset + 32);
            Tools.store64LE(data[5], dest, offset + 40);
            Tools.store64LE(data[6], dest, offset + 48);
            Tools.store64LE(data[7], dest, offset + 56);
        }

        @Override
        public void output(byte[] dest, int offset, int length) {
            int index = 0;
            while (length >= 64) {
                digestBlock(dest, offset, index++);
                offset += 64;
                length -= 64;
            }
            if (length > 0) {
                byte[] temp = new byte[64];
                digestBlock(temp, 0, index);
                System.arraycopy(temp, 0, dest, offset, length);
            }
        }

    }

    private static class Skein1024Engine implements SkeinEngine {

        private final long[] state, data = new long[16], tweak;

        private Skein1024Engine(long[] state, long[] tweak) {
            this.state = state;
            this.tweak = tweak;
            tweak[0] = 0;
            tweak[1] = T_MSG | FIRST;
        }

        @Override
        public void ingestOneBlock(MemorySegment input, long offset) {
            tweak[0] += 128;

            data[0] = input.get(LAYOUT, offset + 0);
            data[1] = input.get(LAYOUT, offset + 8);
            data[2] = input.get(LAYOUT, offset + 16);
            data[3] = input.get(LAYOUT, offset + 24);
            data[4] = input.get(LAYOUT, offset + 32);
            data[5] = input.get(LAYOUT, offset + 40);
            data[6] = input.get(LAYOUT, offset + 48);
            data[7] = input.get(LAYOUT, offset + 56);
            data[8] = input.get(LAYOUT, offset + 64);
            data[9] = input.get(LAYOUT, offset + 72);
            data[10] = input.get(LAYOUT, offset + 80);
            data[11] = input.get(LAYOUT, offset + 88);
            data[12] = input.get(LAYOUT, offset + 96);
            data[13] = input.get(LAYOUT, offset + 104);
            data[14] = input.get(LAYOUT, offset + 112);
            data[15] = input.get(LAYOUT, offset + 120);

            threefish1024(state, tweak, data, state);

            state[0] ^= data[0];
            state[1] ^= data[1];
            state[2] ^= data[2];
            state[3] ^= data[3];
            state[4] ^= data[4];
            state[5] ^= data[5];
            state[6] ^= data[6];
            state[7] ^= data[7];
            state[8] ^= data[8];
            state[9] ^= data[9];
            state[10] ^= data[10];
            state[11] ^= data[11];
            state[12] ^= data[12];
            state[13] ^= data[13];
            state[14] ^= data[14];
            state[15] ^= data[15];

            tweak[1] &= NOT_FIRST;
        }

        @Override
        public void ingestLastBlock(MemorySegment input, int length) {
            Tools.zeropad(input, length);
            tweak[0] += length;
            tweak[1] |= LAST;

            data[0] = input.get(LAYOUT, 0);
            data[1] = input.get(LAYOUT, 8);
            data[2] = input.get(LAYOUT, 16);
            data[3] = input.get(LAYOUT, 24);
            data[4] = input.get(LAYOUT, 32);
            data[5] = input.get(LAYOUT, 40);
            data[6] = input.get(LAYOUT, 48);
            data[7] = input.get(LAYOUT, 56);
            data[8] = input.get(LAYOUT, 64);
            data[9] = input.get(LAYOUT, 72);
            data[10] = input.get(LAYOUT, 80);
            data[11] = input.get(LAYOUT, 88);
            data[12] = input.get(LAYOUT, 96);
            data[13] = input.get(LAYOUT, 104);
            data[14] = input.get(LAYOUT, 112);
            data[15] = input.get(LAYOUT, 120);

            threefish1024(state, tweak, data, state);

            state[0] ^= data[0];
            state[1] ^= data[1];
            state[2] ^= data[2];
            state[3] ^= data[3];
            state[4] ^= data[4];
            state[5] ^= data[5];
            state[6] ^= data[6];
            state[7] ^= data[7];
            state[8] ^= data[8];
            state[9] ^= data[9];
            state[10] ^= data[10];
            state[11] ^= data[11];
            state[12] ^= data[12];
            state[13] ^= data[13];
            state[14] ^= data[14];
            state[15] ^= data[15];

            tweak[0] = 8;
            tweak[1] = T_OUT | FIRST | LAST;
        }

        private void digestBlock(byte[] dest, int offset, int index) {
            data[0] = index;
            data[1] = 0;
            data[2] = 0;
            data[3] = 0;
            data[4] = 0;
            data[5] = 0;
            data[6] = 0;
            data[7] = 0;
            data[8] = 0;
            data[9] = 0;
            data[10] = 0;
            data[11] = 0;
            data[12] = 0;
            data[13] = 0;
            data[14] = 0;
            data[15] = 0;

            threefish1024(state, tweak, data, data);

            Tools.store64LE(data[0], dest, offset + 0);
            Tools.store64LE(data[1], dest, offset + 8);
            Tools.store64LE(data[2], dest, offset + 16);
            Tools.store64LE(data[3], dest, offset + 24);
            Tools.store64LE(data[4], dest, offset + 32);
            Tools.store64LE(data[5], dest, offset + 40);
            Tools.store64LE(data[6], dest, offset + 48);
            Tools.store64LE(data[7], dest, offset + 56);
            Tools.store64LE(data[8], dest, offset + 64);
            Tools.store64LE(data[9], dest, offset + 72);
            Tools.store64LE(data[10], dest, offset + 80);
            Tools.store64LE(data[11], dest, offset + 88);
            Tools.store64LE(data[12], dest, offset + 96);
            Tools.store64LE(data[13], dest, offset + 104);
            Tools.store64LE(data[14], dest, offset + 112);
            Tools.store64LE(data[15], dest, offset + 120);
        }

        @Override
        public void output(byte[] dest, int offset, int length) {
            int index = 0;
            while (length >= 128) {
                digestBlock(dest, offset, index++);
                offset += 128;
                length -= 128;
            }
            if (length > 0) {
                byte[] temp = new byte[128];
                digestBlock(temp, 0, index);
                System.arraycopy(temp, 0, dest, offset, length);
            }
        }

    }

    private enum Type {
        SKEIN_256, SKEIN_512, SKEIN_1024;

        int blockSize() {
            return 32 << ordinal();
        }
    }

}
