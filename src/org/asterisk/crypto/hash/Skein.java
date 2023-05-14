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
import java.lang.foreign.ValueLayout;
import org.asterisk.crypto.helper.AbstractDigestEngine;
import org.asterisk.crypto.helper.AbstractMacEngine;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.interfaces.Digest;
import org.asterisk.crypto.interfaces.Mac;

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

    private static void threefish256(long[] key, long t0, long t1, long[] src, long[] dst) {
        final long k0 = key[0], k1 = key[1], k2 = key[2], k3 = key[3], k4 = C_240 ^ k0 ^ k1 ^ k2 ^ k3;
        final long t2 = t0 ^ t1;
        long x0 = src[0], x1 = src[1], x2 = src[2], x3 = src[3];

        x1 += k1 + t0;
        x3 += k3 + 0;

        x0 += x1 + k0;
        x1 = Long.rotateLeft(x1, 14) ^ x0;
        x2 += x3 + k2 + t1;
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

        x1 += k2 + t1;
        x3 += k4 + 1;

        x0 += x1 + k1;
        x1 = Long.rotateLeft(x1, 25) ^ x0;
        x2 += x3 + k3 + t2;
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

        x1 += k3 + t2;
        x3 += k0 + 2;

        x0 += x1 + k2;
        x1 = Long.rotateLeft(x1, 14) ^ x0;
        x2 += x3 + k4 + t0;
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

        x1 += k4 + t0;
        x3 += k1 + 3;

        x0 += x1 + k3;
        x1 = Long.rotateLeft(x1, 25) ^ x0;
        x2 += x3 + k0 + t1;
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

        x1 += k0 + t1;
        x3 += k2 + 4;

        x0 += x1 + k4;
        x1 = Long.rotateLeft(x1, 14) ^ x0;
        x2 += x3 + k1 + t2;
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

        x1 += k1 + t2;
        x3 += k3 + 5;

        x0 += x1 + k0;
        x1 = Long.rotateLeft(x1, 25) ^ x0;
        x2 += x3 + k2 + t0;
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

        x1 += k2 + t0;
        x3 += k4 + 6;

        x0 += x1 + k1;
        x1 = Long.rotateLeft(x1, 14) ^ x0;
        x2 += x3 + k3 + t1;
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

        x1 += k3 + t1;
        x3 += k0 + 7;

        x0 += x1 + k2;
        x1 = Long.rotateLeft(x1, 25) ^ x0;
        x2 += x3 + k4 + t2;
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

        x1 += k4 + t2;
        x3 += k1 + 8;

        x0 += x1 + k3;
        x1 = Long.rotateLeft(x1, 14) ^ x0;
        x2 += x3 + k0 + t0;
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

        x1 += k0 + t0;
        x3 += k2 + 9;

        x0 += x1 + k4;
        x1 = Long.rotateLeft(x1, 25) ^ x0;
        x2 += x3 + k1 + t1;
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

        x1 += k1 + t1;
        x3 += k3 + 10;

        x0 += x1 + k0;
        x1 = Long.rotateLeft(x1, 14) ^ x0;
        x2 += x3 + k2 + t2;
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

        x1 += k2 + t2;
        x3 += k4 + 11;

        x0 += x1 + k1;
        x1 = Long.rotateLeft(x1, 25) ^ x0;
        x2 += x3 + k3 + t0;
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

        x1 += k3 + t0;
        x3 += k0 + 12;

        x0 += x1 + k2;
        x1 = Long.rotateLeft(x1, 14) ^ x0;
        x2 += x3 + k4 + t1;
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

        x1 += k4 + t1;
        x3 += k1 + 13;

        x0 += x1 + k3;
        x1 = Long.rotateLeft(x1, 25) ^ x0;
        x2 += x3 + k0 + t2;
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

        x1 += k0 + t2;
        x3 += k2 + 14;

        x0 += x1 + k4;
        x1 = Long.rotateLeft(x1, 14) ^ x0;
        x2 += x3 + k1 + t0;
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

        x1 += k1 + t0;
        x3 += k3 + 15;

        x0 += x1 + k0;
        x1 = Long.rotateLeft(x1, 25) ^ x0;
        x2 += x3 + k2 + t1;
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

        x1 += k2 + t1;
        x3 += k4 + 16;

        x0 += x1 + k1;
        x1 = Long.rotateLeft(x1, 14) ^ x0;
        x2 += x3 + k3 + t2;
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

        x1 += k3 + t2;
        x3 += k0 + 17;

        x0 += x1 + k2;
        x1 = Long.rotateLeft(x1, 25) ^ x0;
        x2 += x3 + k4 + t0;
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

        dst[0] = x0 + k3;
        dst[1] = x1 + k4 + t0;
        dst[2] = x2 + k0 + t1;
        dst[3] = x3 + k1 + 18;
    }

    public static Skein skein256(int outputSize) {
        if ((outputSize & 7) != 0) {
            throw new IllegalArgumentException("This implementaion only supports byte-length outputs");
        }
        return new Skein(outputSize >>> 3, Type.SKEIN_256);
    }

    private final int outputLength;
    private volatile long[] precomputedState;
    private final Type type;

    private Skein(int outputLength, Type type) {
        this.outputLength = outputLength;
        this.type = type;
    }

    private long[] precomputed() {
        var state = precomputedState;
        if (state == null) {
            synchronized (this) {
                state = precomputedState;
                if (state == null) {
                    state = new long[4];
                    cfgUbi(state, new long[4]);
                    precomputedState = state;
                }
            }
        }
        return state;
    }

    private void cfgUbi(long[] state, long[] data) {
        data[0] = CFG;
        data[1] = outputLength;
        threefish256(state, 32, T_CFG | FIRST | LAST, data, state);
        state[0] ^= data[0];
        state[1] ^= data[1];
    }

    @Override
    public Digest.Engine start() {
        var internal = new Skein256Engine(precomputed(), outputLength);
        return new AbstractDigestEngine(32) {

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
                internal.output(dest, offset);
            }

            @Override
            public Digest getAlgorithm() {
                return Skein.this;
            }
        };
    }

    @Override
    public Mac.Engine start(byte[] key) {
        long[] state = new long[4], data = new long[4];

        data[0] = Tools.load32LE(key, 0);
        data[1] = Tools.load32LE(key, 8);
        data[2] = Tools.load32LE(key, 16);
        data[3] = Tools.load32LE(key, 24);
        threefish256(state, 32, FIRST | LAST, data, state);
        state[0] ^= data[0];
        state[1] ^= data[1];
        state[2] ^= data[2];
        state[3] ^= data[3];

        cfgUbi(state, data);

        var internal = new Skein256Engine(state, outputLength);

        return new AbstractMacEngine(32) {

            @Override
            protected void ingestOneBlock(MemorySegment input, long offset) {
                internal.ingestOneBlock(input, offset);
            }

            @Override
            protected void ingestLastBlock(MemorySegment input, int length) {
                internal.ingestLastBlock(input, length);
            }

            @Override
            protected void getTag(byte[] dest, int offset) {
                internal.output(dest, offset);
            }

            @Override
            public void authenticateTo(byte[] tag, int offset, int length) {
                if (length != outputLength) {
                    throw new IllegalArgumentException("This Skein-256 instance can only produce outputs of " + outputLength + " bytes");
                }
                super.authenticateTo(tag, offset, length);
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
        return 32;
    }

    @Override
    public int tagLength() {
        return outputLength;
    }

    @Override
    public int keyLength() {
        return 32;
    }

    @Override
    public String toString() {
        return "Skein-256-" + outputLength;
    }

    private static class Skein256Engine {

        private final long[] state, data = new long[4];
        private long tweak = T_MSG | FIRST, counter = 0;

        private final int outputLength;

        private Skein256Engine(long[] state, int outputSize) {
            this.state = state;
            this.outputLength = outputSize;
        }

        protected void ingestOneBlock(MemorySegment input, long offset) {
            counter += 32;

            data[0] = input.get(LAYOUT, offset + 0);
            data[1] = input.get(LAYOUT, offset + 8);
            data[2] = input.get(LAYOUT, offset + 16);
            data[3] = input.get(LAYOUT, offset + 24);

            threefish256(state, counter, tweak, data, state);

            state[0] ^= data[0];
            state[1] ^= data[1];
            state[2] ^= data[2];
            state[3] ^= data[3];

            tweak &= NOT_FIRST;
        }

        protected void ingestLastBlock(MemorySegment input, int length) {
            Tools.zeropad(input, length);
            counter += length;

            data[0] = input.get(LAYOUT, 0);
            data[1] = input.get(LAYOUT, 8);
            data[2] = input.get(LAYOUT, 16);
            data[3] = input.get(LAYOUT, 24);

            threefish256(state, counter, tweak | LAST, data, state);

            state[0] ^= data[0];
            state[1] ^= data[1];
            state[2] ^= data[2];
            state[3] ^= data[3];

            data[1] = 0;
            data[2] = 0;
            data[3] = 0;
        }

        private void digestBlock(byte[] dest, int offset, int index) {
            data[0] = index;
            data[1] = 0;
            data[2] = 0;
            data[3] = 0;
            threefish256(state, 8, T_OUT | FIRST | LAST, data, data);
            Tools.store64LE(data[0], dest, offset + 0);
            Tools.store64LE(data[1], dest, offset + 8);
            Tools.store64LE(data[2], dest, offset + 16);
            Tools.store64LE(data[3], dest, offset + 24);
        }

        public void output(byte[] dest, int offset) {
            int index = 0;
            long want = outputLength;
            while (want >= 32) {
                digestBlock(dest, offset, index++);
                offset += 32;
                want -= 32;
            }
            if (want > 0) {
                byte[] temp = new byte[32];
                digestBlock(temp, 0, index);
                System.arraycopy(temp, 0, dest, offset, (int) want);
            }
        }

    }

    private enum Type {
        SKEIN_256
    }

}
