/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.hash;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Arrays;
import org.asterisk.crypto.helper.AbstractDigestEngine;
import org.asterisk.crypto.helper.AbstractMacEngine;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.interfaces.Digest;
import org.asterisk.crypto.interfaces.Mac;

/**
 *
 * @author Sayantan Chakraborty
 */
//For some unknown reason, this apparently slow and rolled process is faster than any unrolled version
public class Blake2b implements Digest, Mac {

    private static final ValueLayout.OfLong LAYOUT = Tools.LITTLE_ENDIAN_64_BIT;

    private static final long[] IV = {
        0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
        0x510e527fade682d1L, 0x9b05688c2b3e6c1fL, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
    };

    private static final byte[] DEFAULT_SALT = new byte[16];

    public static final Blake2b DEFAULT = new Blake2b("");

    public static final Blake2b personalized(String personalization) {
        return personalization.isEmpty() ? DEFAULT : new Blake2b(personalization);
    }

    private static void g(long[] state, int a, int b, int c, int d, long x, long y) {
        state[a] += state[b] + x;
        state[d] = Long.rotateRight(state[d] ^ state[a], 32);
        state[c] += state[d];
        state[b] = Long.rotateRight(state[b] ^ state[c], 24);
        state[a] += state[b] + y;
        state[d] = Long.rotateRight(state[d] ^ state[a], 16);
        state[c] += state[d];
        state[b] = Long.rotateRight(state[b] ^ state[c], 63);
    }

    private static void round(long[] v, long m0, long m1, long m2, long m3, long m4, long m5, long m6, long m7, long m8, long m9, long m10, long m11, long m12, long m13, long m14, long m15) {
        g(v, 0, 4, 8, 12, m0, m1);
        g(v, 1, 5, 9, 13, m2, m3);
        g(v, 2, 6, 10, 14, m4, m5);
        g(v, 3, 7, 11, 15, m6, m7);

        g(v, 0, 5, 10, 15, m8, m9);
        g(v, 1, 6, 11, 12, m10, m11);
        g(v, 2, 7, 8, 13, m12, m13);
        g(v, 3, 4, 9, 14, m14, m15);
    }

    private static void compress(long[] h, long counterMsb, long counterLsb, boolean lastBlock, MemorySegment input, long offset) {
        compress(h, counterMsb, counterLsb, lastBlock,
                input.get(LAYOUT, offset + 0), input.get(LAYOUT, offset + 8),
                input.get(LAYOUT, offset + 16), input.get(LAYOUT, offset + 24),
                input.get(LAYOUT, offset + 32), input.get(LAYOUT, offset + 40),
                input.get(LAYOUT, offset + 48), input.get(LAYOUT, offset + 56),
                input.get(LAYOUT, offset + 64), input.get(LAYOUT, offset + 72),
                input.get(LAYOUT, offset + 80), input.get(LAYOUT, offset + 88),
                input.get(LAYOUT, offset + 96), input.get(LAYOUT, offset + 104),
                input.get(LAYOUT, offset + 112), input.get(LAYOUT, offset + 120));
    }

    private static void compress(long[] h, long counterMsb, long counterLsb, boolean lastBlock,
            long m0, long m1, long m2, long m3, long m4, long m5, long m6, long m7, long m8, long m9, long m10, long m11, long m12, long m13, long m14, long m15) {

        long[] v = new long[16];
        System.arraycopy(h, 0, v, 0, 8);
        System.arraycopy(IV, 0, v, 8, 8);

        v[12] ^= counterLsb;
        v[13] ^= counterMsb;

        if (lastBlock) {
            v[14] = ~v[14];
        }

        round(v, m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15);
        round(v, m14, m10, m4, m8, m9, m15, m13, m6, m1, m12, m0, m2, m11, m7, m5, m3);
        round(v, m11, m8, m12, m0, m5, m2, m15, m13, m10, m14, m3, m6, m7, m1, m9, m4);
        round(v, m7, m9, m3, m1, m13, m12, m11, m14, m2, m6, m5, m10, m4, m0, m15, m8);
        round(v, m9, m0, m5, m7, m2, m4, m10, m15, m14, m1, m11, m12, m6, m8, m3, m13);
        round(v, m2, m12, m6, m10, m0, m11, m8, m3, m4, m13, m7, m5, m15, m14, m1, m9);
        round(v, m12, m5, m1, m15, m14, m13, m4, m10, m0, m7, m6, m3, m9, m2, m8, m11);
        round(v, m13, m11, m7, m14, m12, m1, m3, m9, m5, m0, m15, m4, m8, m6, m2, m10);
        round(v, m6, m15, m14, m9, m11, m3, m0, m8, m12, m2, m13, m7, m1, m4, m10, m5);
        round(v, m10, m2, m8, m4, m7, m6, m1, m5, m15, m11, m9, m14, m3, m12, m13, m0);
        round(v, m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15);
        round(v, m14, m10, m4, m8, m9, m15, m13, m6, m1, m12, m0, m2, m11, m7, m5, m3);

        for (int i = 0; i < 8; i++) {
            h[i] ^= v[i] ^ v[i + 8];
        }

    }

    private final byte[] pers;
    private final String persString;

    private Blake2b(String personalization) {
        pers = Arrays.copyOf(personalization.getBytes(), 16);
        persString = new String(pers);
    }

    @Override
    public Mac.Engine start(byte[] key) {
        return startSalted(key, DEFAULT_SALT);
    }

    public Mac.Engine startSalted(byte[] key, byte[] salt) {
        var padded = salt.length < 16 ? Arrays.copyOf(salt, 16) : salt;
        return new AbstractMacEngine(128) {

            private final long[] state = IV.clone();

            private long counter = 0;

            {
                state[0] ^= 0x01012040;
                state[4] ^= Tools.load64LE(padded, 0);
                state[5] ^= Tools.load64LE(padded, 8);
                state[6] ^= Tools.load64LE(pers, 0);
                state[7] ^= Tools.load64LE(pers, 8);
                ingest(key, 0, 32);
                setBufferPosition(128);
            }

            @Override
            protected void ingestOneBlock(MemorySegment input, long offset) {
                counter += 128;
                compress(state, 0, counter, false, input, offset);
            }

            @Override
            protected void ingestLastBlock(MemorySegment input, int length) {
                Tools.zeropad(input, length);
                counter += length;
                compress(state, 0, counter, true, input, 0);
            }

            @Override
            protected void getTag(byte[] dest, int offset) {
                Tools.store64LE(state[0], dest, offset + 0);
                Tools.store64LE(state[1], dest, offset + 8);
            }

            @Override
            public Mac getAlgorithm() {
                return Blake2b.this;
            }

        };
    }

    @Override
    public int tagLength() {
        return 16;
    }

    @Override
    public int keyLength() {
        return 32;
    }

    @Override
    public Digest.Engine start() {
        return startSalted(DEFAULT_SALT);
    }

    public Digest.Engine startSalted(byte[] salt) {
        var padded = salt.length < 16 ? Arrays.copyOf(salt, 16) : salt;
        return new AbstractDigestEngine(128) {

            private final long[] state = IV.clone();

            private long counter = 0;

            {
                state[0] ^= 0x01010040;
                state[4] ^= Tools.load64LE(padded, 0);
                state[5] ^= Tools.load64LE(padded, 8);
                state[6] ^= Tools.load64LE(pers, 0);
                state[7] ^= Tools.load64LE(pers, 8);
            }

            @Override
            protected void ingestOneBlock(MemorySegment input, long offset) {
                counter += 128;
                compress(state, 0, counter, false, input, offset);
            }

            @Override
            protected void ingestLastBlock(MemorySegment input, int length) {
                Tools.zeropad(input, length);
                counter += length;
                compress(state, 0, counter, true, input, 0);
            }

            @Override
            protected void getDigest(byte[] dest, int offset) {
                for (int i = 0; i < 8; i++) {
                    Tools.store64LE(state[i], dest, offset + 8 * i);
                }
            }

            @Override
            public Digest getAlgorithm() {
                return Blake2b.this;
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

    @Override
    public String toString() {
        return "Blake2b{personalization=" + persString + "}";
    }

}
