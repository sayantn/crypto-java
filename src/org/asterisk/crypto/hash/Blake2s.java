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
public class Blake2s implements Digest, Mac {

    private static final ValueLayout.OfInt LAYOUT = Tools.LITTLE_ENDIAN_32_BIT;

    private static final int[] IV = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    private static final byte[] DEFAULT_SALT = new byte[8];

    public static final Blake2s DEFAULT = new Blake2s("");

    public static final Blake2s personalized(String personalization) {
        return personalization.isEmpty() ? DEFAULT : new Blake2s(personalization);
    }

    private static void g(int[] state, int a, int b, int c, int d, int x, int y) {
        state[a] += state[b] + x;
        state[d] = Integer.rotateRight(state[d] ^ state[a], 16);
        state[c] += state[d];
        state[b] = Integer.rotateRight(state[b] ^ state[c], 12);
        state[a] += state[b] + y;
        state[d] = Integer.rotateRight(state[d] ^ state[a], 8);
        state[c] += state[d];
        state[b] = Integer.rotateRight(state[b] ^ state[c], 7);
    }

    private static void round(int[] v, int m0, int m1, int m2, int m3, int m4, int m5, int m6, int m7, int m8, int m9, int m10, int m11, int m12, int m13, int m14, int m15) {
        g(v, 0, 4, 8, 12, m0, m1);
        g(v, 1, 5, 9, 13, m2, m3);
        g(v, 2, 6, 10, 14, m4, m5);
        g(v, 3, 7, 11, 15, m6, m7);

        g(v, 0, 5, 10, 15, m8, m9);
        g(v, 1, 6, 11, 12, m10, m11);
        g(v, 2, 7, 8, 13, m12, m13);
        g(v, 3, 4, 9, 14, m14, m15);
    }

    private static void compress(int[] h, long counter, boolean lastBlock, MemorySegment input, long offset) {
        compress(h, counter, lastBlock,
                input.get(LAYOUT, offset + 0), input.get(LAYOUT, offset + 4),
                input.get(LAYOUT, offset + 8), input.get(LAYOUT, offset + 12),
                input.get(LAYOUT, offset + 16), input.get(LAYOUT, offset + 20),
                input.get(LAYOUT, offset + 24), input.get(LAYOUT, offset + 28),
                input.get(LAYOUT, offset + 32), input.get(LAYOUT, offset + 36),
                input.get(LAYOUT, offset + 40), input.get(LAYOUT, offset + 44),
                input.get(LAYOUT, offset + 48), input.get(LAYOUT, offset + 52),
                input.get(LAYOUT, offset + 56), input.get(LAYOUT, offset + 60));
    }

    private static void compress(int[] h, long counter, boolean lastBlock,
            int m0, int m1, int m2, int m3, int m4, int m5, int m6, int m7, int m8, int m9, int m10, int m11, int m12, int m13, int m14, int m15) {

        int[] v = new int[16];
        System.arraycopy(h, 0, v, 0, 8);
        System.arraycopy(IV, 0, v, 8, 8);

        v[12] ^= (int) counter;
        v[13] ^= (int) (counter >>> 32);

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

        for (int i = 0; i < 8; i++) {
            h[i] ^= v[i] ^ v[i + 8];
        }

    }

    private final byte[] pers;
    private final String persString;

    private Blake2s(String personalization) {
        pers = Arrays.copyOf(personalization.getBytes(), 8);
        persString = new String(pers);
    }

    @Override
    public Mac.Engine start(byte[] key) {
        return startSalted(key, DEFAULT_SALT);
    }

    public Mac.Engine startSalted(byte[] key, byte[] salt) {
        var padded = salt.length < 8 ? Arrays.copyOf(salt, 8) : salt;
        return new AbstractMacEngine(64) {

            private final int[] state = IV.clone();

            private long counter = 0;

            {
                state[0] ^= 0x01012020;
                state[4] ^= Tools.load32LE(padded, 0);
                state[5] ^= Tools.load32LE(padded, 4);
                state[6] ^= Tools.load32LE(pers, 0);
                state[7] ^= Tools.load32LE(pers, 4);
                ingest(key, 0, 32);
                setBufferPosition(64);
            }

            @Override
            protected void ingestOneBlock(MemorySegment input, long offset) {
                counter += 64;
                compress(state, counter, false, input, offset);
            }

            @Override
            protected void ingestLastBlock(MemorySegment input, int length) {
                Tools.zeropad(input, length);
                counter += length;
                compress(state, counter, true, input, 0);
            }

            @Override
            protected void getTag(byte[] dest, int offset) {
                Tools.store32LE(state[0], dest, offset + 0);
                Tools.store32LE(state[1], dest, offset + 4);
                Tools.store32LE(state[2], dest, offset + 8);
                Tools.store32LE(state[3], dest, offset + 12);
            }

            @Override
            public Mac getAlgorithm() {
                return Blake2s.this;
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
        var padded = salt.length < 8 ? Arrays.copyOf(salt, 8) : salt;
        return new AbstractDigestEngine(64) {

            private final int[] state = IV.clone();

            private long counter = 0;

            {
                state[0] ^= 0x01010020;
                state[4] ^= Tools.load32BE(padded, 0);
                state[5] ^= Tools.load32BE(padded, 4);
                state[6] ^= Tools.load32BE(pers, 0);
                state[7] ^= Tools.load32BE(pers, 4);
            }

            @Override
            protected void ingestOneBlock(MemorySegment input, long offset) {
                counter += 64;
                compress(state, counter, false, input, offset);
            }

            @Override
            protected void ingestLastBlock(MemorySegment input, int length) {
                Tools.zeropad(input, length);
                counter += length;
                compress(state, counter, true, input, 0);
            }

            @Override
            protected void getDigest(byte[] dest, int offset) {
                for (int i = 0; i < 8; i++) {
                    Tools.store32LE(state[i], dest, offset + 4 * i);
                }
            }

            @Override
            public Digest getAlgorithm() {
                return Blake2s.this;
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

    @Override
    public String toString() {
        return "Blake2s{personalization=" + persString + "}";
    }

}
