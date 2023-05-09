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
package org.asterisk.crypto.aead;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import org.asterisk.crypto.helper.AbstractAuthenticaterEngine;
import org.asterisk.crypto.helper.AbstractVerifierEngine;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.interfaces.AuthenticatedCipher;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum Acorn implements AuthenticatedCipher {
    ACORN;

    private static final ValueLayout.OfInt LAYOUT = Tools.BIG_ENDIAN_32_BIT;

    private static int maj(int x, int y, int z) {
        return (x & y) ^ (y & z) ^ (z & x);
    }

    private static int ch(int x, int y, int z) {
        return (x & y) ^ (~x & z);
    }

    private static int encrypt32(long[] state, int pt, int ca, int cb) {
        long word235 = state[5] >>> 5;
        long word196 = state[4] >>> 3;
        long word160 = state[3] >>> 6;
        long word111 = state[2] >>> 4;
        long word66 = state[1] >>> 5;
        long word23 = state[0] >>> 23;
        int word244 = (int) (state[5] >>> 14);
        int word12 = (int) (state[0] >>> 12);

        state[6] ^= (state[5] ^ word235) & 0xffffffffL;
        state[5] ^= (state[4] ^ word196) & 0xffffffffL;
        state[4] ^= (state[3] ^ word160) & 0xffffffffL;
        state[3] ^= (state[2] ^ word111) & 0xffffffffL;
        state[2] ^= (state[1] ^ word66) & 0xffffffffL;
        state[1] ^= (state[0] ^ word23) & 0xffffffffL;

        int ks = word12 ^ (int) state[3] ^ maj((int) word235, (int) state[1], (int) state[4]) ^ ch((int) state[5], (int) word111, (int) word66);

        int f = (int) state[0] ^ (~(int) state[2]) ^ maj(word244, (int) word23, (int) word160) ^ ((int) word196 & ca) ^ (cb & ks) ^ pt;
        state[6] ^= (f & 0xffffffffL) << 4;

        state[0] = (state[0] >>> 32) | ((state[1] & 0xffffffffL) << 29);
        state[1] = (state[1] >>> 32) | ((state[2] & 0xffffffffL) << 14);
        state[2] = (state[2] >>> 32) | ((state[3] & 0xffffffffL) << 15);
        state[3] = (state[3] >>> 32) | ((state[4] & 0xffffffffL) << 7);
        state[4] = (state[4] >>> 32) | ((state[5] & 0xffffffffL) << 5);
        state[5] = (state[5] >>> 32) | ((state[6] & 0xffffffffL) << 27);
        state[6] >>>= 32;

        return pt ^ ks;
    }

    private static byte encrypt8(long[] state, byte pt, int ca, int cb) {
        long word235 = state[5] >>> 5;
        long word196 = state[4] >>> 3;
        long word160 = state[3] >>> 6;
        long word111 = state[2] >>> 4;
        long word66 = state[1] >>> 5;
        long word23 = state[0] >>> 23;
        int word244 = (int) (state[5] >>> 14);
        int word12 = (int) (state[0] >>> 12);

        state[6] ^= (state[5] ^ word235) & 0xffL;
        state[5] ^= (state[4] ^ word196) & 0xffL;
        state[4] ^= (state[3] ^ word160) & 0xffL;
        state[3] ^= (state[2] ^ word111) & 0xffL;
        state[2] ^= (state[1] ^ word66) & 0xffL;
        state[1] ^= (state[0] ^ word23) & 0xffL;

        int ks = word12 ^ (int) state[3] ^ maj((int) word235, (int) state[1], (int) state[4]) ^ ch((int) state[5], (int) word111, (int) word66);

        int f = (int) state[0] ^ (~(int) state[2]) ^ maj(word244, (int) word23, (int) word160) ^ ((int) word196 & ca) ^ (cb & ks) ^ pt;
        state[6] ^= (f & 0xffL) << 4;

        state[0] = (state[0] >>> 8) | ((state[1] & 0xffffffffL) << 53);
        state[1] = (state[1] >>> 8) | ((state[2] & 0xffffffffL) << 38);
        state[2] = (state[2] >>> 8) | ((state[3] & 0xffffffffL) << 39);
        state[3] = (state[3] >>> 8) | ((state[4] & 0xffffffffL) << 31);
        state[4] = (state[4] >>> 8) | ((state[5] & 0xffffffffL) << 29);
        state[5] = (state[5] >>> 8) | ((state[6] & 0xffffffffL) << 51);
        state[6] >>>= 8;

        return (byte) (pt ^ ks);
    }

    private static int decrypt32(long[] state, int ct, int ca, int cb) {
        long word235 = state[5] >>> 5;
        long word196 = state[4] >>> 3;
        long word160 = state[3] >>> 6;
        long word111 = state[2] >>> 4;
        long word66 = state[1] >>> 5;
        long word23 = state[0] >>> 23;
        int word244 = (int) (state[5] >>> 14);
        int word12 = (int) (state[0] >>> 12);

        state[6] ^= (state[5] ^ word235) & 0xffffffffL;
        state[5] ^= (state[4] ^ word196) & 0xffffffffL;
        state[4] ^= (state[3] ^ word160) & 0xffffffffL;
        state[3] ^= (state[2] ^ word111) & 0xffffffffL;
        state[2] ^= (state[1] ^ word66) & 0xffffffffL;
        state[1] ^= (state[0] ^ word23) & 0xffffffffL;

        int ks = word12 ^ (int) state[3] ^ maj((int) word235, (int) state[1], (int) state[4]) ^ ch((int) state[5], (int) word111, (int) word66);

        int pt = ct ^ ks;

        int f = (int) state[0] ^ (~(int) state[2]) ^ maj(word244, (int) word23, (int) word160) ^ ((int) word196 & ca) ^ (cb & ks) ^ pt;
        state[6] ^= (f & 0xffffffffL) << 4;

        state[0] = (state[0] >>> 32) | ((state[1] & 0xffffffffL) << 29);
        state[1] = (state[1] >>> 32) | ((state[2] & 0xffffffffL) << 14);
        state[2] = (state[2] >>> 32) | ((state[3] & 0xffffffffL) << 15);
        state[3] = (state[3] >>> 32) | ((state[4] & 0xffffffffL) << 7);
        state[4] = (state[4] >>> 32) | ((state[5] & 0xffffffffL) << 5);
        state[5] = (state[5] >>> 32) | ((state[6] & 0xffffffffL) << 27);
        state[6] >>>= 32;

        return pt;
    }

    private static byte decrypt8(long[] state, byte ct, int ca, int cb) {
        long word235 = state[5] >>> 5;
        long word196 = state[4] >>> 3;
        long word160 = state[3] >>> 6;
        long word111 = state[2] >>> 4;
        long word66 = state[1] >>> 5;
        long word23 = state[0] >>> 23;
        int word244 = (int) (state[5] >>> 14);
        int word12 = (int) (state[0] >>> 12);

        state[6] ^= (state[5] ^ word235) & 0xffL;
        state[5] ^= (state[4] ^ word196) & 0xffL;
        state[4] ^= (state[3] ^ word160) & 0xffL;
        state[3] ^= (state[2] ^ word111) & 0xffL;
        state[2] ^= (state[1] ^ word66) & 0xffL;
        state[1] ^= (state[0] ^ word23) & 0xffL;

        int ks = word12 ^ (int) state[3] ^ maj((int) word235, (int) state[1], (int) state[4]) ^ ch((int) state[5], (int) word111, (int) word66);

        int pt = ct ^ ks;

        int f = (int) state[0] ^ (~(int) state[2]) ^ maj(word244, (int) word23, (int) word160) ^ ((int) word196 & ca) ^ (cb & ks) ^ pt;
        state[6] ^= (f & 0xffL) << 4;

        state[0] = (state[0] >>> 8) | ((state[1] & 0xffffffffL) << 53);
        state[1] = (state[1] >>> 8) | ((state[2] & 0xffffffffL) << 38);
        state[2] = (state[2] >>> 8) | ((state[3] & 0xffffffffL) << 39);
        state[3] = (state[3] >>> 8) | ((state[4] & 0xffffffffL) << 31);
        state[4] = (state[4] >>> 8) | ((state[5] & 0xffffffffL) << 29);
        state[5] = (state[5] >>> 8) | ((state[6] & 0xffffffffL) << 51);
        state[6] >>>= 8;

        return (byte) pt;
    }

    private static long[] init(byte[] key, byte[] iv) {
        long[] state = new long[7];

        int key0 = Tools.load32BE(key, 0);
        int key1 = Tools.load32BE(key, 4);
        int key2 = Tools.load32BE(key, 8);
        int key3 = Tools.load32BE(key, 12);

        encrypt32(state, key0, -1, -1);
        encrypt32(state, key1, -1, -1);
        encrypt32(state, key2, -1, -1);
        encrypt32(state, key3, -1, -1);

        encrypt32(state, Tools.load32BE(iv, 0), -1, -1);
        encrypt32(state, Tools.load32BE(iv, 4), -1, -1);
        encrypt32(state, Tools.load32BE(iv, 8), -1, -1);
        encrypt32(state, Tools.load32BE(iv, 12), -1, -1);

        encrypt32(state, key0 ^ 1, -1, -1);
        encrypt32(state, key1, -1, -1);
        encrypt32(state, key2, -1, -1);
        encrypt32(state, key3, -1, -1);

        for (int i = 0; i < 11; i++) {
            encrypt32(state, key0, -1, -1);
            encrypt32(state, key1, -1, -1);
            encrypt32(state, key2, -1, -1);
            encrypt32(state, key3, -1, -1);
        }

        return state;
    }

    private static void finalizeState(long[] state) {
        encrypt32(state, 0, -1, -1);
        encrypt32(state, 0, -1, -1);
        encrypt32(state, 0, -1, -1);
        encrypt32(state, 0, -1, -1);
        encrypt32(state, 0, -1, -1);
        encrypt32(state, 0, -1, -1);
        encrypt32(state, 0, -1, -1);
        encrypt32(state, 0, -1, -1);
        encrypt32(state, 0, -1, -1);
        encrypt32(state, 0, -1, -1);
        encrypt32(state, 0, -1, -1);
        encrypt32(state, 0, -1, -1);
        encrypt32(state, 0, -1, -1);
        encrypt32(state, 0, -1, -1);
        encrypt32(state, 0, -1, -1);
        encrypt32(state, 0, -1, -1);
        encrypt32(state, 0, -1, -1);
        encrypt32(state, 0, -1, -1);
        encrypt32(state, 0, -1, -1);
        encrypt32(state, 0, -1, -1);
    }

    private static void generateTag(long[] state, byte[] tag) {
        Tools.store32BE(encrypt32(state, 0, -1, -1), tag, 0);
        Tools.store32BE(encrypt32(state, 0, -1, -1), tag, 4);
        Tools.store32BE(encrypt32(state, 0, -1, -1), tag, 8);
        Tools.store32BE(encrypt32(state, 0, -1, -1), tag, 12);
    }

    private static void pad(long[] state, int cb) {
        encrypt32(state, 1, -1, cb);
        encrypt32(state, 0, -1, cb);
        encrypt32(state, 0, -1, cb);
        encrypt32(state, 0, -1, cb);
        encrypt32(state, 0, 0, cb);
        encrypt32(state, 0, 0, cb);
        encrypt32(state, 0, 0, cb);
        encrypt32(state, 0, 0, cb);
    }

    @Override
    public EncryptEngine startEncryption(byte[] key, byte[] iv) {
        return new AbstractAuthenticaterEngine(4) {

            private final long[] state = init(key, iv);

            @Override
            protected void ingestOneBlock(MemorySegment aad, long offset) {
                encrypt32(state, aad.get(LAYOUT, offset), -1, -1);
            }

            @Override
            protected void ingestLastBlock(MemorySegment aad, int length) {
                for (int i = 0; i < length; i++) {
                    encrypt8(state, aad.get(ValueLayout.JAVA_BYTE, i), -1, -1);
                }
                pad(state, -1);
            }

            @Override
            protected void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
                ciphertext.set(LAYOUT, cOffset, encrypt32(state, plaintext.get(LAYOUT, pOffset), -1, 0));
            }

            @Override
            protected int encryptLastBlock(MemorySegment buffer, int length, MemorySegment ciphertext) {
                for (int i = 0; i < length; i++) {
                    ciphertext.set(ValueLayout.JAVA_BYTE, i, encrypt8(state, buffer.get(ValueLayout.JAVA_BYTE, i), -1, 0));
                }
                pad(state, 0);
                return length;
            }

            @Override
            protected void finalizeState() {
                Acorn.finalizeState(state);
            }

            @Override
            protected void generateTag(byte[] dest) {
                Acorn.generateTag(state, dest);
            }

            @Override
            public AuthenticatedCipher getAlgorithm() {
                return ACORN;
            }
        };
    }

    @Override
    public DecryptEngine startDecryption(byte[] key, byte[] iv) {
        return new AbstractVerifierEngine(4) {

            private final long[] state = init(key, iv);

            @Override
            protected void ingestOneBlock(MemorySegment aad, long offset) {
                encrypt32(state, aad.get(LAYOUT, offset), -1, -1);
            }

            @Override
            protected void ingestLastBlock(MemorySegment aad, int length) {
                for (int i = 0; i < length; i++) {
                    encrypt8(state, aad.get(ValueLayout.JAVA_BYTE, i), -1, -1);
                }
                pad(state, -1);
            }

            @Override
            protected void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset) {
                plaintext.set(LAYOUT, pOffset, decrypt32(state, ciphertext.get(LAYOUT, cOffset), -1, 0));
            }

            @Override
            protected int decryptLastBlock(MemorySegment buffer, int length, MemorySegment plaintext) {
                for (int i = 0; i < length; i++) {
                    plaintext.set(ValueLayout.JAVA_BYTE, i, decrypt8(state, buffer.get(ValueLayout.JAVA_BYTE, i), -1, 0));
                }
                pad(state, 0);
                return length;
            }

            @Override
            protected void finalizeState() {
                Acorn.finalizeState(state);
            }

            @Override
            protected void generateTag(byte[] dest) {
                Acorn.generateTag(state, dest);
            }

            @Override
            public AuthenticatedCipher getAlgorithm() {
                return ACORN;
            }
        };
    }

    @Override
    public int keyLength() {
        return 16;
    }

    @Override
    public int ivLength() {
        return 16;
    }

    @Override
    public int tagLength() {
        return 16;
    }

}
