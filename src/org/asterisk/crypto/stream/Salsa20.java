/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.stream;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import org.asterisk.crypto.helper.AbstractStreamEncrypter;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.Cipher;
import org.asterisk.crypto.StreamCipher;

import static org.asterisk.crypto.helper.Tools.load32LE;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum Salsa20 implements StreamCipher {

    SALSA20(10), SALSA20_12(6), SALSA20_8(4);

    private static final ValueLayout.OfInt LAYOUT = Tools.LITTLE_ENDIAN_32_BIT;

    static final int CONST_0 = 0x61707865;
    static final int CONST_1 = 0x3320646e;
    static final int CONST_2 = 0x79622d32;
    static final int CONST_3 = 0x6b206574;

    public static void salsa20Core(int[] state, int[] buffer, int rounds) {
        int x4 = state[4] ^ Integer.rotateLeft(state[0] + state[12], 7);
        int x8 = state[8] ^ Integer.rotateLeft(x4 + state[0], 9);
        int x12 = state[12] ^ Integer.rotateLeft(x8 + x4, 13);
        int x0 = state[0] ^ Integer.rotateLeft(x12 + x8, 18);

        int x5 = state[5] ^ Integer.rotateLeft(state[1] + state[13], 7);
        int x9 = state[9] ^ Integer.rotateLeft(x5 + state[1], 9);
        int x13 = state[13] ^ Integer.rotateLeft(x9 + x5, 13);
        int x1 = state[1] ^ Integer.rotateLeft(x13 + x9, 18);

        int x6 = state[6] ^ Integer.rotateLeft(state[2] + state[14], 7);
        int x10 = state[10] ^ Integer.rotateLeft(x6 + state[2], 9);
        int x14 = state[14] ^ Integer.rotateLeft(x10 + x6, 13);
        int x2 = state[2] ^ Integer.rotateLeft(x14 + x10, 18);

        int x7 = state[7] ^ Integer.rotateLeft(state[3] + state[15], 7);
        int x11 = state[11] ^ Integer.rotateLeft(x7 + state[3], 9);
        int x15 = state[15] ^ Integer.rotateLeft(x11 + x7, 13);
        int x3 = state[3] ^ Integer.rotateLeft(x15 + x11, 18);

        x1 ^= Integer.rotateLeft(x0 + x3, 7);
        x2 ^= Integer.rotateLeft(x1 + x0, 9);
        x3 ^= Integer.rotateLeft(x2 + x1, 13);
        x0 ^= Integer.rotateLeft(x3 + x2, 18);

        x6 ^= Integer.rotateLeft(x5 + x4, 7);
        x7 ^= Integer.rotateLeft(x6 + x5, 9);
        x4 ^= Integer.rotateLeft(x7 + x6, 13);
        x5 ^= Integer.rotateLeft(x4 + x7, 18);

        x11 ^= Integer.rotateLeft(x10 + x9, 7);
        x8 ^= Integer.rotateLeft(x11 + x10, 9);
        x9 ^= Integer.rotateLeft(x8 + x11, 13);
        x10 ^= Integer.rotateLeft(x9 + x8, 18);

        x12 ^= Integer.rotateLeft(x15 + x14, 7);
        x13 ^= Integer.rotateLeft(x12 + x15, 9);
        x14 ^= Integer.rotateLeft(x13 + x12, 13);
        x15 ^= Integer.rotateLeft(x14 + x13, 18);

        for (int i = 1; i < rounds; i++) {

            x4 ^= Integer.rotateLeft(x0 + x12, 7);
            x8 ^= Integer.rotateLeft(x4 + x0, 9);
            x12 ^= Integer.rotateLeft(x8 + x4, 13);
            x0 ^= Integer.rotateLeft(x12 + x8, 18);

            x5 ^= Integer.rotateLeft(x1 + x13, 7);
            x9 ^= Integer.rotateLeft(x5 + x1, 9);
            x13 ^= Integer.rotateLeft(x9 + x5, 13);
            x1 ^= Integer.rotateLeft(x13 + x9, 18);

            x6 ^= Integer.rotateLeft(x2 + x14, 7);
            x10 ^= Integer.rotateLeft(x6 + x2, 9);
            x14 ^= Integer.rotateLeft(x10 + x6, 13);
            x2 ^= Integer.rotateLeft(x14 + x10, 18);

            x7 ^= Integer.rotateLeft(x3 + x15, 7);
            x11 ^= Integer.rotateLeft(x7 + x3, 9);
            x15 ^= Integer.rotateLeft(x11 + x7, 13);
            x3 ^= Integer.rotateLeft(x15 + x11, 18);

            x1 ^= Integer.rotateLeft(x0 + x3, 7);
            x2 ^= Integer.rotateLeft(x1 + x0, 9);
            x3 ^= Integer.rotateLeft(x2 + x1, 13);
            x0 ^= Integer.rotateLeft(x3 + x2, 18);

            x6 ^= Integer.rotateLeft(x5 + x4, 7);
            x7 ^= Integer.rotateLeft(x6 + x5, 9);
            x4 ^= Integer.rotateLeft(x7 + x6, 13);
            x5 ^= Integer.rotateLeft(x4 + x7, 18);

            x11 ^= Integer.rotateLeft(x10 + x9, 7);
            x8 ^= Integer.rotateLeft(x11 + x10, 9);
            x9 ^= Integer.rotateLeft(x8 + x11, 13);
            x10 ^= Integer.rotateLeft(x9 + x8, 18);

            x12 ^= Integer.rotateLeft(x15 + x14, 7);
            x13 ^= Integer.rotateLeft(x12 + x15, 9);
            x14 ^= Integer.rotateLeft(x13 + x12, 13);
            x15 ^= Integer.rotateLeft(x14 + x13, 18);
        }

        buffer[0] = x0;
        buffer[1] = x1;
        buffer[2] = x2;
        buffer[3] = x3;
        buffer[4] = x4;
        buffer[5] = x5;
        buffer[6] = x6;
        buffer[7] = x7;
        buffer[8] = x8;
        buffer[9] = x9;
        buffer[10] = x10;
        buffer[11] = x11;
        buffer[12] = x12;
        buffer[13] = x13;
        buffer[14] = x14;
        buffer[15] = x15;

    }

    private static int[] expand(byte[] key, byte[] iv) {
        if (key.length < 16) {
            throw new IllegalArgumentException("SALSA20 requires at least a 16-byte key, " + key.length + " bytes provided");
        }
        if (iv.length < 8) {
            throw new IllegalArgumentException("SALSA20 requires a 8-byte iv, " + iv.length + " bytes provided");
        }
        if (key.length < 32) {

            int k0 = load32LE(key, 0), k1 = load32LE(key, 4), k2 = load32LE(key, 8), k3 = load32LE(key, 12);

            return new int[]{
                CONST_0, k0, k1, k2,
                k3, 0x3120646e, load32LE(iv, 0), load32LE(iv, 4),
                0, 0, 0x79622d36, k0,
                k1, k2, k3, 0x6b206574
            };
        } else {
            return new int[]{
                CONST_0, load32LE(key, 0), load32LE(key, 4), load32LE(key, 8),
                load32LE(key, 12), CONST_1, load32LE(iv, 0), load32LE(iv, 4),
                0, 0, CONST_2, load32LE(key, 16),
                load32LE(key, 20), load32LE(key, 24), load32LE(key, 28), CONST_3};
        }
    }

    static void keystreamOneBlock(int[] state, int[] buffer, long counter, int rounds, MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
        state[8] = (int) counter;
        state[9] = (int) (counter >>> 32);

        salsa20Core(state, buffer, rounds);

        ciphertext.set(LAYOUT, cOffset + 0, (buffer[0] + state[0]) ^ plaintext.get(LAYOUT, pOffset + 0));
        ciphertext.set(LAYOUT, cOffset + 4, (buffer[1] + state[1]) ^ plaintext.get(LAYOUT, pOffset + 4));
        ciphertext.set(LAYOUT, cOffset + 8, (buffer[2] + state[2]) ^ plaintext.get(LAYOUT, pOffset + 8));
        ciphertext.set(LAYOUT, cOffset + 12, (buffer[3] + state[3]) ^ plaintext.get(LAYOUT, pOffset + 12));
        ciphertext.set(LAYOUT, cOffset + 16, (buffer[4] + state[4]) ^ plaintext.get(LAYOUT, pOffset + 16));
        ciphertext.set(LAYOUT, cOffset + 20, (buffer[5] + state[5]) ^ plaintext.get(LAYOUT, pOffset + 20));
        ciphertext.set(LAYOUT, cOffset + 24, (buffer[6] + state[6]) ^ plaintext.get(LAYOUT, pOffset + 24));
        ciphertext.set(LAYOUT, cOffset + 28, (buffer[7] + state[7]) ^ plaintext.get(LAYOUT, pOffset + 28));
        ciphertext.set(LAYOUT, cOffset + 32, (buffer[8] + state[8]) ^ plaintext.get(LAYOUT, pOffset + 32));
        ciphertext.set(LAYOUT, cOffset + 36, (buffer[9] + state[9]) ^ plaintext.get(LAYOUT, pOffset + 36));
        ciphertext.set(LAYOUT, cOffset + 40, (buffer[10] + state[10]) ^ plaintext.get(LAYOUT, pOffset + 40));
        ciphertext.set(LAYOUT, cOffset + 44, (buffer[11] + state[11]) ^ plaintext.get(LAYOUT, pOffset + 44));
        ciphertext.set(LAYOUT, cOffset + 48, (buffer[12] + state[12]) ^ plaintext.get(LAYOUT, pOffset + 48));
        ciphertext.set(LAYOUT, cOffset + 52, (buffer[13] + state[13]) ^ plaintext.get(LAYOUT, pOffset + 52));
        ciphertext.set(LAYOUT, cOffset + 56, (buffer[14] + state[14]) ^ plaintext.get(LAYOUT, pOffset + 56));
        ciphertext.set(LAYOUT, cOffset + 60, (buffer[15] + state[15]) ^ plaintext.get(LAYOUT, pOffset + 60));

    }

    private final int rounds;

    private Salsa20(int rounds) {
        this.rounds = rounds;
    }

    @Override
    public EncryptEngine startEncryption(byte[] key, byte[] iv) {
        return new AbstractStreamEncrypter(64) {

            private final int[] state = expand(key, iv), buffer = new int[16];

            private long counter = 0;

            @Override
            protected void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
                keystreamOneBlock(state, buffer, counter++, rounds, plaintext, pOffset, ciphertext, cOffset);
            }

            @Override
            public Cipher getAlgorithm() {
                return Salsa20.this;
            }
        };
    }

    @Override
    public int keyLength() {
        return 32;
    }

    @Override
    public int ivLength() {
        return 8;
    }

}
