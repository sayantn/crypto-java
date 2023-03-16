/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.stream;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import org.asterisk.crypto.Tested;
import org.asterisk.crypto.helper.AbstractStreamEncrypter;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.interfaces.Cipher;
import org.asterisk.crypto.interfaces.StreamCipher;
import org.asterisk.crypto.mac.Poly1305;

import static org.asterisk.crypto.helper.Tools.load32LE;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum ChaCha implements StreamCipher {

    CHACHA20(10), CHACHA6(3), CHACHA12(6), 
    @Tested
    CHACHA20_IETF(10) {

        @Override
        public ChaChaEngine startEncryption(byte[] key, byte[] iv) {
            if (iv.length < 12) {
                throw new IllegalArgumentException("ChaCha20-IETF requires a 12-byte iv, " + iv.length + " bytes provided");
            }
            return new ChaChaEngine(key, iv, 4, (long) load32LE(iv, 0) << 32);
        }

        @Override
        public int ivLength() {
            return 12;
        }
    };

    private static final ValueLayout.OfInt LAYOUT = Tools.LITTLE_ENDIAN_32_BIT;

    public static void chachaCore(int[] state, int[] buffer, int rounds) {
        int x0 = state[0] + state[4];
        int x12 = Integer.rotateLeft(state[12] ^ state[0], 16);
        int x8 = state[8] + x12;
        int x4 = Integer.rotateLeft(state[4] ^ x8, 12);

        x0 += x4;
        x12 = Integer.rotateLeft(x12 ^ x0, 8);
        x8 += x12;
        x4 = Integer.rotateLeft(x4 ^ x8, 7);

        int x1 = state[1] + state[5];
        int x13 = Integer.rotateLeft(state[13] ^ state[1], 16);
        int x9 = state[9] + x13;
        int x5 = Integer.rotateLeft(state[5] ^ x9, 12);

        x1 += x5;
        x13 = Integer.rotateLeft(x13 ^ x1, 8);
        x9 += x13;
        x5 = Integer.rotateLeft(x5 ^ x9, 7);

        int x2 = state[2] + state[6];
        int x14 = Integer.rotateLeft(state[14] ^ state[2], 16);
        int x10 = state[10] + x14;
        int x6 = Integer.rotateLeft(state[6] ^ x10, 12);

        x2 += x6;
        x14 = Integer.rotateLeft(x14 ^ x2, 8);
        x10 += x14;
        x6 = Integer.rotateLeft(x6 ^ x10, 7);

        int x3 = state[3] + state[7];
        int x15 = Integer.rotateLeft(state[15] ^ state[3], 16);
        int x11 = state[11] + x15;
        int x7 = Integer.rotateLeft(state[7] ^ x11, 12);

        x3 += x7;
        x15 = Integer.rotateLeft(x15 ^ x3, 8);
        x11 += x15;
        x7 = Integer.rotateLeft(x7 ^ x11, 7);

        x0 += x5;
        x15 = Integer.rotateLeft(x15 ^ x0, 16);
        x10 += x15;
        x5 = Integer.rotateLeft(x5 ^ x10, 12);
        x0 += x5;
        x15 = Integer.rotateLeft(x15 ^ x0, 8);
        x10 += x15;
        x5 = Integer.rotateLeft(x5 ^ x10, 7);

        x1 += x6;
        x12 = Integer.rotateLeft(x12 ^ x1, 16);
        x11 += x12;
        x6 = Integer.rotateLeft(x6 ^ x11, 12);
        x1 += x6;
        x12 = Integer.rotateLeft(x12 ^ x1, 8);
        x11 += x12;
        x6 = Integer.rotateLeft(x6 ^ x11, 7);

        x2 += x7;
        x13 = Integer.rotateLeft(x13 ^ x2, 16);
        x8 += x13;
        x7 = Integer.rotateLeft(x7 ^ x8, 12);
        x2 += x7;
        x13 = Integer.rotateLeft(x13 ^ x2, 8);
        x8 += x13;
        x7 = Integer.rotateLeft(x7 ^ x8, 7);

        x3 += x4;
        x14 = Integer.rotateLeft(x14 ^ x3, 16);
        x9 += x14;
        x4 = Integer.rotateLeft(x4 ^ x9, 12);
        x3 += x4;
        x14 = Integer.rotateLeft(x14 ^ x3, 8);
        x9 += x14;
        x4 = Integer.rotateLeft(x4 ^ x9, 7);

        for (int i = 1; i < rounds; i++) {
            x0 += x4;
            x12 = Integer.rotateLeft(x12 ^ x0, 16);
            x8 += x12;
            x4 = Integer.rotateLeft(x4 ^ x8, 12);
            x0 += x4;
            x12 = Integer.rotateLeft(x12 ^ x0, 8);
            x8 += x12;
            x4 = Integer.rotateLeft(x4 ^ x8, 7);

            x1 += x5;
            x13 = Integer.rotateLeft(x13 ^ x1, 16);
            x9 += x13;
            x5 = Integer.rotateLeft(x5 ^ x9, 12);
            x1 += x5;
            x13 = Integer.rotateLeft(x13 ^ x1, 8);
            x9 += x13;
            x5 = Integer.rotateLeft(x5 ^ x9, 7);

            x2 += x6;
            x14 = Integer.rotateLeft(x14 ^ x2, 16);
            x10 += x14;
            x6 = Integer.rotateLeft(x6 ^ x10, 12);
            x2 += x6;
            x14 = Integer.rotateLeft(x14 ^ x2, 8);
            x10 += x14;
            x6 = Integer.rotateLeft(x6 ^ x10, 7);

            x3 += x7;
            x15 = Integer.rotateLeft(x15 ^ x3, 16);
            x11 += x15;
            x7 = Integer.rotateLeft(x7 ^ x11, 12);
            x3 += x7;
            x15 = Integer.rotateLeft(x15 ^ x3, 8);
            x11 += x15;
            x7 = Integer.rotateLeft(x7 ^ x11, 7);

            x0 += x5;
            x15 = Integer.rotateLeft(x15 ^ x0, 16);
            x10 += x15;
            x5 = Integer.rotateLeft(x5 ^ x10, 12);
            x0 += x5;
            x15 = Integer.rotateLeft(x15 ^ x0, 8);
            x10 += x15;
            x5 = Integer.rotateLeft(x5 ^ x10, 7);

            x1 += x6;
            x12 = Integer.rotateLeft(x12 ^ x1, 16);
            x11 += x12;
            x6 = Integer.rotateLeft(x6 ^ x11, 12);
            x1 += x6;
            x12 = Integer.rotateLeft(x12 ^ x1, 8);
            x11 += x12;
            x6 = Integer.rotateLeft(x6 ^ x11, 7);

            x2 += x7;
            x13 = Integer.rotateLeft(x13 ^ x2, 16);
            x8 += x13;
            x7 = Integer.rotateLeft(x7 ^ x8, 12);
            x2 += x7;
            x13 = Integer.rotateLeft(x13 ^ x2, 8);
            x8 += x13;
            x7 = Integer.rotateLeft(x7 ^ x8, 7);

            x3 += x4;
            x14 = Integer.rotateLeft(x14 ^ x3, 16);
            x9 += x14;
            x4 = Integer.rotateLeft(x4 ^ x9, 12);
            x3 += x4;
            x14 = Integer.rotateLeft(x14 ^ x3, 8);
            x9 += x14;
            x4 = Integer.rotateLeft(x4 ^ x9, 7);
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

    static void keystreamOneBlock(int[] state, int[] buffer, int rounds, MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {

        chachaCore(state, buffer, rounds);

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

    private static int[] expand(byte[] key, byte[] iv, int ivOffset) {
        if (key.length < 32) {
            throw new IllegalArgumentException("ChaCha requires a 32-byte key, " + key.length + " bytes provided");
        }
        if (iv.length - ivOffset < 8) {
            throw new IllegalArgumentException("ChaCha requires a 8-byte iv, " + iv.length + " bytes provided");
        }

        return new int[]{
            Salsa20.CONST_0, Salsa20.CONST_1, Salsa20.CONST_2, Salsa20.CONST_3,
            load32LE(key, 0), load32LE(key, 4), load32LE(key, 8), load32LE(key, 12),
            load32LE(key, 16), load32LE(key, 20), load32LE(key, 24), load32LE(key, 28),
            0, 0, load32LE(iv, ivOffset), load32LE(iv, ivOffset + 4)
        };
    }

    private final int rounds;

    private ChaCha(int rounds) {
        this.rounds = rounds;
    }

    @Override
    public ChaChaEngine startEncryption(byte[] key, byte[] iv) {
        return new ChaChaEngine(key, iv, 0, 0);
    }

    @Override
    public int keyLength() {
        return 32;
    }

    @Override
    public int ivLength() {
        return 8;
    }

    public class ChaChaEngine extends AbstractStreamEncrypter {

        private final int[] state;
        private final int[] buffer = new int[16];
        private long counter;

        public ChaChaEngine(byte[] key, byte[] iv, int ivOffset, long initialCounter) {
            super(64);
            state = expand(key, iv, ivOffset);
            counter = initialCounter;
        }

        @Override
        protected void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
            state[12] = (int) counter;
            state[13] = (int) (counter >>> 32);
            keystreamOneBlock(state, buffer, rounds, plaintext, pOffset, ciphertext, cOffset);
            counter++;
        }

        public Poly1305.Poly1305Engine keyPoly1305() {
            state[12] = (int) counter;
            state[13] = (int) (counter >>> 32);

            chachaCore(state, buffer, rounds);

            buffer[0] += state[0];
            buffer[1] += state[1];
            buffer[2] += state[2];
            buffer[3] += state[3];
            buffer[4] += state[4];
            buffer[5] += state[5];
            buffer[6] += state[6];
            buffer[7] += state[7];

            counter++;

            return new Poly1305.Poly1305Engine(buffer);
        }

        @Override
        public Cipher getAlgorithm() {
            return ChaCha.this;
        }
    }

}
