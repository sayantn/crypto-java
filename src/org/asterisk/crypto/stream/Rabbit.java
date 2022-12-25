/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.stream;

import java.lang.foreign.MemorySegment;
import org.asterisk.crypto.Tested;
import org.asterisk.crypto.helper.AbstractStreamEncrypter;
import org.asterisk.crypto.interfaces.Cipher;
import org.asterisk.crypto.interfaces.StreamCipher;

import static org.asterisk.crypto.helper.Tools.BIG_ENDIAN_32_BIT;
import static org.asterisk.crypto.helper.Tools.load32BE;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum Rabbit implements StreamCipher {

    @Tested
    RABBIT;

    private static int g(int upv) {
        long temp = (long)upv * upv;
        return ((int) (temp >>> 32)) ^ ((int) temp);
    }

    private static int counterUpdate(int[] counter, int carry) {
        long temp;

        temp = Integer.toUnsignedLong(counter[0]) + 0x4d34d34dL + carry;
        counter[0] = (int) temp;
        temp = Integer.toUnsignedLong(counter[1]) + 0xd34d34d3L + (temp >>> 32);
        counter[1] = (int) temp;
        temp = Integer.toUnsignedLong(counter[2]) + 0x34d34d34L + (temp >>> 32);
        counter[2] = (int) temp;
        temp = Integer.toUnsignedLong(counter[3]) + 0x4d34d34dL + (temp >>> 32);
        counter[3] = (int) temp;
        temp = Integer.toUnsignedLong(counter[4]) + 0xd34d34d3L + (temp >>> 32);
        counter[4] = (int) temp;
        temp = Integer.toUnsignedLong(counter[5]) + 0x34d34d34L + (temp >>> 32);
        counter[5] = (int) temp;
        temp = Integer.toUnsignedLong(counter[6]) + 0x4d34d34dL + (temp >>> 32);
        counter[6] = (int) temp;
        temp = Integer.toUnsignedLong(counter[7]) + 0xd34d34d3L + (temp >>> 32);
        counter[7] = (int) temp;

        return (int) (temp >>> 32);
    }

    private static void nextState(int[] state, int[] counter) {
        int g0 = g(state[0] + counter[0]);
        int g1 = g(state[1] + counter[1]);
        int g2 = g(state[2] + counter[2]);
        int g3 = g(state[3] + counter[3]);
        int g4 = g(state[4] + counter[4]);
        int g5 = g(state[5] + counter[5]);
        int g6 = g(state[6] + counter[6]);
        int g7 = g(state[7] + counter[7]);

        state[0] = g0 + Integer.rotateLeft(g7, 16) + Integer.rotateLeft(g6, 16);
        state[1] = g1 + Integer.rotateLeft(g0, 8) + g7;
        state[2] = g2 + Integer.rotateLeft(g1, 16) + Integer.rotateLeft(g0, 16);
        state[3] = g3 + Integer.rotateLeft(g2, 8) + g1;
        state[4] = g4 + Integer.rotateLeft(g3, 16) + Integer.rotateLeft(g2, 16);
        state[5] = g5 + Integer.rotateLeft(g4, 8) + g3;
        state[6] = g6 + Integer.rotateLeft(g5, 16) + Integer.rotateLeft(g4, 16);
        state[7] = g7 + Integer.rotateLeft(g6, 8) + g5;
    }

    private static int initialize(int[] state, int[] counter, byte[] key, byte[] iv) {
        int k0 = load32BE(key, 0);
        int k2 = load32BE(key, 4);
        int k4 = load32BE(key, 8);
        int k6 = load32BE(key, 12);

        int k1 = (k0 << 16) | (k2 >>> 16);
        int k3 = (k2 << 16) | (k4 >>> 16);
        int k5 = (k4 << 16) | (k6 >>> 16);
        int k7 = (k6 << 16) | (k0 >>> 16);

        state[0] = k6;
        counter[0] = Integer.rotateLeft(k2, 16);
        state[1] = k1;
        counter[1] = Integer.rotateLeft(k5, 16);
        state[2] = k4;
        counter[2] = Integer.rotateLeft(k0, 16);
        state[3] = k7;
        counter[3] = Integer.rotateLeft(k3, 16);
        state[4] = k2;
        counter[4] = Integer.rotateLeft(k6, 16);
        state[5] = k5;
        counter[5] = Integer.rotateLeft(k1, 16);
        state[6] = k0;
        counter[6] = Integer.rotateLeft(k4, 16);
        state[7] = k3;
        counter[7] = Integer.rotateLeft(k7, 16);

        int carry = 0;

        carry = counterUpdate(counter, carry);
        nextState(state, counter);
        carry = counterUpdate(counter, carry);
        nextState(state, counter);
        carry = counterUpdate(counter, carry);
        nextState(state, counter);
        carry = counterUpdate(counter, carry);
        nextState(state, counter);

        counter[0] ^= state[4];
        counter[1] ^= state[5];
        counter[2] ^= state[6];
        counter[3] ^= state[7];
        counter[4] ^= state[0];
        counter[5] ^= state[1];
        counter[6] ^= state[2];
        counter[7] ^= state[3];

        int iv0 = load32BE(iv, 0);
        int iv1 = load32BE(iv, 4);

        int iv2 = (iv0 & 0xffff0000) | (iv1 >>> 16);
        int iv3 = (iv0 << 16) | (iv1 & 0xffff);

        counter[0] ^= iv1;
        counter[1] ^= iv2;
        counter[2] ^= iv0;
        counter[3] ^= iv3;
        counter[4] ^= iv1;
        counter[5] ^= iv2;
        counter[6] ^= iv0;
        counter[7] ^= iv3;

        carry = counterUpdate(counter, carry);
        nextState(state, counter);
        carry = counterUpdate(counter, carry);
        nextState(state, counter);
        carry = counterUpdate(counter, carry);
        nextState(state, counter);
        carry = counterUpdate(counter, carry);
        nextState(state, counter);

        return carry;

    }

    @Override
    public EncryptEngine startEncryption(byte[] key, byte[] iv) {
        return new AbstractStreamEncrypter(16) {

            private final int[] state = new int[8], counter = new int[8];
            private int carry = initialize(state, counter, key, iv);

            @Override
            protected void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {

                carry = counterUpdate(counter, carry);
                nextState(state, counter);

                ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 0, plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 0) ^ state[6] ^ (state[1] << 16) ^ (state[3] >>> 16));
                ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 4, plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 4) ^ state[4] ^ (state[7] << 16) ^ (state[1] >>> 16));
                ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 8, plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 8) ^ state[2] ^ (state[5] << 16) ^ (state[7] >>> 16));
                ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 12, plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 12) ^ state[0] ^ (state[3] << 16) ^ (state[5] >>> 16));
            }

            @Override
            public Cipher getAlgorithm() {
                return RABBIT;
            }

        };
    }

    @Override
    public int keyLength() {
        return 16;
    }

    @Override
    public int ivLength() {
        return 8;
    }

}
