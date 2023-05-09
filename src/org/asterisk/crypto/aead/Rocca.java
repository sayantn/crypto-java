/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.aead;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import org.asterisk.crypto.Tested;
import org.asterisk.crypto.helper.AbstractAuthenticaterEngine;
import org.asterisk.crypto.helper.AbstractVerifierEngine;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.interfaces.AuthenticatedCipher;

import static org.asterisk.crypto.lowlevel.AesPermutation.aesRound;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum Rocca implements AuthenticatedCipher {

    @Tested
    ROCCA;

    private static final ValueLayout.OfInt LAYOUT = Tools.BIG_ENDIAN_32_BIT;

    private static final int[] Z0 = {
        0xcd65ef23, 0x91443771, 0x22ae28d7, 0x982f8a42
    };

    private static final int[] Z1 = {
        0xbcdb8981, 0xa5dbb5e9, 0x2f3b4dec, 0xcffbc0b5
    };

    private static void round(int[] state, int m0, int m1, int m2, int m3, int m4, int m5, int m6, int m7) {
        int temp0 = state[28];
        int temp1 = state[29];
        int temp2 = state[30];
        int temp3 = state[31];

        int temp4 = state[24];
        int temp5 = state[25];
        int temp6 = state[26];
        int temp7 = state[27];

        state[28] = temp4 ^ state[0];
        state[29] = temp5 ^ state[1];
        state[30] = temp6 ^ state[2];
        state[31] = temp7 ^ state[3];

        aesRound(state, 20, state, 24, state, 16);

        aesRound(state, 16, state, 20, state, 12);

        state[16] = state[12] ^ m4;
        state[17] = state[13] ^ m5;
        state[18] = state[14] ^ m6;
        state[19] = state[15] ^ m7;

        aesRound(state, 8, state, 12, state, 4);

        state[8] = state[4] ^ temp4;
        state[9] = state[5] ^ temp5;
        state[10] = state[6] ^ temp6;
        state[11] = state[7] ^ temp7;

        aesRound(state, 0, state, 4, temp0, temp1, temp2, temp3);

        state[0] = temp0 ^ m0;
        state[1] = temp1 ^ m1;
        state[2] = temp2 ^ m2;
        state[3] = temp3 ^ m3;

    }

    private static void round(int[] state, MemorySegment data, long offset) {
        round(state,
                data.get(LAYOUT, offset + 0),
                data.get(LAYOUT, offset + 4),
                data.get(LAYOUT, offset + 8),
                data.get(LAYOUT, offset + 12),
                data.get(LAYOUT, offset + 16),
                data.get(LAYOUT, offset + 20),
                data.get(LAYOUT, offset + 24),
                data.get(LAYOUT, offset + 28));
    }

    private static int[] init(byte[] key, byte[] iv) {
        int k4 = Tools.load32BE(key, 16);
        int k5 = Tools.load32BE(key, 20);
        int k6 = Tools.load32BE(key, 24);
        int k7 = Tools.load32BE(key, 28);

        int iv0 = Tools.load32BE(iv, 0);
        int iv1 = Tools.load32BE(iv, 4);
        int iv2 = Tools.load32BE(iv, 8);
        int iv3 = Tools.load32BE(iv, 12);

        int[] state = {
            k4, k5, k6, k7,
            iv0, iv1, iv2, iv3,
            Z0[0], Z0[1], Z0[2], Z0[3],
            Z1[0], Z1[1], Z1[2], Z1[3],
            iv0 ^ k4, iv1 ^ k5, iv2 ^ k6, iv3 ^ k7,
            0, 0, 0, 0, Tools.load32BE(key, 0), Tools.load32BE(key, 4), Tools.load32BE(key, 8), Tools.load32BE(key, 12),
            0, 0, 0, 0
        };

        for (int i = 0; i < 20; i++) {
            round(state, Z0[0], Z0[1], Z0[2], Z0[3], Z1[0], Z1[1], Z1[2], Z1[3]);
        }

        return state;

    }

    @Override
    public EncryptEngine startEncryption(byte[] key, byte[] iv) {
        return new AbstractAuthenticaterEngine(32) {

            private final int[] state = init(key, iv), data = new int[4];
            private long adlen = 0, msglen = 0;

            @Override
            protected void ingestOneBlock(MemorySegment aad, long offset) {
                round(state, aad, offset);
                adlen++;
            }

            @Override
            protected void ingestLastBlock(MemorySegment aad, int length) {
                if (length == 16) {
                    ingestOneBlock(aad, 0);
                    adlen = Long.reverseBytes(adlen << 8);
                } else if (length > 0) {
                    Tools.zeropad(aad, length);
                    round(state, aad, 0);
                    adlen = Long.reverseBytes((adlen << 8) | (length << 3));
                }
            }

            @Override
            protected void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
                int m0 = plaintext.get(LAYOUT, pOffset + 0);
                int m1 = plaintext.get(LAYOUT, pOffset + 4);
                int m2 = plaintext.get(LAYOUT, pOffset + 8);
                int m3 = plaintext.get(LAYOUT, pOffset + 12);
                int m4 = plaintext.get(LAYOUT, pOffset + 16);
                int m5 = plaintext.get(LAYOUT, pOffset + 20);
                int m6 = plaintext.get(LAYOUT, pOffset + 24);
                int m7 = plaintext.get(LAYOUT, pOffset + 28);

                aesRound(state, 4, data, 0, state, 20);
                ciphertext.set(LAYOUT, cOffset + 0, data[0] ^ m0);
                ciphertext.set(LAYOUT, cOffset + 4, data[1] ^ m1);
                ciphertext.set(LAYOUT, cOffset + 8, data[2] ^ m2);
                ciphertext.set(LAYOUT, cOffset + 12, data[3] ^ m3);

                aesRound(state[0] ^ state[16], state[1] ^ state[17], state[2] ^ state[18], state[3] ^ state[19], data, 0, state, 8);
                ciphertext.set(LAYOUT, cOffset + 16, data[0] ^ m4);
                ciphertext.set(LAYOUT, cOffset + 20, data[1] ^ m5);
                ciphertext.set(LAYOUT, cOffset + 24, data[2] ^ m6);
                ciphertext.set(LAYOUT, cOffset + 28, data[3] ^ m7);

                round(state, m0, m1, m2, m3, m4, m5, m6, m7);

                msglen++;
            }

            @Override
            protected int encryptLastBlock(MemorySegment buffer, int length, MemorySegment ciphertext) {
                if (length == 32) {
                    encryptOneBlock(buffer, 0, ciphertext, 0);
                    msglen = Long.reverseBytes(msglen << 8);
                } else if (length > 0) {
                    Tools.zeropad(buffer, length);
                    encryptOneBlock(buffer, 0, buffer, 0);
                    msglen = Long.reverseBytes(((msglen - 1) << 8) | (length << 3));
                    MemorySegment.copy(buffer, 0, ciphertext, 0, length);
                }
                return length;
            }

            @Override
            protected void finalizeState() {
                int m0 = (int) (adlen >>> 32), m1 = (int) adlen, m2 = (int) (msglen >>> 32), m3 = (int) msglen;

                for (int i = 0; i < 20; i++) {
                    round(state, m0, m1, 0, 0, m2, m3, 0, 0);
                }
            }

            @Override
            protected void generateTag(byte[] dest) {
                Tools.store32BE(state[0] ^ state[4] ^ state[8] ^ state[12] ^ state[16] ^ state[20] ^ state[24] ^ state[28], dest, 0);
                Tools.store32BE(state[1] ^ state[5] ^ state[9] ^ state[13] ^ state[17] ^ state[21] ^ state[25] ^ state[29], dest, 4);
                Tools.store32BE(state[2] ^ state[6] ^ state[10] ^ state[14] ^ state[18] ^ state[22] ^ state[26] ^ state[30], dest, 8);
                Tools.store32BE(state[3] ^ state[7] ^ state[11] ^ state[15] ^ state[19] ^ state[23] ^ state[27] ^ state[31], dest, 12);
            }

            @Override
            public AuthenticatedCipher getAlgorithm() {
                return ROCCA;
            }
        };
    }

    @Override
    public DecryptEngine startDecryption(byte[] key, byte[] iv) {
        return new AbstractVerifierEngine(32) {

            private final int[] state = init(key, iv), data = new int[4];
            private long adlen = 0, msglen = 0;

            @Override
            protected void ingestOneBlock(MemorySegment aad, long offset) {
                round(state, aad, offset);
                adlen++;
            }

            @Override
            protected void ingestLastBlock(MemorySegment aad, int length) {
                if (length == 16) {
                    ingestOneBlock(aad, 0);
                    adlen = Long.reverseBytes(adlen << 8);
                } else if (length > 0) {
                    Tools.zeropad(aad, length);
                    round(state, aad, 0);
                    adlen = Long.reverseBytes((adlen << 8) | (length << 3));
                }
            }

            @Override
            protected void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset) {

                aesRound(state, 4, data, 0, state, 20);

                int m0 = ciphertext.get(LAYOUT, cOffset + 0) ^ data[0];
                int m1 = ciphertext.get(LAYOUT, cOffset + 4) ^ data[1];
                int m2 = ciphertext.get(LAYOUT, cOffset + 8) ^ data[2];
                int m3 = ciphertext.get(LAYOUT, cOffset + 12) ^ data[3];

                aesRound(state[0] ^ state[16], state[1] ^ state[17], state[2] ^ state[18], state[3] ^ state[19], data, 0, state, 8);

                int m4 = ciphertext.get(LAYOUT, cOffset + 16) ^ data[0];
                int m5 = ciphertext.get(LAYOUT, cOffset + 20) ^ data[1];
                int m6 = ciphertext.get(LAYOUT, cOffset + 24) ^ data[2];
                int m7 = ciphertext.get(LAYOUT, cOffset + 28) ^ data[3];

                plaintext.set(LAYOUT, pOffset + 0, m0);
                plaintext.set(LAYOUT, pOffset + 4, m1);
                plaintext.set(LAYOUT, pOffset + 8, m2);
                plaintext.set(LAYOUT, pOffset + 12, m3);
                plaintext.set(LAYOUT, pOffset + 16, m4);
                plaintext.set(LAYOUT, pOffset + 20, m5);
                plaintext.set(LAYOUT, pOffset + 24, m6);
                plaintext.set(LAYOUT, pOffset + 28, m7);

                round(state, m0, m1, m2, m3, m4, m5, m6, m7);

                msglen++;
            }

            @Override
            protected int decryptLastBlock(MemorySegment buffer, int length, MemorySegment plaintext) {
                if (length == 32) {
                    decryptOneBlock(buffer, 0, plaintext, 0);
                    msglen = Long.reverseBytes(msglen << 8);
                } else if (length > 0) {

                    aesRound(state, 4, data, 0, state, 20);
                    buffer.set(LAYOUT, 0, buffer.get(LAYOUT, 0) ^ data[0]);
                    buffer.set(LAYOUT, 4, buffer.get(LAYOUT, 4) ^ data[1]);
                    buffer.set(LAYOUT, 8, buffer.get(LAYOUT, 8) ^ data[2]);
                    buffer.set(LAYOUT, 12, buffer.get(LAYOUT, 12) ^ data[3]);

                    aesRound(state[0] ^ state[16], state[1] ^ state[17], state[2] ^ state[18], state[3] ^ state[19], data, 0, state, 8);
                    buffer.set(LAYOUT, 16, buffer.get(LAYOUT, 16) ^ data[0]);
                    buffer.set(LAYOUT, 20, buffer.get(LAYOUT, 20) ^ data[1]);
                    buffer.set(LAYOUT, 24, buffer.get(LAYOUT, 24) ^ data[2]);
                    buffer.set(LAYOUT, 28, buffer.get(LAYOUT, 28) ^ data[3]);

                    Tools.zeropad(buffer, length);

                    round(state, buffer, 0);

                    MemorySegment.copy(buffer, 0, plaintext, 0, length);

                }
                return length;
            }

            @Override
            protected void finalizeState() {
                int m0 = (int) (adlen >>> 32), m1 = (int) adlen, m2 = (int) (msglen >>> 32), m3 = (int) msglen;

                for (int i = 0; i < 20; i++) {
                    round(state, m0, m1, 0, 0, m2, m3, 0, 0);
                }
            }

            @Override
            protected void generateTag(byte[] dest) {
                Tools.store32BE(state[0] ^ state[4] ^ state[8] ^ state[12] ^ state[16] ^ state[20] ^ state[24] ^ state[28], dest, 0);
                Tools.store32BE(state[1] ^ state[5] ^ state[9] ^ state[13] ^ state[17] ^ state[21] ^ state[25] ^ state[29], dest, 4);
                Tools.store32BE(state[2] ^ state[6] ^ state[10] ^ state[14] ^ state[18] ^ state[22] ^ state[26] ^ state[30], dest, 8);
                Tools.store32BE(state[3] ^ state[7] ^ state[11] ^ state[15] ^ state[19] ^ state[23] ^ state[27] ^ state[31], dest, 12);
            }

            @Override
            public AuthenticatedCipher getAlgorithm() {
                return ROCCA;
            }
        };
    }

    @Override
    public int keyLength() {
        return 32;
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
