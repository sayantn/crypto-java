/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.aead;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import org.asterisk.crypto.helper.AbstractAuthenticaterEngine;
import org.asterisk.crypto.helper.AbstractVerifierEngine;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.AuthenticatedCipher;
import org.asterisk.crypto.lowlevel.AesPermutation;

import static org.asterisk.crypto.helper.Tools.load32BE;
import static org.asterisk.crypto.helper.Tools.store32BE;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum Tiaoxin implements AuthenticatedCipher {

    TIAOXIN_346;

    private static final ValueLayout.OfInt LAYOUT = Tools.BIG_ENDIAN_32_BIT;

    private static final int[] Z = {
        0xcd65ef23, 0x91443771, 0x22ae28d7, 0x982f8a42,
        0xbcdb8981, 0xa5dbb5e9, 0x2f3b4dec, 0xcffbc0b5
    };

    private void round(int[] srcState, int[] destState, int m0, int m1, int m2, int m3, int m4, int m5, int m6, int m7, int m8, int m9, int m10, int m11) {
        AesPermutation.aesRound(srcState, 8, destState, 0, srcState[0] ^ m0, srcState[1] ^ m1, srcState[2] ^ m2, srcState[3] ^ m3);
        AesPermutation.aesRound(srcState, 0, destState, 4, Z, 0);

        destState[8] = srcState[4];
        destState[9] = srcState[5];
        destState[10] = srcState[6];
        destState[11] = srcState[7];

        AesPermutation.aesRound(srcState, 24, destState, 12, srcState[12] ^ m4, srcState[13] ^ m5, srcState[14] ^ m6, srcState[15] ^ m7);
        AesPermutation.aesRound(srcState, 12, destState, 16, Z, 0);

        destState[20] = srcState[16];
        destState[21] = srcState[17];
        destState[22] = srcState[18];
        destState[23] = srcState[19];

        destState[24] = srcState[20];
        destState[25] = srcState[21];
        destState[26] = srcState[22];
        destState[27] = srcState[23];

        AesPermutation.aesRound(srcState, 48, destState, 28, srcState[28] ^ m8, srcState[29] ^ m9, srcState[30] ^ m10, srcState[31] ^ m11);
        AesPermutation.aesRound(srcState, 28, destState, 32, Z, 0);

        destState[36] = srcState[32];
        destState[37] = srcState[33];
        destState[38] = srcState[34];
        destState[39] = srcState[35];

        destState[40] = srcState[36];
        destState[41] = srcState[37];
        destState[42] = srcState[38];
        destState[43] = srcState[39];

        destState[44] = srcState[40];
        destState[45] = srcState[41];
        destState[46] = srcState[42];
        destState[47] = srcState[43];

        destState[48] = srcState[44];
        destState[49] = srcState[45];
        destState[50] = srcState[46];
        destState[51] = srcState[47];
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

    @Override
    public AuthenticatedCipher.EncryptEngine startEncryption(byte[] key, byte[] iv) {
        final int k0 = load32BE(key, 0), k1 = load32BE(key, 4), k2 = load32BE(key, 8), k3 = load32BE(key, 12);
        final int iv0 = load32BE(iv, 0), iv1 = load32BE(iv, 4), iv2 = load32BE(iv, 8), iv3 = load32BE(iv, 12);

        return new AbstractAuthenticaterEngine(32) {

            private int[] altstate = {
                k0, k1, k2, k3,
                k0, k1, k2, k3,
                iv0, iv1, iv2, iv3,
                k0, k1, k2, k3,
                k0, k1, k2, k3,
                iv0, iv1, iv2, iv3,
                Z[0], Z[1], Z[2], Z[3],
                k0, k1, k2, k3,
                k0, k1, k2, k3,
                iv0, iv1, iv2, iv3,
                Z[4], Z[5], Z[6], Z[7],
                0, 0, 0, 0,
                0, 0, 0, 0
            }, state = new int[52];

            private long aadlen = 0, msglen = 0;

            {
                for (int i = 0; i < 14; i += 2) {
                    round(altstate, state, Z[0], Z[1], Z[2], Z[3], Z[4], Z[5], Z[6], Z[7], Z[0], Z[1], Z[2], Z[3]);
                    round(state, altstate, Z[0], Z[1], Z[2], Z[3], Z[4], Z[5], Z[6], Z[7], Z[0], Z[1], Z[2], Z[3]);
                }
                round(altstate, state, Z[0], Z[1], Z[2], Z[3], Z[4], Z[5], Z[6], Z[7], Z[0], Z[1], Z[2], Z[3]);
            }

            private void update(int m0, int m1, int m2, int m3, int m4, int m5, int m6, int m7, int m8, int m9, int m10, int m11) {
                round(state, altstate, m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11);

                var temp = altstate;
                altstate = state;
                state = temp;
            }

            @Override
            protected void ingestOneBlock(MemorySegment input, long offset) {
                var m0 = input.get(LAYOUT, offset + 0);
                var m1 = input.get(LAYOUT, offset + 4);
                var m2 = input.get(LAYOUT, offset + 8);
                var m3 = input.get(LAYOUT, offset + 12);
                var m4 = input.get(LAYOUT, offset + 16);
                var m5 = input.get(LAYOUT, offset + 20);
                var m6 = input.get(LAYOUT, offset + 24);
                var m7 = input.get(LAYOUT, offset + 28);

                update(m0, m1, m2, m3, m4, m5, m6, m7, m0 ^ m4, m1 ^ m5, m2 ^ m6, m3 ^ m7);

                aadlen += 256;
            }

            @Override
            protected void ingestLastBlock(MemorySegment buffer, int length) {
                if (length > 0) {
                    Tools.zeropad(buffer, length);
                    ingestOneBlock(buffer, 0);
                    aadlen -= 256 - 8 * length;
                }
            }

            @Override
            public void generateTag(byte[] buffer) {
                store32BE(state[0] ^ state[4] ^ state[8] ^ state[12] ^ state[16] ^ state[20] ^ state[24] ^ state[28] ^ state[32] ^ state[36] ^ state[40] ^ state[44] ^ state[48], buffer, 0);
                store32BE(state[1] ^ state[5] ^ state[9] ^ state[13] ^ state[17] ^ state[21] ^ state[25] ^ state[29] ^ state[33] ^ state[37] ^ state[41] ^ state[45] ^ state[49], buffer, 4);
                store32BE(state[2] ^ state[6] ^ state[10] ^ state[14] ^ state[18] ^ state[22] ^ state[26] ^ state[30] ^ state[34] ^ state[38] ^ state[42] ^ state[46] ^ state[50], buffer, 8);
                store32BE(state[3] ^ state[7] ^ state[11] ^ state[15] ^ state[19] ^ state[23] ^ state[27] ^ state[31] ^ state[35] ^ state[39] ^ state[43] ^ state[47] ^ state[51], buffer, 12);
            }

            @Override
            public AuthenticatedCipher getAlgorithm() {
                return TIAOXIN_346;
            }

            @Override
            protected void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
                var m0 = plaintext.get(LAYOUT, pOffset + 0);
                var m1 = plaintext.get(LAYOUT, pOffset + 4);
                var m2 = plaintext.get(LAYOUT, pOffset + 8);
                var m3 = plaintext.get(LAYOUT, pOffset + 12);
                var m4 = plaintext.get(LAYOUT, pOffset + 16);
                var m5 = plaintext.get(LAYOUT, pOffset + 20);
                var m6 = plaintext.get(LAYOUT, pOffset + 24);
                var m7 = plaintext.get(LAYOUT, pOffset + 28);

                update(m0, m1, m2, m3, m4, m5, m6, m7, m0 ^ m4, m1 ^ m5, m2 ^ m6, m3 ^ m7);

                msglen += 256;

                ciphertext.set(LAYOUT, cOffset + 0, state[0] ^ state[8] ^ state[16] ^ (state[40] & state[24]));
                ciphertext.set(LAYOUT, cOffset + 4, state[1] ^ state[9] ^ state[17] ^ (state[41] & state[25]));
                ciphertext.set(LAYOUT, cOffset + 8, state[2] ^ state[10] ^ state[18] ^ (state[42] & state[26]));
                ciphertext.set(LAYOUT, cOffset + 12, state[3] ^ state[11] ^ state[19] ^ (state[43] & state[27]));

                ciphertext.set(LAYOUT, cOffset + 16, state[28] ^ state[20] ^ state[4] ^ (state[48] & state[8]));
                ciphertext.set(LAYOUT, cOffset + 20, state[29] ^ state[21] ^ state[5] ^ (state[49] & state[9]));
                ciphertext.set(LAYOUT, cOffset + 24, state[30] ^ state[22] ^ state[6] ^ (state[50] & state[10]));
                ciphertext.set(LAYOUT, cOffset + 28, state[31] ^ state[23] ^ state[7] ^ (state[51] & state[11]));
            }

            @Override
            protected int encryptLastBlock(MemorySegment buffer, int length, MemorySegment ciphertext) {
                if (length > 0) {
                    Tools.zeropad(buffer, length);
                    encryptOneBlock(buffer, 0, buffer, 0);
                    msglen -= 256 - 8 * length;
                    MemorySegment.copy(buffer, 0, ciphertext, 0, length);
                }
                return length;
            }

            @Override
            protected void finalizeState() {
                int aad2 = (int) (aadlen >>> 32), aad3 = (int) aadlen;
                int msg2 = (int) (msglen >>> 32), msg3 = (int) msglen;

                update(0, 0, aad2, aad3, 0, 0, msg2, msg3, 0, 0, aad2 ^ msg2, aad3 ^ msg3);

                for (int i = 0; i < 20; i += 2) {
                    round(state, altstate, Z[4], Z[5], Z[6], Z[7], Z[0], Z[1], Z[2], Z[3], Z[4], Z[5], Z[6], Z[7]);
                    round(altstate, state, Z[4], Z[5], Z[6], Z[7], Z[0], Z[1], Z[2], Z[3], Z[4], Z[5], Z[6], Z[7]);
                }
            }
        };
    }

    @Override
    public AuthenticatedCipher.DecryptEngine startDecryption(byte[] key, byte[] iv) {
        final int k0 = load32BE(key, 0), k1 = load32BE(key, 4), k2 = load32BE(key, 8), k3 = load32BE(key, 12);
        final int iv0 = load32BE(iv, 0), iv1 = load32BE(iv, 4), iv2 = load32BE(iv, 8), iv3 = load32BE(iv, 12);

        return new AbstractVerifierEngine(32) {

            private int[] altstate = {
                k0, k1, k2, k3,
                k0, k1, k2, k3,
                iv0, iv1, iv2, iv3,
                k0, k1, k2, k3,
                k0, k1, k2, k3,
                iv0, iv1, iv2, iv3,
                Z[0], Z[1], Z[2], Z[3],
                k0, k1, k2, k3,
                k0, k1, k2, k3,
                iv0, iv1, iv2, iv3,
                Z[4], Z[5], Z[6], Z[7],
                0, 0, 0, 0,
                0, 0, 0, 0
            }, state = new int[52];

            private long aadlen = 0, msglen = 0;

            {
                for (int i = 0; i < 14; i += 2) {
                    round(altstate, state, Z[0], Z[1], Z[2], Z[3], Z[4], Z[5], Z[6], Z[7], Z[0], Z[1], Z[2], Z[3]);
                    round(state, altstate, Z[0], Z[1], Z[2], Z[3], Z[4], Z[5], Z[6], Z[7], Z[0], Z[1], Z[2], Z[3]);
                }
                round(altstate, state, Z[0], Z[1], Z[2], Z[3], Z[4], Z[5], Z[6], Z[7], Z[0], Z[1], Z[2], Z[3]);
            }

            private void update(int m0, int m1, int m2, int m3, int m4, int m5, int m6, int m7, int m8, int m9, int m10, int m11) {
                round(state, altstate, m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11);

                var temp = altstate;
                altstate = state;
                state = temp;
            }

            @Override
            protected void ingestOneBlock(MemorySegment input, long offset) {
                var m0 = input.get(LAYOUT, offset + 0);
                var m1 = input.get(LAYOUT, offset + 4);
                var m2 = input.get(LAYOUT, offset + 8);
                var m3 = input.get(LAYOUT, offset + 12);
                var m4 = input.get(LAYOUT, offset + 16);
                var m5 = input.get(LAYOUT, offset + 20);
                var m6 = input.get(LAYOUT, offset + 24);
                var m7 = input.get(LAYOUT, offset + 28);

                update(m0, m1, m2, m3, m4, m5, m6, m7, m0 ^ m4, m1 ^ m5, m2 ^ m6, m3 ^ m7);

                aadlen += 256;
            }

            @Override
            protected void ingestLastBlock(MemorySegment buffer, int length) {
                if (length > 0) {
                    Tools.zeropad(buffer, length);
                    ingestOneBlock(buffer, 0);
                    aadlen -= 256 - 8 * length;
                }
            }

            @Override
            public void generateTag(byte[] buffer) {
                store32BE(state[0] ^ state[4] ^ state[8] ^ state[12] ^ state[16] ^ state[20] ^ state[24] ^ state[28] ^ state[32] ^ state[36] ^ state[40] ^ state[44] ^ state[48], buffer, 0);
                store32BE(state[1] ^ state[5] ^ state[9] ^ state[13] ^ state[17] ^ state[21] ^ state[25] ^ state[29] ^ state[33] ^ state[37] ^ state[41] ^ state[45] ^ state[49], buffer, 4);
                store32BE(state[2] ^ state[6] ^ state[10] ^ state[14] ^ state[18] ^ state[22] ^ state[26] ^ state[30] ^ state[34] ^ state[38] ^ state[42] ^ state[46] ^ state[50], buffer, 8);
                store32BE(state[3] ^ state[7] ^ state[11] ^ state[15] ^ state[19] ^ state[23] ^ state[27] ^ state[31] ^ state[35] ^ state[39] ^ state[43] ^ state[47] ^ state[51], buffer, 12);
            }

            @Override
            public AuthenticatedCipher getAlgorithm() {
                return TIAOXIN_346;
            }

            @Override
            protected void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset) {
                AesPermutation.aesRound(state, 0, altstate, 4, Z, 0);
                System.arraycopy(state, 4, altstate, 8, 4);

                AesPermutation.aesRound(state, 12, altstate, 16, Z, 0);
                System.arraycopy(state, 16, altstate, 20, 8);

                AesPermutation.aesRound(state, 28, altstate, 32, Z, 0);
                System.arraycopy(state, 32, altstate, 36, 16);

                altstate[0] = ciphertext.get(LAYOUT, cOffset + 0) ^ altstate[8] ^ altstate[16] ^ (altstate[40] & altstate[24]);
                altstate[1] = ciphertext.get(LAYOUT, cOffset + 4) ^ altstate[9] ^ altstate[17] ^ (altstate[41] & altstate[25]);
                altstate[2] = ciphertext.get(LAYOUT, cOffset + 8) ^ altstate[10] ^ altstate[18] ^ (altstate[42] & altstate[26]);
                altstate[3] = ciphertext.get(LAYOUT, cOffset + 12) ^ altstate[11] ^ altstate[19] ^ (altstate[43] & altstate[27]);

                AesPermutation.aesRound(state, 8, state, 4, state[0] ^ altstate[0], state[1] ^ altstate[1], state[2] ^ altstate[2], state[3] ^ altstate[3]);

                plaintext.set(LAYOUT, pOffset + 0, state[4]);
                plaintext.set(LAYOUT, pOffset + 4, state[5]);
                plaintext.set(LAYOUT, pOffset + 8, state[6]);
                plaintext.set(LAYOUT, pOffset + 12, state[7]);

                altstate[28] = ciphertext.get(LAYOUT, cOffset + 16) ^ altstate[20] ^ altstate[4] ^ (altstate[48] & altstate[8]);
                altstate[29] = ciphertext.get(LAYOUT, cOffset + 20) ^ altstate[21] ^ altstate[5] ^ (altstate[49] & altstate[9]);
                altstate[30] = ciphertext.get(LAYOUT, cOffset + 24) ^ altstate[22] ^ altstate[6] ^ (altstate[50] & altstate[10]);
                altstate[31] = ciphertext.get(LAYOUT, cOffset + 28) ^ altstate[23] ^ altstate[7] ^ (altstate[51] & altstate[11]);

                AesPermutation.aesRound(state, 48, state, 8, state[28] ^ altstate[28] ^ state[4], state[29] ^ altstate[29] ^ state[5], state[30] ^ altstate[30] ^ state[6], state[31] ^ altstate[31] ^ state[7]);

                AesPermutation.aesRound(state, 24, altstate, 12, state[12] ^ state[8], state[13] ^ state[9], state[14] ^ state[10], state[15] ^ state[11]);

                plaintext.set(LAYOUT, pOffset + 16, state[8]);
                plaintext.set(LAYOUT, pOffset + 20, state[9]);
                plaintext.set(LAYOUT, pOffset + 24, state[10]);
                plaintext.set(LAYOUT, pOffset + 28, state[11]);

                var temp = altstate;
                altstate = state;
                state = temp;

                msglen += 256;
            }

            @Override
            protected int decryptLastBlock(MemorySegment buffer, int position, MemorySegment plaintext) {
                if (position == 32) {
                    decryptOneBlock(buffer, 0, plaintext, 0);
                    return 32;
                } else if (position > 0) {

                    AesPermutation.aesRound(state, 8, altstate, 0, state, 0);
                    AesPermutation.aesRound(state, 0, altstate, 4, Z, 0);
                    System.arraycopy(state, 4, altstate, 8, 4);

                    AesPermutation.aesRound(state, 24, altstate, 12, state, 12);
                    AesPermutation.aesRound(state, 12, altstate, 16, Z, 0);
                    System.arraycopy(state, 16, altstate, 20, 8);

                    AesPermutation.aesRound(state, 48, altstate, 28, state, 28);
                    AesPermutation.aesRound(state, 28, altstate, 32, Z, 0);
                    System.arraycopy(state, 32, altstate, 36, 16);

                    //using the first 2 blocks of the state array as a buffer
                    state[0] = buffer.get(LAYOUT, 0) ^ altstate[0] ^ altstate[8] ^ altstate[16] ^ (altstate[40] & altstate[24]);
                    state[1] = buffer.get(LAYOUT, 4) ^ altstate[1] ^ altstate[9] ^ altstate[17] ^ (altstate[41] & altstate[25]);
                    state[2] = buffer.get(LAYOUT, 8) ^ altstate[2] ^ altstate[10] ^ altstate[18] ^ (altstate[42] & altstate[26]);
                    state[3] = buffer.get(LAYOUT, 12) ^ altstate[3] ^ altstate[11] ^ altstate[19] ^ (altstate[43] & altstate[27]);

                    state[4] = buffer.get(LAYOUT, 16) ^ altstate[28] ^ altstate[20] ^ altstate[4] ^ (altstate[48] & altstate[8]) ^ state[0];
                    state[5] = buffer.get(LAYOUT, 20) ^ altstate[29] ^ altstate[21] ^ altstate[5] ^ (altstate[49] & altstate[9]) ^ state[1];
                    state[6] = buffer.get(LAYOUT, 24) ^ altstate[30] ^ altstate[22] ^ altstate[6] ^ (altstate[50] & altstate[10]) ^ state[2];
                    state[7] = buffer.get(LAYOUT, 28) ^ altstate[31] ^ altstate[23] ^ altstate[7] ^ (altstate[51] & altstate[11]) ^ state[3];

                    for (int i = 0, j = 0; i < 8; i++, j += 4) {
                        buffer.set(LAYOUT, j, state[i]);
                    }
                    Tools.zeropad(buffer, position);

                    for (int i = 0, j = 0; i < 8; i++, j += 4) {
                        state[i] = buffer.get(LAYOUT, j);
                    }

                    altstate[0] ^= state[0];
                    altstate[1] ^= state[1];
                    altstate[2] ^= state[2];
                    altstate[3] ^= state[3];

                    altstate[12] ^= state[4];
                    altstate[13] ^= state[5];
                    altstate[14] ^= state[6];
                    altstate[15] ^= state[7];

                    altstate[28] ^= state[0] ^ state[4];
                    altstate[29] ^= state[1] ^ state[5];
                    altstate[30] ^= state[2] ^ state[6];
                    altstate[31] ^= state[3] ^ state[7];

                    var temp = altstate;
                    altstate = state;
                    state = temp;

                    msglen += 8 * position;

                    MemorySegment.copy(buffer, 0, plaintext, 0, position);
                }
                return position;
            }

            @Override
            protected void finalizeState() {
                int aad2 = (int) (aadlen >>> 32), aad3 = (int) aadlen;
                int msg2 = (int) (msglen >>> 32), msg3 = (int) msglen;

                update(0, 0, aad2, aad3, 0, 0, msg2, msg3, 0, 0, aad2 ^ msg2, aad3 ^ msg3);

                for (int i = 0; i < 20; i += 2) {
                    round(state, altstate, Z[4], Z[5], Z[6], Z[7], Z[0], Z[1], Z[2], Z[3], Z[4], Z[5], Z[6], Z[7]);
                    round(altstate, state, Z[4], Z[5], Z[6], Z[7], Z[0], Z[1], Z[2], Z[3], Z[4], Z[5], Z[6], Z[7]);
                }
            }

        };
    }

}
