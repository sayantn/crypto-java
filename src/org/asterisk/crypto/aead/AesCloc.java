/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.aead;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import org.asterisk.crypto.AuthenticatedCipher;
import org.asterisk.crypto.helper.AbstractAuthenticaterEngine;
import org.asterisk.crypto.helper.AbstractVerifierEngine;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.lowlevel.AesEncApi;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum AesCloc implements AuthenticatedCipher {

    AES_128_CLOC;

    private static final int PARAM = 0xc0000000;

    private static final ValueLayout.OfInt LAYOUT = Tools.BIG_ENDIAN_32_BIT;

    /**
     * a constant-time implementation of the h function in cloc. This should be
     * used instead of a secret-dependent branching in HASH_K
     *
     * @param state
     * @param flag  0 if to do h, -1 if not
     */
    private static void h(int[] state, int flag) {
        int x0 = state[0], x1 = state[1];

        state[0] ^= flag & state[1];
        state[1] ^= flag & state[2];
        state[2] ^= flag & state[3];
        state[3] ^= flag & (x0 ^ x1);
    }

    private static void f1(int[] state) {
        int x0 = state[0], x1 = state[1];

        state[0] ^= state[2];
        state[1] ^= state[3];
        state[3] ^= x1 ^ state[2];
        state[2] ^= x0 ^ x1;
    }

    private static void f2(int[] state) {
        int x0 = state[0], x1 = state[1];

        state[0] = x1;
        state[1] = state[2];
        state[2] = state[3];
        state[3] = x0 ^ x1;
    }

    private static void g2(int[] src, int[] dst) {
        dst[0] = src[1];
        dst[1] = src[2];
        dst[2] = src[3];
        dst[3] = src[0] ^ src[1];
    }

    @Override
    public EncryptEngine startEncryption(byte[] key, byte[] iv) {
        return new AbstractAuthenticaterEngine(16) {

            private final AesEncApi.Aes128EncApi aes = new AesEncApi.Aes128EncApi(key);

            private final int[] state = new int[4], checksum = new int[4];

            private final int[] storednonce = {
                PARAM | (Tools.load32BE(iv, 0) >>> 8), Tools.load32BE(iv, 3), Tools.load32BE(iv, 7), iv[11] << 24
            };

            private boolean first = true;

            @Override
            protected void ingestOneBlock(MemorySegment aad, long offset) {
                if (first) {
                    int temp = aad.get(LAYOUT, offset);

                    state[0] = temp & 0x7fffffff;
                    state[1] = aad.get(LAYOUT, offset + 4);
                    state[2] = aad.get(LAYOUT, offset + 8);
                    state[3] = aad.get(LAYOUT, offset + 12);

                    aes.encryptBlock(state, 0, state, 0);
                    h(state, temp >> 31);

                    first = false;
                } else {
                    state[0] ^= aad.get(LAYOUT, offset + 0);
                    state[1] ^= aad.get(LAYOUT, offset + 4);
                    state[2] ^= aad.get(LAYOUT, offset + 8);
                    state[3] ^= aad.get(LAYOUT, offset + 12);

                    aes.encryptBlock(state, 0, state, 0);
                }
            }

            @Override
            protected void ingestLastBlock(MemorySegment aad, int length) {
                if (length != 16) {
                    Tools.ozpad(aad, length);
                }
                ingestOneBlock(aad, 0);

                state[0] ^= storednonce[0];
                state[1] ^= storednonce[1];
                state[2] ^= storednonce[2];
                state[3] ^= storednonce[3];

                if (length == 16) {
                    f1(state);
                } else {
                    f2(state);
                }

                g2(state, checksum);

                aes.encryptBlock(state, 0, state, 0);
            }

            @Override
            protected void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
                state[0] ^= plaintext.get(LAYOUT, pOffset + 0);
                state[1] ^= plaintext.get(LAYOUT, pOffset + 4);
                state[2] ^= plaintext.get(LAYOUT, pOffset + 8);
                state[3] ^= plaintext.get(LAYOUT, pOffset + 12);

                aes.encryptBlock(checksum, 0, checksum, 0);

                checksum[0] ^= state[0];
                checksum[1] ^= state[1];
                checksum[2] ^= state[2];
                checksum[3] ^= state[3];

                ciphertext.set(LAYOUT, cOffset + 0, state[0]);
                ciphertext.set(LAYOUT, cOffset + 4, state[1]);
                ciphertext.set(LAYOUT, cOffset + 8, state[2]);
                ciphertext.set(LAYOUT, cOffset + 12, state[3]);

                state[0] |= 0x80000000;

                aes.encryptBlock(state, 0, state, 0);

            }

            @Override
            protected int encryptLastBlock(MemorySegment buffer, int length, MemorySegment ciphertext) {
                if (length > 0) {
                    buffer.set(LAYOUT, 0, buffer.get(LAYOUT, 0) ^ state[0]);
                    buffer.set(LAYOUT, 4, buffer.get(LAYOUT, 4) ^ state[1]);
                    buffer.set(LAYOUT, 8, buffer.get(LAYOUT, 8) ^ state[2]);
                    buffer.set(LAYOUT, 12, buffer.get(LAYOUT, 12) ^ state[3]);

                    MemorySegment.copy(buffer, 0, ciphertext, 0, length);

                    if (length != 16) {
                        Tools.ozpad(buffer, length);
                    }

                    aes.encryptBlock(checksum, 0, checksum, 0);

                    checksum[0] ^= buffer.get(LAYOUT, 0);
                    checksum[1] ^= buffer.get(LAYOUT, 4);
                    checksum[2] ^= buffer.get(LAYOUT, 8);
                    checksum[3] ^= buffer.get(LAYOUT, 12);
                }

                if (length == 16) {
                    f1(checksum);
                } else {
                    f2(checksum);
                }

                return length;
            }

            @Override
            protected void finalizeState() {
                aes.encryptBlock(checksum, 0, checksum, 0);
            }

            @Override
            protected void generateTag(byte[] dest) {
                Tools.store32BE(checksum[0], dest, 0);
                Tools.store32BE(checksum[1], dest, 4);
            }

            @Override
            public AuthenticatedCipher getAlgorithm() {
                return AES_128_CLOC;
            }
        };
    }

    @Override
    public DecryptEngine startDecryption(byte[] key, byte[] iv) {
        return new AbstractVerifierEngine(16) {

            private final AesEncApi.Aes128EncApi aes = new AesEncApi.Aes128EncApi(key);

            private final int[] state = new int[4], checksum = new int[4], data = new int[4];

            private final int[] storednonce = {
                PARAM | (Tools.load32BE(iv, 0) >>> 8), Tools.load32BE(iv, 3), Tools.load32BE(iv, 7), iv[11] << 24
            };

            private boolean first = true;

            @Override
            protected void ingestOneBlock(MemorySegment aad, long offset) {
                if (first) {
                    int temp = aad.get(LAYOUT, offset);

                    state[0] = temp & 0x7fffffff;
                    state[1] = aad.get(LAYOUT, offset + 4);
                    state[2] = aad.get(LAYOUT, offset + 8);
                    state[3] = aad.get(LAYOUT, offset + 12);

                    aes.encryptBlock(state, 0, state, 0);
                    h(state, temp >> 31);

                    first = false;
                } else {
                    state[0] ^= aad.get(LAYOUT, offset + 0);
                    state[1] ^= aad.get(LAYOUT, offset + 4);
                    state[2] ^= aad.get(LAYOUT, offset + 8);
                    state[3] ^= aad.get(LAYOUT, offset + 12);

                    aes.encryptBlock(state, 0, state, 0);
                }
            }

            @Override
            protected void ingestLastBlock(MemorySegment aad, int length) {
                if (length != 16) {
                    Tools.ozpad(aad, length);
                }
                ingestOneBlock(aad, 0);

                state[0] ^= storednonce[0];
                state[1] ^= storednonce[1];
                state[2] ^= storednonce[2];
                state[3] ^= storednonce[3];

                if (length == 16) {
                    f1(state);
                } else {
                    f2(state);
                }

                g2(state, checksum);

                aes.encryptBlock(state, 0, state, 0);
            }

            @Override
            protected void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset) {
                data[0] = ciphertext.get(LAYOUT, cOffset + 0);
                data[1] = ciphertext.get(LAYOUT, cOffset + 4);
                data[2] = ciphertext.get(LAYOUT, cOffset + 8);
                data[3] = ciphertext.get(LAYOUT, cOffset + 12);

                aes.encryptBlock(checksum, 0, checksum, 0);

                checksum[0] ^= data[0];
                checksum[1] ^= data[1];
                checksum[2] ^= data[2];
                checksum[3] ^= data[3];

                plaintext.set(LAYOUT, pOffset + 0, state[0] ^ data[0]);
                plaintext.set(LAYOUT, pOffset + 4, state[1] ^ data[1]);
                plaintext.set(LAYOUT, pOffset + 8, state[2] ^ data[2]);
                plaintext.set(LAYOUT, pOffset + 12, state[3] ^ data[3]);

                data[0] |= 0x80000000;

                aes.encryptBlock(data, 0, state, 0);

            }

            @Override
            protected int decryptLastBlock(MemorySegment buffer, int length, MemorySegment plaintext) {
                if (length > 0) {
                    if (length != 16) {
                        Tools.ozpad(buffer, length);
                    }

                    data[0] = buffer.get(LAYOUT, 0);
                    data[1] = buffer.get(LAYOUT, 4);
                    data[2] = buffer.get(LAYOUT, 8);
                    data[3] = buffer.get(LAYOUT, 12);

                    aes.encryptBlock(checksum, 0, checksum, 0);

                    checksum[0] ^= data[0];
                    checksum[1] ^= data[1];
                    checksum[2] ^= data[2];
                    checksum[3] ^= data[3];

                    buffer.set(LAYOUT, 0, data[0] ^ state[0]);
                    buffer.set(LAYOUT, 4, data[1] ^ state[1]);
                    buffer.set(LAYOUT, 8, data[2] ^ state[2]);
                    buffer.set(LAYOUT, 12, data[3] ^ state[3]);

                    MemorySegment.copy(buffer, 0, plaintext, 0, length);
                }

                if (length == 16) {
                    f1(checksum);
                } else {
                    f2(checksum);
                }

                return length;
            }

            @Override
            protected void finalizeState() {
                aes.encryptBlock(checksum, 0, checksum, 0);
            }

            @Override
            protected void generateTag(byte[] dest) {
                Tools.store32BE(checksum[0], dest, 0);
                Tools.store32BE(checksum[1], dest, 4);
            }

            @Override
            public AuthenticatedCipher getAlgorithm() {
                return AES_128_CLOC;
            }

        };
    }

    @Override
    public int keyLength() {
        return 16;
    }

    @Override
    public int ivLength() {
        return 12;
    }

    @Override
    public int tagLength() {
        return 8;
    }

}
