/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.aead;

import java.lang.foreign.MemorySegment;
import org.asterisk.crypto.Tested;
import org.asterisk.crypto.helper.AbstractAuthenticaterEngine;
import org.asterisk.crypto.helper.AbstractVerifierEngine;
import org.asterisk.crypto.interfaces.AuthenticatedCipher;

import static org.asterisk.crypto.helper.Tools.BIG_ENDIAN_32_BIT;
import static org.asterisk.crypto.helper.Tools.load32BE;
import static org.asterisk.crypto.helper.Tools.store32BE;
import static org.asterisk.crypto.lowlevel.AesPermutation.aesRound;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum Aegis implements AuthenticatedCipher {

    AEGIS_128 {

        private static int[] initialize(byte[] key, byte[] iv) {
            if (key.length < 16) {
                throw new IllegalArgumentException("AEGIS-128 requires a key of 16 bytes - passed " + key.length + " bytes");
            }
            if (iv.length < 16) {
                throw new IllegalArgumentException("AEGIS-128 requires an IV of 16 bytes - passed " + iv.length + " bytes");
            }

            int k0 = load32BE(key, 0), k1 = load32BE(key, 4), k2 = load32BE(key, 8), k3 = load32BE(key, 12);
            int nonce0 = k0 ^ load32BE(iv, 0), nonce1 = k1 ^ load32BE(iv, 4),
                    nonce2 = k2 ^ load32BE(iv, 8), nonce3 = k3 ^ load32BE(iv, 12);

            int[] state = {
                nonce0, nonce1, nonce2, nonce3,
                CONST[4], CONST[5], CONST[6], CONST[7],
                CONST[0], CONST[1], CONST[2], CONST[3],
                k0 ^ CONST[0], k1 ^ CONST[1], k2 ^ CONST[2], k3 ^ CONST[3],
                k0 ^ CONST[4], k1 ^ CONST[5], k2 ^ CONST[6], k3 ^ CONST[7]
            };

            stateUpdate128(state, k0, k1, k2, k3);
            stateUpdate128(state, nonce0, nonce1, nonce2, nonce3);
            stateUpdate128(state, k0, k1, k2, k3);
            stateUpdate128(state, nonce0, nonce1, nonce2, nonce3);
            stateUpdate128(state, k0, k1, k2, k3);
            stateUpdate128(state, nonce0, nonce1, nonce2, nonce3);
            stateUpdate128(state, k0, k1, k2, k3);
            stateUpdate128(state, nonce0, nonce1, nonce2, nonce3);
            stateUpdate128(state, k0, k1, k2, k3);
            stateUpdate128(state, nonce0, nonce1, nonce2, nonce3);

            return state;

        }

        @Override
        public EncryptEngine startEncryption(byte[] key, byte[] iv) {
            return new AbstractAuthenticaterEngine(16) {

                private final int[] state = initialize(key, iv);
                private long adlen = 0, msglen = 0;

                @Override
                protected void ingestOneBlock(MemorySegment aad, long offset) {
                    stateUpdate128(state,
                            aad.get(BIG_ENDIAN_32_BIT, offset + 0),
                            aad.get(BIG_ENDIAN_32_BIT, offset + 4),
                            aad.get(BIG_ENDIAN_32_BIT, offset + 8),
                            aad.get(BIG_ENDIAN_32_BIT, offset + 12));
                    adlen += 128;
                }

                @Override
                protected void ingestLastBlock(MemorySegment aad, int length) {
                    if (length == 16) {
                        ingestOneBlock(aad, 0);
                    } else if (length > 0) {
                        aad.asSlice(length).fill((byte) 0);
                        stateUpdate128(state,
                                aad.get(BIG_ENDIAN_32_BIT, 0),
                                aad.get(BIG_ENDIAN_32_BIT, 4),
                                aad.get(BIG_ENDIAN_32_BIT, 8),
                                aad.get(BIG_ENDIAN_32_BIT, 12));
                        adlen |= (length << 3);
                    }
                }

                @Override
                protected void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
                    int p0 = plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 0),
                            p1 = plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 4),
                            p2 = plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 8),
                            p3 = plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 12);

                    ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 0, p0 ^ state[4] ^ state[16] ^ (state[8] & state[12]));
                    ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 4, p1 ^ state[5] ^ state[17] ^ (state[9] & state[13]));
                    ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 8, p2 ^ state[6] ^ state[18] ^ (state[10] & state[14]));
                    ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 12, p3 ^ state[7] ^ state[19] ^ (state[11] & state[15]));

                    stateUpdate128(state, p0, p1, p2, p3);

                    msglen += 128;

                }

                @Override
                protected int encryptLastBlock(MemorySegment buffer, int length, MemorySegment ciphertext) {
                    if (length == 16) {
                        encryptOneBlock(buffer, 0, ciphertext, 0);
                    } else if (length > 0) {
                        buffer.asSlice(length).fill((byte) 0);

                        int p0 = buffer.get(BIG_ENDIAN_32_BIT, 0),
                                p1 = buffer.get(BIG_ENDIAN_32_BIT, 4),
                                p2 = buffer.get(BIG_ENDIAN_32_BIT, 8),
                                p3 = buffer.get(BIG_ENDIAN_32_BIT, 12);

                        buffer.set(BIG_ENDIAN_32_BIT, 0, p0 ^ state[4] ^ state[16] ^ (state[8] & state[12]));
                        buffer.set(BIG_ENDIAN_32_BIT, 4, p1 ^ state[5] ^ state[17] ^ (state[9] & state[13]));
                        buffer.set(BIG_ENDIAN_32_BIT, 8, p2 ^ state[6] ^ state[18] ^ (state[10] & state[14]));
                        buffer.set(BIG_ENDIAN_32_BIT, 12, p3 ^ state[7] ^ state[19] ^ (state[11] & state[15]));

                        MemorySegment.copy(buffer, 0, ciphertext, 0, length);

                        stateUpdate128(state, p0, p1, p2, p3);

                        msglen |= (length << 3);
                    }
                    return length;
                }

                @Override
                protected void finalizeState() {
                    long adlenLE = Long.reverseBytes(adlen), msglenLE = Long.reverseBytes(msglen);

                    int tmp0 = state[12] ^ (int) (adlenLE >>> 32);
                    int tmp1 = state[13] ^ (int) adlenLE;
                    int tmp2 = state[14] ^ (int) (msglenLE >>> 32);
                    int tmp3 = state[15] ^ (int) msglenLE;

                    stateUpdate128(state, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate128(state, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate128(state, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate128(state, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate128(state, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate128(state, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate128(state, tmp0, tmp1, tmp2, tmp3);
                }

                @Override
                protected void generateTag(byte[] dest) {
                    store32BE(state[0] ^ state[4] ^ state[8] ^ state[12] ^ state[16], dest, 0);
                    store32BE(state[1] ^ state[5] ^ state[9] ^ state[13] ^ state[17], dest, 4);
                    store32BE(state[2] ^ state[6] ^ state[10] ^ state[14] ^ state[18], dest, 8);
                    store32BE(state[3] ^ state[7] ^ state[11] ^ state[15] ^ state[19], dest, 12);
                }

                @Override
                public AuthenticatedCipher getAlgorithm() {
                    return Aegis.AEGIS_128;
                }

            };
        }

        @Override
        public DecryptEngine startDecryption(byte[] key, byte[] iv) {
            return new AbstractVerifierEngine(16) {

                private final int[] state = initialize(key, iv);
                private long adlen = 0, msglen = 0;

                @Override
                protected void ingestOneBlock(MemorySegment aad, long offset) {
                    stateUpdate128(state,
                            aad.get(BIG_ENDIAN_32_BIT, offset + 0),
                            aad.get(BIG_ENDIAN_32_BIT, offset + 4),
                            aad.get(BIG_ENDIAN_32_BIT, offset + 8),
                            aad.get(BIG_ENDIAN_32_BIT, offset + 12));
                    adlen += 128;
                }

                @Override
                protected void ingestLastBlock(MemorySegment aad, int length) {
                    if (length == 16) {
                        ingestOneBlock(aad, 0);
                    } else if (length > 0) {
                        aad.asSlice(length).fill((byte) 0);
                        stateUpdate128(state,
                                aad.get(BIG_ENDIAN_32_BIT, 0),
                                aad.get(BIG_ENDIAN_32_BIT, 4),
                                aad.get(BIG_ENDIAN_32_BIT, 8),
                                aad.get(BIG_ENDIAN_32_BIT, 12));
                        adlen |= (length << 3);
                    }
                }

                @Override
                protected void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset) {
                    int p0 = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 0) ^ state[4] ^ state[16] ^ (state[8] & state[12]);
                    int p1 = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 4) ^ state[5] ^ state[17] ^ (state[9] & state[13]);
                    int p2 = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 8) ^ state[6] ^ state[18] ^ (state[10] & state[14]);
                    int p3 = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 12) ^ state[7] ^ state[19] ^ (state[11] & state[15]);

                    plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 0, p0);
                    plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 4, p1);
                    plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 8, p2);
                    plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 12, p3);

                    stateUpdate128(state, p0, p1, p2, p3);

                    msglen += 128;

                }

                @Override
                protected int decryptLastBlock(MemorySegment buffer, int length, MemorySegment plaintext) {
                    if (length == 16) {
                        decryptOneBlock(buffer, 0, plaintext, 0);
                    } else if (length > 0) {

                        buffer.set(BIG_ENDIAN_32_BIT, 0, buffer.get(BIG_ENDIAN_32_BIT, 0) ^ state[4] ^ state[16] ^ (state[8] & state[12]));
                        buffer.set(BIG_ENDIAN_32_BIT, 4, buffer.get(BIG_ENDIAN_32_BIT, 4) ^ state[5] ^ state[17] ^ (state[9] & state[13]));
                        buffer.set(BIG_ENDIAN_32_BIT, 8, buffer.get(BIG_ENDIAN_32_BIT, 8) ^ state[6] ^ state[18] ^ (state[10] & state[14]));
                        buffer.set(BIG_ENDIAN_32_BIT, 12, buffer.get(BIG_ENDIAN_32_BIT, 12) ^ state[7] ^ state[19] ^ (state[11] & state[15]));

                        MemorySegment.copy(buffer, 0, plaintext, 0, length);

                        buffer.asSlice(length).fill((byte) 0);

                        stateUpdate128(state,
                                buffer.get(BIG_ENDIAN_32_BIT, 0),
                                buffer.get(BIG_ENDIAN_32_BIT, 4),
                                buffer.get(BIG_ENDIAN_32_BIT, 8),
                                buffer.get(BIG_ENDIAN_32_BIT, 12)
                        );

                        msglen |= (length << 3);
                    }
                    return length;
                }

                @Override
                protected void finalizeState() {
                    long adlenLE = Long.reverseBytes(adlen), msglenLE = Long.reverseBytes(msglen);

                    int tmp0 = state[12] ^ (int) (adlenLE >>> 32);
                    int tmp1 = state[13] ^ (int) adlenLE;
                    int tmp2 = state[14] ^ (int) (msglenLE >>> 32);
                    int tmp3 = state[15] ^ (int) msglenLE;

                    stateUpdate128(state, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate128(state, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate128(state, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate128(state, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate128(state, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate128(state, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate128(state, tmp0, tmp1, tmp2, tmp3);
                }

                @Override
                protected void generateTag(byte[] dest) {
                    store32BE(state[0] ^ state[4] ^ state[8] ^ state[12] ^ state[16], dest, 0);
                    store32BE(state[1] ^ state[5] ^ state[9] ^ state[13] ^ state[17], dest, 4);
                    store32BE(state[2] ^ state[6] ^ state[10] ^ state[14] ^ state[18], dest, 8);
                    store32BE(state[3] ^ state[7] ^ state[11] ^ state[15] ^ state[19], dest, 12);
                }

                @Override
                public AuthenticatedCipher getAlgorithm() {
                    return Aegis.AEGIS_128;
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

    }, @Tested
    AEGIS_256 {

        private static int[] initialize(byte[] key, byte[] iv) {
            if (key.length < 32) {
                throw new IllegalArgumentException("AEGIS-256 requires a key of 32 bytes - passed " + key.length + " bytes");
            }
            if (iv.length < 32) {
                throw new IllegalArgumentException("AEGIS-256 requires an IV of 32 bytes - passed " + iv.length + " bytes");
            }

            int k0 = load32BE(key, 0), k1 = load32BE(key, 4), k2 = load32BE(key, 8), k3 = load32BE(key, 12);
            int k4 = load32BE(key, 16), k5 = load32BE(key, 20), k6 = load32BE(key, 24), k7 = load32BE(key, 28);

            int nonce0 = k0 ^ load32BE(iv, 0), nonce1 = k1 ^ load32BE(iv, 4),
                    nonce2 = k2 ^ load32BE(iv, 8), nonce3 = k3 ^ load32BE(iv, 12);
            int nonce4 = k5 ^ load32BE(iv, 16), nonce5 = k5 ^ load32BE(iv, 20),
                    nonce6 = k6 ^ load32BE(iv, 24), nonce7 = k7 ^ load32BE(iv, 28);

            int[] state = {
                nonce0, nonce1, nonce2, nonce3,
                nonce4, nonce5, nonce6, nonce7,
                CONST[4], CONST[5], CONST[6], CONST[7],
                CONST[0], CONST[1], CONST[2], CONST[3],
                k0 ^ CONST[0], k1 ^ CONST[1], k2 ^ CONST[2], k3 ^ CONST[3],
                k4 ^ CONST[4], k5 ^ CONST[5], k6 ^ CONST[6], k7 ^ CONST[7]
            };

            stateUpdate256(state, k0, k1, k2, k3);
            stateUpdate256(state, k4, k5, k6, k7);
            stateUpdate256(state, nonce0, nonce1, nonce2, nonce3);
            stateUpdate256(state, nonce4, nonce5, nonce6, nonce7);
            stateUpdate256(state, k0, k1, k2, k3);
            stateUpdate256(state, k4, k5, k6, k7);
            stateUpdate256(state, nonce0, nonce1, nonce2, nonce3);
            stateUpdate256(state, nonce4, nonce5, nonce6, nonce7);
            stateUpdate256(state, k0, k1, k2, k3);
            stateUpdate256(state, k4, k5, k6, k7);
            stateUpdate256(state, nonce0, nonce1, nonce2, nonce3);
            stateUpdate256(state, nonce4, nonce5, nonce6, nonce7);
            stateUpdate256(state, k0, k1, k2, k3);
            stateUpdate256(state, k4, k5, k6, k7);
            stateUpdate256(state, nonce0, nonce1, nonce2, nonce3);
            stateUpdate256(state, nonce4, nonce5, nonce6, nonce7);

            return state;

        }

        @Override
        public EncryptEngine startEncryption(byte[] key, byte[] iv) {
            return new AbstractAuthenticaterEngine(16) {

                private final int[] state = initialize(key, iv);
                private long adlen = 0, msglen = 0;

                @Override
                protected void ingestOneBlock(MemorySegment aad, long offset) {
                    stateUpdate256(state,
                            aad.get(BIG_ENDIAN_32_BIT, offset + 0),
                            aad.get(BIG_ENDIAN_32_BIT, offset + 4),
                            aad.get(BIG_ENDIAN_32_BIT, offset + 8),
                            aad.get(BIG_ENDIAN_32_BIT, offset + 12));
                    adlen += 128;
                }

                @Override
                protected void ingestLastBlock(MemorySegment aad, int length) {
                    if (length == 16) {
                        ingestOneBlock(aad, 0);
                    } else if (length > 0) {
                        aad.asSlice(length).fill((byte) 0);
                        stateUpdate256(state,
                                aad.get(BIG_ENDIAN_32_BIT, 0),
                                aad.get(BIG_ENDIAN_32_BIT, 4),
                                aad.get(BIG_ENDIAN_32_BIT, 8),
                                aad.get(BIG_ENDIAN_32_BIT, 12));
                        adlen |= (length << 3);
                    }
                }

                @Override
                protected void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
                    int p0 = plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 0),
                            p1 = plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 4),
                            p2 = plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 8),
                            p3 = plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 12);

                    ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 0, p0 ^ state[4] ^ state[16] ^ state[20] ^ (state[8] & state[12]));
                    ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 4, p1 ^ state[5] ^ state[17] ^ state[21] ^ (state[9] & state[13]));
                    ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 8, p2 ^ state[6] ^ state[18] ^ state[22] ^ (state[10] & state[14]));
                    ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 12, p3 ^ state[7] ^ state[19] ^ state[23] ^ (state[11] & state[15]));

                    stateUpdate256(state, p0, p1, p2, p3);

                    msglen += 128;
                }

                @Override
                protected int encryptLastBlock(MemorySegment buffer, int length, MemorySegment ciphertext) {
                    if (length == 16) {
                        encryptOneBlock(buffer, 0, ciphertext, 0);
                    } else if (length > 0) {
                        buffer.asSlice(length).fill((byte) 0);

                        int p0 = buffer.get(BIG_ENDIAN_32_BIT, 0),
                                p1 = buffer.get(BIG_ENDIAN_32_BIT, 4),
                                p2 = buffer.get(BIG_ENDIAN_32_BIT, 8),
                                p3 = buffer.get(BIG_ENDIAN_32_BIT, 12);

                        buffer.set(BIG_ENDIAN_32_BIT, 0, p0 ^ state[4] ^ state[16] ^ state[20] ^ (state[8] & state[12]));
                        buffer.set(BIG_ENDIAN_32_BIT, 4, p1 ^ state[5] ^ state[17] ^ state[21] ^ (state[9] & state[13]));
                        buffer.set(BIG_ENDIAN_32_BIT, 8, p2 ^ state[6] ^ state[18] ^ state[22] ^ (state[10] & state[14]));
                        buffer.set(BIG_ENDIAN_32_BIT, 12, p3 ^ state[7] ^ state[19] ^ state[23] ^ (state[11] & state[15]));

                        MemorySegment.copy(buffer, 0, ciphertext, 0, length);

                        stateUpdate256(state, p0, p1, p2, p3);

                        msglen |= (length << 3);
                    }
                    return length;
                }

                @Override
                protected void finalizeState() {
                    long adlenLE = Long.reverseBytes(adlen), msglenLE = Long.reverseBytes(msglen);

                    int tmp0 = state[12] ^ (int) (adlenLE >>> 32);
                    int tmp1 = state[13] ^ (int) adlenLE;
                    int tmp2 = state[14] ^ (int) (msglenLE >>> 32);
                    int tmp3 = state[15] ^ (int) msglenLE;

                    stateUpdate256(state, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate256(state, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate256(state, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate256(state, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate256(state, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate256(state, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate256(state, tmp0, tmp1, tmp2, tmp3);

                }

                @Override
                protected void generateTag(byte[] dest) {
                    store32BE(state[0] ^ state[4] ^ state[8] ^ state[12] ^ state[16] ^ state[20], dest, 0);
                    store32BE(state[1] ^ state[5] ^ state[9] ^ state[13] ^ state[17] ^ state[21], dest, 4);
                    store32BE(state[2] ^ state[6] ^ state[10] ^ state[14] ^ state[18] ^ state[22], dest, 8);
                    store32BE(state[3] ^ state[7] ^ state[11] ^ state[15] ^ state[19] ^ state[23], dest, 12);
                }

                @Override
                public AuthenticatedCipher getAlgorithm() {
                    return Aegis.AEGIS_256;
                }

            };
        }

        @Override
        public DecryptEngine startDecryption(byte[] key, byte[] iv) {
            return new AbstractVerifierEngine(16) {

                private final int[] state = initialize(key, iv);
                private long adlen = 0, msglen = 0;

                @Override
                protected void ingestOneBlock(MemorySegment aad, long offset) {
                    stateUpdate256(state,
                            aad.get(BIG_ENDIAN_32_BIT, offset + 0),
                            aad.get(BIG_ENDIAN_32_BIT, offset + 4),
                            aad.get(BIG_ENDIAN_32_BIT, offset + 8),
                            aad.get(BIG_ENDIAN_32_BIT, offset + 12));
                    adlen += 128;
                }

                @Override
                protected void ingestLastBlock(MemorySegment aad, int length) {
                    if (length == 16) {
                        ingestOneBlock(aad, 0);
                    } else if (length > 0) {
                        aad.asSlice(length).fill((byte) 0);
                        stateUpdate256(state,
                                aad.get(BIG_ENDIAN_32_BIT, 0),
                                aad.get(BIG_ENDIAN_32_BIT, 4),
                                aad.get(BIG_ENDIAN_32_BIT, 8),
                                aad.get(BIG_ENDIAN_32_BIT, 12));
                        adlen |= (length << 3);
                    }
                }

                @Override
                protected void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset) {
                    int p0 = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 0) ^ state[4] ^ state[16] ^ state[20] ^ (state[8] & state[12]),
                            p1 = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 4) ^ state[5] ^ state[17] ^ state[21] ^ (state[9] & state[13]),
                            p2 = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 8) ^ state[6] ^ state[18] ^ state[22] ^ (state[10] & state[14]),
                            p3 = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 12) ^ state[7] ^ state[19] ^ state[23] ^ (state[11] & state[15]);

                    plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 0, p0);
                    plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 4, p1);
                    plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 8, p2);
                    plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 12, p3);

                    stateUpdate256(state, p0, p1, p2, p3);

                    msglen += 128;
                }

                @Override
                protected int decryptLastBlock(MemorySegment buffer, int length, MemorySegment plaintext) {
                    if (length == 16) {
                        decryptOneBlock(buffer, 0, plaintext, 0);
                    } else if (length > 0) {

                        buffer.set(BIG_ENDIAN_32_BIT, 0, buffer.get(BIG_ENDIAN_32_BIT, 0) ^ state[4] ^ state[16] ^ state[20] ^ (state[8] & state[12]));
                        buffer.set(BIG_ENDIAN_32_BIT, 4, buffer.get(BIG_ENDIAN_32_BIT, 4) ^ state[5] ^ state[17] ^ state[21] ^ (state[9] & state[13]));
                        buffer.set(BIG_ENDIAN_32_BIT, 8, buffer.get(BIG_ENDIAN_32_BIT, 8) ^ state[6] ^ state[18] ^ state[22] ^ (state[10] & state[14]));
                        buffer.set(BIG_ENDIAN_32_BIT, 12, buffer.get(BIG_ENDIAN_32_BIT, 12) ^ state[7] ^ state[19] ^ state[23] ^ (state[11] & state[15]));

                        MemorySegment.copy(buffer, 0, plaintext, 0, length);

                        buffer.asSlice(length).fill((byte) 0);

                        stateUpdate256(state,
                                buffer.get(BIG_ENDIAN_32_BIT, 0),
                                buffer.get(BIG_ENDIAN_32_BIT, 4),
                                buffer.get(BIG_ENDIAN_32_BIT, 8),
                                buffer.get(BIG_ENDIAN_32_BIT, 12)
                        );

                        msglen |= (length << 3);
                    }
                    return length;
                }

                @Override
                protected void finalizeState() {
                    long adlenLE = Long.reverseBytes(adlen), msglenLE = Long.reverseBytes(msglen);

                    int tmp0 = state[12] ^ (int) (adlenLE >>> 32);
                    int tmp1 = state[13] ^ (int) adlenLE;
                    int tmp2 = state[14] ^ (int) (msglenLE >>> 32);
                    int tmp3 = state[15] ^ (int) msglenLE;

                    stateUpdate256(state, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate256(state, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate256(state, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate256(state, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate256(state, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate256(state, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate256(state, tmp0, tmp1, tmp2, tmp3);

                }

                @Override
                protected void generateTag(byte[] dest) {
                    store32BE(state[0] ^ state[4] ^ state[8] ^ state[12] ^ state[16] ^ state[20], dest, 0);
                    store32BE(state[1] ^ state[5] ^ state[9] ^ state[13] ^ state[17] ^ state[21], dest, 4);
                    store32BE(state[2] ^ state[6] ^ state[10] ^ state[14] ^ state[18] ^ state[22], dest, 8);
                    store32BE(state[3] ^ state[7] ^ state[11] ^ state[15] ^ state[19] ^ state[23], dest, 12);
                }

                @Override
                public AuthenticatedCipher getAlgorithm() {
                    return Aegis.AEGIS_256;
                }

            };
        }

        @Override
        public int keyLength() {
            return 32;
        }

        @Override
        public int ivLength() {
            return 32;
        }

    }, @Tested
    AEGIS_128L {

        private static int[] initialize(byte[] key, byte[] iv) {
            if (key.length < 16) {
                throw new IllegalArgumentException("AEGIS-128 requires a key of 16 bytes - passed " + key.length + " bytes");
            }
            if (iv.length < 16) {
                throw new IllegalArgumentException("AEGIS-128 requires an IV of 16 bytes - passed " + iv.length + " bytes");
            }

            int k0 = load32BE(key, 0), k1 = load32BE(key, 4), k2 = load32BE(key, 8), k3 = load32BE(key, 12);
            int iv0 = load32BE(iv, 0), iv1 = load32BE(iv, 4), iv2 = load32BE(iv, 8), iv3 = load32BE(iv, 12);

            int[] state = {
                k0 ^ iv0, k1 ^ iv1, k2 ^ iv2, k3 ^ iv3,
                CONST[4], CONST[5], CONST[6], CONST[7],
                CONST[0], CONST[1], CONST[2], CONST[3],
                CONST[4], CONST[5], CONST[6], CONST[7],
                k0 ^ iv0, k1 ^ iv1, k2 ^ iv2, k3 ^ iv3,
                k0 ^ CONST[0], k1 ^ CONST[1], k2 ^ CONST[2], k3 ^ CONST[3],
                k0 ^ CONST[4], k1 ^ CONST[5], k2 ^ CONST[6], k3 ^ CONST[7],
                k0 ^ CONST[0], k1 ^ CONST[1], k2 ^ CONST[2], k3 ^ CONST[3]
            };

            stateUpdate128L(state, iv0, iv1, iv2, iv3, k0, k1, k2, k3);
            stateUpdate128L(state, iv0, iv1, iv2, iv3, k0, k1, k2, k3);
            stateUpdate128L(state, iv0, iv1, iv2, iv3, k0, k1, k2, k3);
            stateUpdate128L(state, iv0, iv1, iv2, iv3, k0, k1, k2, k3);
            stateUpdate128L(state, iv0, iv1, iv2, iv3, k0, k1, k2, k3);
            stateUpdate128L(state, iv0, iv1, iv2, iv3, k0, k1, k2, k3);
            stateUpdate128L(state, iv0, iv1, iv2, iv3, k0, k1, k2, k3);
            stateUpdate128L(state, iv0, iv1, iv2, iv3, k0, k1, k2, k3);
            stateUpdate128L(state, iv0, iv1, iv2, iv3, k0, k1, k2, k3);
            stateUpdate128L(state, iv0, iv1, iv2, iv3, k0, k1, k2, k3);

            return state;

        }

        @Override
        public EncryptEngine startEncryption(byte[] key, byte[] iv) {
            return new AbstractAuthenticaterEngine(32) {

                private final int[] state = initialize(key, iv);
                private long adlen = 0, msglen = 0;

                @Override
                protected void ingestOneBlock(MemorySegment aad, long offset) {
                    stateUpdate128L(state,
                            aad.get(BIG_ENDIAN_32_BIT, offset + 0),
                            aad.get(BIG_ENDIAN_32_BIT, offset + 4),
                            aad.get(BIG_ENDIAN_32_BIT, offset + 8),
                            aad.get(BIG_ENDIAN_32_BIT, offset + 12),
                            aad.get(BIG_ENDIAN_32_BIT, offset + 16),
                            aad.get(BIG_ENDIAN_32_BIT, offset + 20),
                            aad.get(BIG_ENDIAN_32_BIT, offset + 24),
                            aad.get(BIG_ENDIAN_32_BIT, offset + 28)
                    );
                    adlen += 256;
                }

                @Override
                protected void ingestLastBlock(MemorySegment aad, int length) {
                    if (length == 32) {
                        ingestOneBlock(aad, 0);
                    } else if (length > 0) {
                        aad.asSlice(length).fill((byte) 0);

                        stateUpdate128L(state,
                                aad.get(BIG_ENDIAN_32_BIT, 0),
                                aad.get(BIG_ENDIAN_32_BIT, 4),
                                aad.get(BIG_ENDIAN_32_BIT, 8),
                                aad.get(BIG_ENDIAN_32_BIT, 12),
                                aad.get(BIG_ENDIAN_32_BIT, 16),
                                aad.get(BIG_ENDIAN_32_BIT, 20),
                                aad.get(BIG_ENDIAN_32_BIT, 24),
                                aad.get(BIG_ENDIAN_32_BIT, 28)
                        );

                        adlen |= (length << 3);
                    }
                }

                @Override
                protected void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
                    int p0 = plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 0);
                    int p1 = plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 4);
                    int p2 = plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 8);
                    int p3 = plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 12);
                    int p4 = plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 16);
                    int p5 = plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 20);
                    int p6 = plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 24);
                    int p7 = plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 28);

                    ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 0, p0 ^ state[4] ^ state[24] ^ (state[8] & state[12]));
                    ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 4, p1 ^ state[5] ^ state[25] ^ (state[9] & state[13]));
                    ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 8, p2 ^ state[6] ^ state[26] ^ (state[10] & state[14]));
                    ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 12, p3 ^ state[7] ^ state[27] ^ (state[11] & state[15]));

                    ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 16, p4 ^ state[8] ^ state[20] ^ (state[24] & state[28]));
                    ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 20, p5 ^ state[9] ^ state[21] ^ (state[25] & state[29]));
                    ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 24, p6 ^ state[10] ^ state[22] ^ (state[26] & state[30]));
                    ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 28, p7 ^ state[11] ^ state[23] ^ (state[27] & state[31]));

                    stateUpdate128L(state, p0, p1, p2, p3, p4, p5, p6, p7);

                    msglen += 256;

                }

                @Override
                protected int encryptLastBlock(MemorySegment buffer, int length, MemorySegment ciphertext) {
                    if (length == 32) {
                        encryptOneBlock(buffer, 0, ciphertext, 0);
                    } else if (length > 0) {
                        buffer.asSlice(length).fill((byte) 0);

                        int p0 = buffer.get(BIG_ENDIAN_32_BIT, 0);
                        int p1 = buffer.get(BIG_ENDIAN_32_BIT, 4);
                        int p2 = buffer.get(BIG_ENDIAN_32_BIT, 8);
                        int p3 = buffer.get(BIG_ENDIAN_32_BIT, 12);
                        int p4 = buffer.get(BIG_ENDIAN_32_BIT, 16);
                        int p5 = buffer.get(BIG_ENDIAN_32_BIT, 20);
                        int p6 = buffer.get(BIG_ENDIAN_32_BIT, 24);
                        int p7 = buffer.get(BIG_ENDIAN_32_BIT, 28);

                        buffer.set(BIG_ENDIAN_32_BIT, 0, p0 ^ state[4] ^ state[24] ^ (state[8] & state[12]));
                        buffer.set(BIG_ENDIAN_32_BIT, 4, p1 ^ state[5] ^ state[25] ^ (state[9] & state[13]));
                        buffer.set(BIG_ENDIAN_32_BIT, 8, p2 ^ state[6] ^ state[26] ^ (state[10] & state[14]));
                        buffer.set(BIG_ENDIAN_32_BIT, 12, p3 ^ state[7] ^ state[27] ^ (state[11] & state[15]));

                        buffer.set(BIG_ENDIAN_32_BIT, 16, p4 ^ state[8] ^ state[20] ^ (state[24] & state[28]));
                        buffer.set(BIG_ENDIAN_32_BIT, 20, p5 ^ state[9] ^ state[21] ^ (state[25] & state[29]));
                        buffer.set(BIG_ENDIAN_32_BIT, 24, p6 ^ state[10] ^ state[22] ^ (state[26] & state[30]));
                        buffer.set(BIG_ENDIAN_32_BIT, 28, p7 ^ state[11] ^ state[23] ^ (state[27] & state[31]));

                        MemorySegment.copy(buffer, 0, ciphertext, 0, length);

                        stateUpdate128L(state, p0, p1, p2, p3, p4, p5, p6, p7);

                        msglen |= length << 3;
                    }
                    return length;
                }

                @Override
                protected void finalizeState() {
                    long adlenLE = Long.reverseBytes(adlen), msglenLE = Long.reverseBytes(msglen);

                    int tmp0 = state[8] ^ (int) (adlenLE >>> 32);
                    int tmp1 = state[9] ^ (int) adlenLE;
                    int tmp2 = state[10] ^ (int) (msglenLE >>> 32);
                    int tmp3 = state[11] ^ (int) msglenLE;

                    stateUpdate128L(state, tmp0, tmp1, tmp2, tmp3, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate128L(state, tmp0, tmp1, tmp2, tmp3, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate128L(state, tmp0, tmp1, tmp2, tmp3, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate128L(state, tmp0, tmp1, tmp2, tmp3, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate128L(state, tmp0, tmp1, tmp2, tmp3, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate128L(state, tmp0, tmp1, tmp2, tmp3, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate128L(state, tmp0, tmp1, tmp2, tmp3, tmp0, tmp1, tmp2, tmp3);
                }

                @Override
                protected void generateTag(byte[] dest) {
                    store32BE(state[0] ^ state[4] ^ state[8] ^ state[12] ^ state[16] ^ state[20] ^ state[24], dest, 0);
                    store32BE(state[1] ^ state[5] ^ state[9] ^ state[13] ^ state[17] ^ state[21] ^ state[25], dest, 4);
                    store32BE(state[2] ^ state[6] ^ state[10] ^ state[14] ^ state[18] ^ state[22] ^ state[26], dest, 8);
                    store32BE(state[3] ^ state[7] ^ state[11] ^ state[15] ^ state[19] ^ state[23] ^ state[27], dest, 12);
                }

                @Override
                public AuthenticatedCipher getAlgorithm() {
                    return Aegis.AEGIS_128L;
                }
            };
        }

        @Override
        public DecryptEngine startDecryption(byte[] key, byte[] iv) {
            return new AbstractVerifierEngine(32) {

                private final int[] state = initialize(key, iv);
                private long adlen = 0, msglen = 0;

                @Override
                protected void ingestOneBlock(MemorySegment aad, long offset) {
                    stateUpdate128L(state,
                            aad.get(BIG_ENDIAN_32_BIT, offset + 0),
                            aad.get(BIG_ENDIAN_32_BIT, offset + 4),
                            aad.get(BIG_ENDIAN_32_BIT, offset + 8),
                            aad.get(BIG_ENDIAN_32_BIT, offset + 12),
                            aad.get(BIG_ENDIAN_32_BIT, offset + 16),
                            aad.get(BIG_ENDIAN_32_BIT, offset + 20),
                            aad.get(BIG_ENDIAN_32_BIT, offset + 24),
                            aad.get(BIG_ENDIAN_32_BIT, offset + 28)
                    );
                    adlen += 256;
                }

                @Override
                protected void ingestLastBlock(MemorySegment aad, int length) {
                    if (length == 32) {
                        ingestOneBlock(aad, 0);
                    } else if (length > 0) {
                        aad.asSlice(length).fill((byte) 0);

                        stateUpdate128L(state,
                                aad.get(BIG_ENDIAN_32_BIT, 0),
                                aad.get(BIG_ENDIAN_32_BIT, 4),
                                aad.get(BIG_ENDIAN_32_BIT, 8),
                                aad.get(BIG_ENDIAN_32_BIT, 12),
                                aad.get(BIG_ENDIAN_32_BIT, 16),
                                aad.get(BIG_ENDIAN_32_BIT, 20),
                                aad.get(BIG_ENDIAN_32_BIT, 24),
                                aad.get(BIG_ENDIAN_32_BIT, 28)
                        );

                        adlen |= (length << 3);
                    }
                }

                @Override
                protected void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset) {
                    int p0 = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 0) ^ state[4] ^ state[24] ^ (state[8] & state[12]);
                    int p1 = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 4) ^ state[5] ^ state[25] ^ (state[9] & state[13]);
                    int p2 = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 8) ^ state[6] ^ state[26] ^ (state[10] & state[14]);
                    int p3 = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 12) ^ state[7] ^ state[27] ^ (state[11] & state[15]);

                    int p4 = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 16) ^ state[8] ^ state[20] ^ (state[24] & state[28]);
                    int p5 = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 20) ^ state[9] ^ state[21] ^ (state[25] & state[29]);
                    int p6 = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 24) ^ state[10] ^ state[22] ^ (state[26] & state[30]);
                    int p7 = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 28) ^ state[11] ^ state[23] ^ (state[27] & state[31]);

                    plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 0, p0);
                    plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 4, p1);
                    plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 8, p2);
                    plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 12, p3);
                    plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 16, p4);
                    plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 20, p5);
                    plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 24, p6);
                    plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 28, p7);

                    stateUpdate128L(state, p0, p1, p2, p3, p4, p5, p6, p7);

                    msglen += 256;

                }

                @Override
                protected int decryptLastBlock(MemorySegment buffer, int length, MemorySegment ciphertext) {
                    if (length == 32) {
                        decryptOneBlock(buffer, 0, ciphertext, 0);
                    } else if (length > 0) {

                        int p0 = buffer.get(BIG_ENDIAN_32_BIT, 0) ^ state[4] ^ state[24] ^ (state[8] & state[12]);
                        int p1 = buffer.get(BIG_ENDIAN_32_BIT, 4) ^ state[5] ^ state[25] ^ (state[9] & state[13]);
                        int p2 = buffer.get(BIG_ENDIAN_32_BIT, 8) ^ state[6] ^ state[26] ^ (state[10] & state[14]);
                        int p3 = buffer.get(BIG_ENDIAN_32_BIT, 12) ^ state[7] ^ state[27] ^ (state[11] & state[15]);

                        int p4 = buffer.get(BIG_ENDIAN_32_BIT, 16) ^ state[8] ^ state[20] ^ (state[24] & state[28]);
                        int p5 = buffer.get(BIG_ENDIAN_32_BIT, 20) ^ state[9] ^ state[21] ^ (state[25] & state[29]);
                        int p6 = buffer.get(BIG_ENDIAN_32_BIT, 24) ^ state[10] ^ state[22] ^ (state[26] & state[30]);
                        int p7 = buffer.get(BIG_ENDIAN_32_BIT, 28) ^ state[11] ^ state[23] ^ (state[27] & state[31]);

                        buffer.set(BIG_ENDIAN_32_BIT, 0, p0);
                        buffer.set(BIG_ENDIAN_32_BIT, 4, p1);
                        buffer.set(BIG_ENDIAN_32_BIT, 8, p2);
                        buffer.set(BIG_ENDIAN_32_BIT, 12, p3);
                        buffer.set(BIG_ENDIAN_32_BIT, 16, p4);
                        buffer.set(BIG_ENDIAN_32_BIT, 20, p5);
                        buffer.set(BIG_ENDIAN_32_BIT, 24, p6);
                        buffer.set(BIG_ENDIAN_32_BIT, 28, p7);

                        buffer.asSlice(length).fill((byte) 0);

                        MemorySegment.copy(buffer, 0, ciphertext, 0, length);

                        stateUpdate128L(state,
                                buffer.get(BIG_ENDIAN_32_BIT, 0),
                                buffer.get(BIG_ENDIAN_32_BIT, 4),
                                buffer.get(BIG_ENDIAN_32_BIT, 8),
                                buffer.get(BIG_ENDIAN_32_BIT, 12),
                                buffer.get(BIG_ENDIAN_32_BIT, 16),
                                buffer.get(BIG_ENDIAN_32_BIT, 20),
                                buffer.get(BIG_ENDIAN_32_BIT, 24),
                                buffer.get(BIG_ENDIAN_32_BIT, 28)
                        );

                        msglen |= length << 3;
                    }
                    return length;
                }

                @Override
                protected void finalizeState() {
                    long adlenLE = Long.reverseBytes(adlen), msglenLE = Long.reverseBytes(msglen);

                    int tmp0 = state[8] ^ (int) (adlenLE >>> 32);
                    int tmp1 = state[9] ^ (int) adlenLE;
                    int tmp2 = state[10] ^ (int) (msglenLE >>> 32);
                    int tmp3 = state[11] ^ (int) msglenLE;

                    stateUpdate128L(state, tmp0, tmp1, tmp2, tmp3, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate128L(state, tmp0, tmp1, tmp2, tmp3, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate128L(state, tmp0, tmp1, tmp2, tmp3, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate128L(state, tmp0, tmp1, tmp2, tmp3, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate128L(state, tmp0, tmp1, tmp2, tmp3, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate128L(state, tmp0, tmp1, tmp2, tmp3, tmp0, tmp1, tmp2, tmp3);
                    stateUpdate128L(state, tmp0, tmp1, tmp2, tmp3, tmp0, tmp1, tmp2, tmp3);
                }

                @Override
                protected void generateTag(byte[] dest) {
                    store32BE(state[0] ^ state[4] ^ state[8] ^ state[12] ^ state[16] ^ state[20] ^ state[24], dest, 0);
                    store32BE(state[1] ^ state[5] ^ state[9] ^ state[13] ^ state[17] ^ state[21] ^ state[25], dest, 4);
                    store32BE(state[2] ^ state[6] ^ state[10] ^ state[14] ^ state[18] ^ state[22] ^ state[26], dest, 8);
                    store32BE(state[3] ^ state[7] ^ state[11] ^ state[15] ^ state[19] ^ state[23] ^ state[27], dest, 12);
                }

                @Override
                public AuthenticatedCipher getAlgorithm() {
                    return Aegis.AEGIS_128L;
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

    };

    private static final int[] CONST = {
        0x00010102, 0x0305080d, 0x15223759, 0x90e97962,
        0xdb3d1855, 0x6dc22ff1, 0x20113142, 0x73b528dd
    };

    private static void stateUpdate128(int[] state, int m0, int m1, int m2, int m3) {
        int temp0 = state[16], temp1 = state[17], temp2 = state[18], temp3 = state[19];
        aesRound(state, 12, state, 16, state, 16);
        aesRound(state, 8, state, 12, state, 12);
        aesRound(state, 4, state, 8, state, 8);
        aesRound(state, 0, state, 4, state, 4);
        aesRound(temp0, temp1, temp2, temp3, state, 0, state[0] ^ m0, state[1] ^ m1, state[2] ^ m2, state[3] ^ m3);
    }

    private static void stateUpdate256(int[] state, int m0, int m1, int m2, int m3) {
        int temp0 = state[20], temp1 = state[21], temp2 = state[22], temp3 = state[23];
        aesRound(state, 16, state, 20, state, 20);
        aesRound(state, 12, state, 16, state, 16);
        aesRound(state, 8, state, 12, state, 12);
        aesRound(state, 4, state, 8, state, 8);
        aesRound(state, 0, state, 4, state, 4);
        aesRound(temp0, temp1, temp2, temp3, state, 0, state[0] ^ m0, state[1] ^ m1, state[2] ^ m2, state[3] ^ m3);
    }

    private static void stateUpdate128L(int[] state, int m0, int m1, int m2, int m3, int m4, int m5, int m6, int m7) {
        int temp0 = state[28], temp1 = state[29], temp2 = state[30], temp3 = state[31];
        aesRound(state, 24, state, 28, state, 28);
        aesRound(state, 20, state, 24, state, 24);
        aesRound(state, 16, state, 20, state, 20);
        aesRound(state, 12, state, 16, state[16] ^ m4, state[17] ^ m5, state[18] ^ m6, state[19] ^ m7);
        aesRound(state, 8, state, 12, state, 12);
        aesRound(state, 4, state, 8, state, 8);
        aesRound(state, 0, state, 4, state, 4);
        aesRound(temp0, temp1, temp2, temp3, state, 0, state[0] ^ m0, state[1] ^ m1, state[2] ^ m2, state[3] ^ m3);
    }

    @Override
    public int tagLength() {
        return 16;
    }



}
