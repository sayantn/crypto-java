/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Enum.java to edit this template
 */
package org.asterisk.crypto.aead;

import org.asterisk.crypto.Tested;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import org.asterisk.crypto.helper.AbstractAuthenticaterEngine;
import org.asterisk.crypto.helper.AbstractVerifierEngine;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.interfaces.AuthenticatedCipher;

import static org.asterisk.crypto.helper.Tools.BIG_ENDIAN_64_BIT;
import static org.asterisk.crypto.helper.Tools.load32BE;
import static org.asterisk.crypto.helper.Tools.load64BE;
import static org.asterisk.crypto.helper.Tools.store64BE;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum Ascon implements AuthenticatedCipher {

    @Tested
    ASCON_128 {

        private static long[] initialize(long k0, long k1, byte[] iv) {
            long[] state = {
                0x80400c0600000000L,
                k0, k1,
                load64BE(iv, 0), load64BE(iv, 8)
            };

            ascon_p(state, 12);

            state[3] ^= k0;
            state[4] ^= k1;

            return state;

        }

        @Override
        public EncryptEngine startEncryption(byte[] key, byte[] iv) {
            return new AbstractAuthenticaterEngine(8) {

                private final long k0 = load64BE(key, 0), k1 = load64BE(key, 8);
                private final long[] state = initialize(k0, k1, iv);

                @Override
                protected void ingestOneBlock(MemorySegment aad, long offset) {
                    state[0] ^= aad.get(BIG_ENDIAN_64_BIT, offset);
                    ascon_p(state, 6);
                }

                @Override
                protected void ingestLastBlock(MemorySegment aad, int length) {
                    if (length == 8) {
                        state[0] ^= aad.get(BIG_ENDIAN_64_BIT, 0);
                        ascon_p(state, 6);
                        state[0] ^= 0x8000000000000000L;
                        ascon_p(state, 6);
                    } else if (length > 0) {
                        aad.set(ValueLayout.JAVA_BYTE, length, (byte) 0x80);
                        aad.asSlice(length + 1).fill((byte) 0);
                        state[0] ^= aad.get(BIG_ENDIAN_64_BIT, 0);
                        ascon_p(state, 6);
                    }
                    state[4] ^= 1;
                }

                @Override
                protected void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
                    state[0] ^= plaintext.get(BIG_ENDIAN_64_BIT, pOffset);
                    ciphertext.set(BIG_ENDIAN_64_BIT, cOffset, state[0]);
                    ascon_p(state, 6);
                }

                @Override
                protected int encryptLastBlock(MemorySegment buffer, int length, MemorySegment ciphertext) {
                    if (length == 8) {
                        state[0] ^= buffer.get(BIG_ENDIAN_64_BIT, 0);
                        ciphertext.set(BIG_ENDIAN_64_BIT, 0, state[0]);
                        ascon_p(state, 6);
                        state[0] ^= 0x8000000000000000L;
                    } else if (length > 0) {
                        buffer.set(ValueLayout.JAVA_BYTE, length, (byte) 0x80);
                        buffer.asSlice(length + 1).fill((byte) 0);

                        state[0] ^= buffer.get(BIG_ENDIAN_64_BIT, 0);
                        buffer.set(BIG_ENDIAN_64_BIT, 0, state[0]);
                        MemorySegment.copy(buffer, 0, ciphertext, 0, length);
                    } else {
                        state[0] ^= 0x8000000000000000L;
                    }
                    return length;
                }

                @Override
                protected void finalizeState() {
                    state[1] ^= k0;
                    state[2] ^= k1;
                    ascon_p(state, 12);
                }

                @Override
                protected void generateTag(byte[] dest) {
                    store64BE(state[3] ^ k0, dest, 0);
                    store64BE(state[4] ^ k1, dest, 8);
                }

                @Override
                public AuthenticatedCipher getAlgorithm() {
                    return Ascon.ASCON_128;
                }
            };
        }

        @Override
        public DecryptEngine startDecryption(byte[] key, byte[] iv) {
            return new AbstractVerifierEngine(8) {

                private final long k0 = load64BE(key, 0), k1 = load64BE(key, 8);
                private final long[] state = initialize(k0, k1, iv);

                @Override
                protected void ingestOneBlock(MemorySegment aad, long offset) {
                    state[0] ^= aad.get(BIG_ENDIAN_64_BIT, offset);
                    ascon_p(state, 6);
                }

                @Override
                protected void ingestLastBlock(MemorySegment aad, int length) {
                    if (length == 8) {
                        state[0] ^= aad.get(BIG_ENDIAN_64_BIT, 0);
                        ascon_p(state, 6);
                        state[0] ^= 0x8000000000000000L;
                        ascon_p(state, 6);
                    } else if (length > 0) {
                        aad.set(ValueLayout.JAVA_BYTE, length, (byte) 0x80);
                        aad.asSlice(length + 1).fill((byte) 0);
                        state[0] ^= aad.get(BIG_ENDIAN_64_BIT, 0);
                        ascon_p(state, 6);
                    }
                    state[4] ^= 1;
                }

                @Override
                protected void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset) {
                    long c = ciphertext.get(BIG_ENDIAN_64_BIT, cOffset);
                    plaintext.set(BIG_ENDIAN_64_BIT, pOffset, state[0] ^ c);
                    state[0] = c;
                    ascon_p(state, 6);
                }

                @Override
                protected int decryptLastBlock(MemorySegment buffer, int length, MemorySegment plaintext) {
                    if (length == 8) {
                        long c = buffer.get(BIG_ENDIAN_64_BIT, 0);
                        plaintext.set(BIG_ENDIAN_64_BIT, 0, state[0] ^ c);
                        state[0] = c;
                        ascon_p(state, 6);
                        state[0] ^= 0x8000000000000000L;
                    } else if (length > 0) {
                        long c = buffer.get(BIG_ENDIAN_64_BIT, 0);
                        buffer.set(BIG_ENDIAN_64_BIT, 0, state[0] ^ c);

                        buffer.set(ValueLayout.JAVA_BYTE, length, (byte) 0x80);
                        buffer.asSlice(length + 1).fill((byte) 0);

                        state[0] ^= buffer.get(BIG_ENDIAN_64_BIT, 0);
                        MemorySegment.copy(buffer, 0, plaintext, 0, length);
                    } else {
                        state[0] ^= 0x8000000000000000L;
                    }
                    return length;
                }

                @Override
                protected void finalizeState() {
                    state[1] ^= k0;
                    state[2] ^= k1;
                    ascon_p(state, 12);
                }

                @Override
                protected void generateTag(byte[] dest) {
                    store64BE(state[3] ^ k0, dest, 0);
                    store64BE(state[4] ^ k1, dest, 8);
                }

                @Override
                public AuthenticatedCipher getAlgorithm() {
                    return Ascon.ASCON_128;
                }
            };
        }

        @Override
        public int keyLength() {
            return 16;
        }

    }, @Tested
    ASCON_128a {

        private static long[] initialize(long k0, long k1, byte[] iv) {
            long[] state = {
                0x80800c0800000000L,
                k0, k1,
                load64BE(iv, 0), load64BE(iv, 8)
            };

            ascon_p(state, 12);

            state[3] ^= k0;
            state[4] ^= k1;

            return state;

        }

        @Override
        public EncryptEngine startEncryption(byte[] key, byte[] iv) {
            return new AbstractAuthenticaterEngine(16) {

                private final long k0 = load64BE(key, 0), k1 = load64BE(key, 8);
                private final long[] state = initialize(k0, k1, iv);

                @Override
                protected void ingestOneBlock(MemorySegment aad, long offset) {
                    state[0] ^= aad.get(BIG_ENDIAN_64_BIT, offset);
                    state[1] ^= aad.get(BIG_ENDIAN_64_BIT, offset + 8);
                    ascon_p(state, 8);
                }

                @Override
                protected void ingestLastBlock(MemorySegment aad, int length) {
                    if (length == 16) {
                        state[0] ^= aad.get(BIG_ENDIAN_64_BIT, 0);
                        state[1] ^= aad.get(BIG_ENDIAN_64_BIT, 8);
                        ascon_p(state, 8);
                        state[0] ^= 0x8000000000000000L;
                        ascon_p(state, 8);
                    } else if (length > 0) {
                        aad.set(ValueLayout.JAVA_BYTE, length, (byte) 0x80);
                        aad.asSlice(length + 1).fill((byte) 0);
                        state[0] ^= aad.get(BIG_ENDIAN_64_BIT, 0);
                        state[1] ^= aad.get(BIG_ENDIAN_64_BIT, 8);
                        ascon_p(state, 8);
                    }
                    state[4] ^= 1;
                }

                @Override
                protected void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
                    state[0] ^= plaintext.get(BIG_ENDIAN_64_BIT, pOffset);
                    state[1] ^= plaintext.get(BIG_ENDIAN_64_BIT, pOffset + 8);
                    ciphertext.set(BIG_ENDIAN_64_BIT, cOffset, state[0]);
                    ciphertext.set(BIG_ENDIAN_64_BIT, cOffset + 8, state[1]);
                    ascon_p(state, 8);
                }

                @Override
                protected int encryptLastBlock(MemorySegment buffer, int length, MemorySegment ciphertext) {
                    if (length == 16) {
                        state[0] ^= buffer.get(BIG_ENDIAN_64_BIT, 0);
                        state[1] ^= buffer.get(BIG_ENDIAN_64_BIT, 8);
                        ciphertext.set(BIG_ENDIAN_64_BIT, 0, state[0]);
                        ciphertext.set(BIG_ENDIAN_64_BIT, 8, state[1]);
                        ascon_p(state, 8);
                        state[0] ^= 0x8000000000000000L;
                    } else if (length > 0) {
                        buffer.set(ValueLayout.JAVA_BYTE, length, (byte) 0x80);
                        buffer.asSlice(length + 1).fill((byte) 0);

                        state[0] ^= buffer.get(BIG_ENDIAN_64_BIT, 0);
                        state[1] ^= buffer.get(BIG_ENDIAN_64_BIT, 8);
                        buffer.set(BIG_ENDIAN_64_BIT, 0, state[0]);
                        buffer.set(BIG_ENDIAN_64_BIT, 8, state[1]);
                        MemorySegment.copy(buffer, 0, ciphertext, 0, length);
                    } else {
                        state[0] ^= 0x8000000000000000L;
                    }
                    return length;
                }

                @Override
                protected void finalizeState() {
                    state[2] ^= k0;
                    state[3] ^= k1;
                    ascon_p(state, 12);
                }

                @Override
                protected void generateTag(byte[] dest) {
                    store64BE(state[3] ^ k0, dest, 0);
                    store64BE(state[4] ^ k1, dest, 8);
                }

                @Override
                public AuthenticatedCipher getAlgorithm() {
                    return Ascon.ASCON_128a;
                }
            };
        }

        @Override
        public DecryptEngine startDecryption(byte[] key, byte[] iv) {
            return new AbstractVerifierEngine(16) {

                private final long k0 = load64BE(key, 0), k1 = load64BE(key, 8);
                private final long[] state = initialize(k0, k1, iv);

                @Override
                protected void ingestOneBlock(MemorySegment aad, long offset) {
                    state[0] ^= aad.get(BIG_ENDIAN_64_BIT, offset);
                    state[1] ^= aad.get(BIG_ENDIAN_64_BIT, offset + 8);
                    ascon_p(state, 8);
                }

                @Override
                protected void ingestLastBlock(MemorySegment aad, int length) {
                    if (length == 16) {
                        ingestOneBlock(aad, 0);
                        state[0] ^= 0x8000000000000000L;
                        ascon_p(state, 8);
                    } else if (length > 0) {
                        Tools.ozpad(aad, length);
                        state[0] ^= aad.get(BIG_ENDIAN_64_BIT, 0);
                        state[1] ^= aad.get(BIG_ENDIAN_64_BIT, 8);
                        ascon_p(state, 8);
                    }
                    state[4] ^= 1;
                }

                @Override
                protected void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset) {
                    long c = ciphertext.get(BIG_ENDIAN_64_BIT, cOffset);
                    plaintext.set(BIG_ENDIAN_64_BIT, pOffset, state[0] ^ c);
                    state[0] = c;
                    c = ciphertext.get(BIG_ENDIAN_64_BIT, cOffset + 8);
                    plaintext.set(BIG_ENDIAN_64_BIT, pOffset + 8, state[1] ^ c);
                    state[1] = c;
                    ascon_p(state, 8);
                }

                @Override
                protected int decryptLastBlock(MemorySegment buffer, int length, MemorySegment plaintext) {
                    if (length == 16) {
                        decryptOneBlock(buffer, 0, plaintext, 0);
                        state[0] ^= 0x8000000000000000L;
                    } else if (length > 0) {
                        long c = buffer.get(BIG_ENDIAN_64_BIT, 0);
                        buffer.set(BIG_ENDIAN_64_BIT, 0, state[0] ^ c);
                        c = buffer.get(BIG_ENDIAN_64_BIT, 8);
                        buffer.set(BIG_ENDIAN_64_BIT, 8, state[1] ^ c);

                        Tools.ozpad(buffer, length);

                        state[0] ^= buffer.get(BIG_ENDIAN_64_BIT, 0);
                        state[1] ^= buffer.get(BIG_ENDIAN_64_BIT, 8);
                        MemorySegment.copy(buffer, 0, plaintext, 0, length);
                    } else {
                        state[0] ^= 0x8000000000000000L;
                    }
                    return length;
                }

                @Override
                protected void finalizeState() {
                    state[2] ^= k0;
                    state[3] ^= k1;
                    ascon_p(state, 12);
                }

                @Override
                protected void generateTag(byte[] dest) {
                    store64BE(state[3] ^ k0, dest, 0);
                    store64BE(state[4] ^ k1, dest, 8);
                }

                @Override
                public AuthenticatedCipher getAlgorithm() {
                    return Ascon.ASCON_128a;
                }
            };
        }

        @Override
        public int keyLength() {
            return 16;
        }
    },
    @Tested
    ASCON_80pq {

        private static long[] initialize(long k0, long k1, long k2, byte[] iv) {
            long[] state = {
                0xa0400c0600000000L | k0,
                k1, k2,
                load64BE(iv, 0), load64BE(iv, 8)
            };

            ascon_p(state, 12);

            state[2] ^= k0;
            state[3] ^= k1;
            state[4] ^= k2;

            return state;
        }

        @Override
        public EncryptEngine startEncryption(byte[] key, byte[] iv) {
            return new AbstractAuthenticaterEngine(8) {

                private final long k0 = load32BE(key, 0) & 0xffffffffL, k1 = load64BE(key, 4), k2 = load64BE(key, 12);
                private final long[] state = initialize(k0, k1, k2, iv);

                @Override
                protected void ingestOneBlock(MemorySegment aad, long offset) {
                    state[0] ^= aad.get(BIG_ENDIAN_64_BIT, offset);
                    ascon_p(state, 6);
                }

                @Override
                protected void ingestLastBlock(MemorySegment aad, int length) {
                    if (length == 8) {
                        state[0] ^= aad.get(BIG_ENDIAN_64_BIT, 0);
                        ascon_p(state, 6);
                        state[0] ^= 0x8000000000000000L;
                        ascon_p(state, 6);
                    } else if (length > 0) {
                        aad.set(ValueLayout.JAVA_BYTE, length, (byte) 0x80);
                        aad.asSlice(length + 1).fill((byte) 0);
                        state[0] ^= aad.get(BIG_ENDIAN_64_BIT, 0);
                        ascon_p(state, 6);
                    }
                    state[4] ^= 1;
                }

                @Override
                protected void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
                    state[0] ^= plaintext.get(BIG_ENDIAN_64_BIT, pOffset);
                    ciphertext.set(BIG_ENDIAN_64_BIT, cOffset, state[0]);
                    ascon_p(state, 6);
                }

                @Override
                protected int encryptLastBlock(MemorySegment buffer, int length, MemorySegment ciphertext) {
                    if (length == 8) {
                        state[0] ^= buffer.get(BIG_ENDIAN_64_BIT, 0);
                        ciphertext.set(BIG_ENDIAN_64_BIT, 0, state[0]);
                        ascon_p(state, 6);
                        state[0] ^= 0x8000000000000000L;
                    } else if (length > 0) {
                        Tools.ozpad(buffer, length);

                        state[0] ^= buffer.get(BIG_ENDIAN_64_BIT, 0);
                        buffer.set(BIG_ENDIAN_64_BIT, 0, state[0]);
                        MemorySegment.copy(buffer, 0, ciphertext, 0, length);
                    } else {
                        state[0] ^= 0x8000000000000000L;
                    }
                    return length;
                }

                @Override
                protected void finalizeState() {
                    state[1] ^= (k0 << 32) | (k1 >>> 32);
                    state[2] ^= (k1 << 32) | (k2 >>> 32);
                    state[3] ^= k2 << 32;
                    ascon_p(state, 12);
                }

                @Override
                protected void generateTag(byte[] dest) {
                    store64BE(state[3] ^ k1, dest, 0);
                    store64BE(state[4] ^ k2, dest, 8);
                }

                @Override
                public AuthenticatedCipher getAlgorithm() {
                    return Ascon.ASCON_128;
                }
            };
        }

        @Override
        public DecryptEngine startDecryption(byte[] key, byte[] iv) {
            return new AbstractVerifierEngine(8) {

                private final long k0 = load32BE(key, 0) & 0xffffffffL, k1 = load64BE(key, 4), k2 = load64BE(key, 12);
                private final long[] state = initialize(k0, k1, k2, iv);

                @Override
                protected void ingestOneBlock(MemorySegment aad, long offset) {
                    state[0] ^= aad.get(BIG_ENDIAN_64_BIT, offset);
                    ascon_p(state, 6);
                }

                @Override
                protected void ingestLastBlock(MemorySegment aad, int length) {
                    if (length == 8) {
                        state[0] ^= aad.get(BIG_ENDIAN_64_BIT, 0);
                        ascon_p(state, 6);
                        state[0] ^= 0x8000000000000000L;
                        ascon_p(state, 6);
                    } else if (length > 0) {
                        aad.set(ValueLayout.JAVA_BYTE, length, (byte) 0x80);
                        aad.asSlice(length + 1).fill((byte) 0);
                        state[0] ^= aad.get(BIG_ENDIAN_64_BIT, 0);
                        ascon_p(state, 6);
                    }
                    state[4] ^= 1;
                }

                @Override
                protected void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset) {
                    long c = ciphertext.get(BIG_ENDIAN_64_BIT, cOffset);
                    plaintext.set(BIG_ENDIAN_64_BIT, pOffset, state[0] ^ c);
                    state[0] = c;
                    ascon_p(state, 6);
                }

                @Override
                protected int decryptLastBlock(MemorySegment buffer, int length, MemorySegment plaintext) {
                    if (length == 8) {
                        long c = buffer.get(BIG_ENDIAN_64_BIT, 0);
                        plaintext.set(BIG_ENDIAN_64_BIT, 0, state[0] ^ c);
                        state[0] = c;
                        ascon_p(state, 6);
                        state[0] ^= 0x8000000000000000L;
                    } else if (length > 0) {
                        long c = buffer.get(BIG_ENDIAN_64_BIT, 0);
                        buffer.set(BIG_ENDIAN_64_BIT, 0, state[0] ^ c);

                        buffer.set(ValueLayout.JAVA_BYTE, length, (byte) 0x80);
                        buffer.asSlice(length + 1).fill((byte) 0);

                        state[0] ^= buffer.get(BIG_ENDIAN_64_BIT, 0);
                        MemorySegment.copy(buffer, 0, plaintext, 0, length);
                    } else {
                        state[0] ^= 0x8000000000000000L;
                    }
                    return length;
                }

                @Override
                protected void finalizeState() {
                    state[1] ^= (k0 << 32) | (k1 >>> 32);
                    state[2] ^= (k1 << 32) | (k2 >>> 32);
                    state[3] ^= k2 << 32;
                    ascon_p(state, 12);
                }

                @Override
                protected void generateTag(byte[] dest) {
                    store64BE(state[3] ^ k1, dest, 0);
                    store64BE(state[4] ^ k2, dest, 8);
                }

                @Override
                public AuthenticatedCipher getAlgorithm() {
                    return Ascon.ASCON_128;
                }
            };
        }

        @Override
        public int keyLength() {
            return 20;
        }

    };

    private static final long[] RND_CONST = {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b};

    /**
     * an implementation of the permutation function of the <i>Ascon</i> cipher
     * from the CAESAR portfolio (in use case 1:Lightweight applications)
     * <p>
     * each round takes 23 cycles to compute
     *
     * @param state  the 320 bit state, represented as 5 big-endian 64-bit words
     * @param rounds
     *
     * @throws IllegalArgumentException if {@literal rounds < 0} or
     *                                  {@literal rounds > 12}
     */
    public static void ascon_p(long[] state, int rounds) {

        if (rounds < 0 || rounds > 12) {
            throw new IllegalArgumentException("Rounds: " + rounds);
        }

        long x0 = state[0], x1 = state[1], x2 = state[2], x3 = state[3], x4 = state[4];
        long t0, t1, t2, t3, t4;

        for (int r = 12 - rounds; r < 12; r++) {
            x2 ^= RND_CONST[r];

            x0 ^= x4;
            x4 ^= x3;
            x2 ^= x1;

            t0 = ~x0 & x1;
            t1 = ~x1 & x2;
            t2 = ~x2 & x3;
            t3 = ~x3 & x4;
            t4 = ~x4 & x0;

            x0 ^= t1;
            x1 ^= t2;
            x2 ^= t3;
            x3 ^= t4;
            x4 ^= t0;

            x1 ^= x0;
            x0 ^= x4;
            x3 ^= x2;
            x2 = ~x2;

            x0 = x0 ^ Long.rotateRight(x0, 19) ^ Long.rotateRight(x0, 28);
            x1 = x1 ^ Long.rotateRight(x1, 61) ^ Long.rotateRight(x1, 39);
            x2 = x2 ^ Long.rotateRight(x2, 1) ^ Long.rotateRight(x2, 6);
            x3 = x3 ^ Long.rotateRight(x3, 10) ^ Long.rotateRight(x3, 17);
            x4 = x4 ^ Long.rotateRight(x4, 7) ^ Long.rotateRight(x4, 41);

        }

        state[0] = x0;
        state[1] = x1;
        state[2] = x2;
        state[3] = x3;
        state[4] = x4;
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
