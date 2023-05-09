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
import org.asterisk.crypto.interfaces.AuthenticatedCipher;
import org.asterisk.crypto.lowlevel.KeccakP;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum Ketje implements AuthenticatedCipher {
    //0 6 12 18 24 3 9 10 16 22 1 7 13 19 20 4 5 11 17 23 2 8 14 15 21
    KETJE_MAJOR {

        private static final ValueLayout.OfLong LAYOUT = Tools.LITTLE_ENDIAN_64_BIT;

        @Override
        public EncryptEngine startEncryption(byte[] key, byte[] iv) {
            return new AbstractAuthenticaterEngine(32) {

                private final long[] state = new long[25];

                {
                    state[0] = (Tools.load64LE(key, 0) << 8) | 18;
                    state[6] = Tools.load64LE(key, 7);
                    state[12] = (Tools.load64LE(iv, 0) << 16) | 0x0100 | (key[15] & 0xff);
                    state[18] = Tools.load64LE(iv, 6);
                    state[24] = (iv[14] & 0xff) | ((iv[15] & 0xff) << 8) | 0x010000;

                    state[21] = 0x8000000000000000L;

                    KeccakP.keccak_p1600(state, 12);
                }

                @Override
                protected void ingestOneBlock(MemorySegment aad, long offset) {
                    state[0] ^= aad.get(LAYOUT, offset + 0);
                    state[6] ^= aad.get(LAYOUT, offset + 8);
                    state[12] ^= aad.get(LAYOUT, offset + 16);
                    state[18] ^= aad.get(LAYOUT, offset + 24);
                    state[24] ^= 0b1100;

                    KeccakP.keccak_p1600_oneround(state);
                }

                @Override
                protected void ingestLastBlock(MemorySegment aad, int length) {
                    if (length < 32) {
                        aad.set(ValueLayout.JAVA_BYTE, length, (byte) 0b110);
                        Tools.zeropad(aad, length + 1);
                        state[24] ^= 0b1000;
                    } else {
                        state[24] ^= 0b1110;
                    }
                    state[0] ^= aad.get(LAYOUT, 0);
                    state[6] ^= aad.get(LAYOUT, 8);
                    state[12] ^= aad.get(LAYOUT, 16);
                    state[18] ^= aad.get(LAYOUT, 24);

                    KeccakP.keccak_p1600_oneround(state);
                }

                @Override
                protected void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
                    state[0] ^= plaintext.get(LAYOUT, pOffset + 0);
                    state[6] ^= plaintext.get(LAYOUT, pOffset + 8);
                    state[12] ^= plaintext.get(LAYOUT, pOffset + 16);
                    state[18] ^= plaintext.get(LAYOUT, pOffset + 24);
                    state[24] ^= 0b1111;

                    ciphertext.set(LAYOUT, cOffset + 0, state[0]);
                    ciphertext.set(LAYOUT, cOffset + 8, state[6]);
                    ciphertext.set(LAYOUT, cOffset + 16, state[12]);
                    ciphertext.set(LAYOUT, cOffset + 24, state[18]);

                    KeccakP.keccak_p1600_oneround(state);
                }

                @Override
                protected int encryptLastBlock(MemorySegment buffer, int length, MemorySegment ciphertext) {
                    if (length < 32) {
                        buffer.set(ValueLayout.JAVA_BYTE, length, (byte) 0b101);
                        Tools.zeropad(buffer, length + 1);
                        state[24] ^= 0b1000;
                    } else {
                        state[24] ^= 0b1101;
                    }

                    state[0] ^= buffer.get(LAYOUT, 0);
                    state[6] ^= buffer.get(LAYOUT, 8);
                    state[12] ^= buffer.get(LAYOUT, 16);
                    state[18] ^= buffer.get(LAYOUT, 24);

                    if (length > 0) {
                        buffer.set(LAYOUT, 0, state[0]);
                        buffer.set(LAYOUT, 8, state[6]);
                        buffer.set(LAYOUT, 16, state[12]);
                        buffer.set(LAYOUT, 24, state[18]);

                        MemorySegment.copy(buffer, 0, ciphertext, 0, length);
                    }

                    return length;
                }

                @Override
                protected void finalizeState() {
                    KeccakP.keccak_p1600(state, 6);
                    enableAad(true);//this makes it a session-based cipher
                }

                @Override
                protected void generateTag(byte[] dest) {
                    Tools.store64LE(state[0], dest, 0);
                    Tools.store64LE(state[6], dest, 8);
                }

                @Override
                public AuthenticatedCipher getAlgorithm() {
                    return Ketje.KETJE_MAJOR;
                }

            };
        }

        @Override
        public DecryptEngine startDecryption(byte[] key, byte[] iv) {
            return new AbstractVerifierEngine(32) {

                private final long[] state = new long[25];

                {
                    state[0] = (Tools.load64LE(key, 0) << 8) | 18;
                    state[6] = Tools.load64LE(key, 7);
                    state[12] = (Tools.load64LE(iv, 0) << 16) | 0x0100 | (key[15] & 0xff);
                    state[18] = Tools.load64LE(iv, 6);
                    state[24] = (iv[14] & 0xff) | ((iv[15] & 0xff) << 8) | 0x010000;
                    state[21] = 0x8000000000000000L;

                    KeccakP.keccak_p1600(state, 12);
                }

                @Override
                protected void ingestOneBlock(MemorySegment aad, long offset) {
                    state[0] ^= aad.get(LAYOUT, offset + 0);
                    state[6] ^= aad.get(LAYOUT, offset + 8);
                    state[12] ^= aad.get(LAYOUT, offset + 16);
                    state[18] ^= aad.get(LAYOUT, offset + 24);
                    state[24] ^= 0b1100;

                    KeccakP.keccak_p1600_oneround(state);
                }

                @Override
                protected void ingestLastBlock(MemorySegment aad, int length) {
                    if (length < 32) {
                        aad.set(ValueLayout.JAVA_BYTE, length, (byte) 0b110);
                        Tools.zeropad(aad, length + 1);

                        state[0] ^= aad.get(LAYOUT, 0);
                        state[6] ^= aad.get(LAYOUT, 8);
                        state[12] ^= aad.get(LAYOUT, 16);
                        state[18] ^= aad.get(LAYOUT, 24);
                        state[24] ^= 0b1000;
                    } else {
                        state[0] ^= aad.get(LAYOUT, 0);
                        state[6] ^= aad.get(LAYOUT, 8);
                        state[12] ^= aad.get(LAYOUT, 16);
                        state[18] ^= aad.get(LAYOUT, 24);
                        state[24] ^= 0b1110;
                    }

                    KeccakP.keccak_p1600_oneround(state);
                }

                @Override
                protected void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset) {
                    long c;

                    c = ciphertext.get(LAYOUT, cOffset + 0);
                    plaintext.set(LAYOUT, pOffset + 0, state[0] ^ c);
                    state[0] = c;

                    c = ciphertext.get(LAYOUT, cOffset + 8);
                    plaintext.set(LAYOUT, pOffset + 8, state[6] ^ c);
                    state[6] = c;

                    c = ciphertext.get(LAYOUT, cOffset + 16);
                    plaintext.set(LAYOUT, pOffset + 16, state[12] ^ c);
                    state[12] = c;

                    c = ciphertext.get(LAYOUT, cOffset + 24);
                    plaintext.set(LAYOUT, pOffset + 24, state[18] ^ c);
                    state[18] = c;

                    state[24] ^= 0b1111;

                    KeccakP.keccak_p1600_oneround(state);
                }

                @Override
                protected int decryptLastBlock(MemorySegment buffer, int length, MemorySegment plaintext) {
                    buffer.set(LAYOUT, 0, state[0] ^ buffer.get(LAYOUT, 0));
                    buffer.set(LAYOUT, 8, state[6] ^ buffer.get(LAYOUT, 8));
                    buffer.set(LAYOUT, 16, state[12] ^ buffer.get(LAYOUT, 16));
                    buffer.set(LAYOUT, 24, state[18] ^ buffer.get(LAYOUT, 24));

                    if (length < 32) {
                        state[24] ^= 0b1000;
                        buffer.set(ValueLayout.JAVA_BYTE, length, (byte) 0b101);
                        Tools.zeropad(buffer, length + 1);
                    } else {
                        state[24] ^= 0b1101;
                    }

                    state[0] ^= buffer.get(LAYOUT, 0);
                    state[6] ^= buffer.get(LAYOUT, 8);
                    state[12] ^= buffer.get(LAYOUT, 16);
                    state[18] ^= buffer.get(LAYOUT, 24);

                    if (length > 0) {
                        MemorySegment.copy(buffer, 0, plaintext, 0, length);
                    }

                    return length;
                }

                @Override
                protected void finalizeState() {
                    KeccakP.keccak_p1600(state, 6);
                }

                @Override
                protected void generateTag(byte[] dest) {
                    Tools.store64LE(state[0], dest, 0);
                    Tools.store64LE(state[6], dest, 8);
                }

                @Override
                public boolean verify(byte[] tag, int offset, int length) {
                    var verified = super.verify(tag, offset, length);
                    if (verified) {
                        enableAad(true);//we will be able to continue unwrapping only if the tag verifies
                    }
                    return verified;
                }

                @Override
                public AuthenticatedCipher getAlgorithm() {
                    return Ketje.KETJE_MAJOR;
                }

            };
        }

    }, KETJE_MINOR {

        private static final ValueLayout.OfInt LAYOUT = Tools.LITTLE_ENDIAN_32_BIT;

        @Override
        public EncryptEngine startEncryption(byte[] key, byte[] iv) {
            return new AbstractAuthenticaterEngine(16) {

                private final int[] state = new int[25];

                {
                    state[0] = (Tools.load32LE(key, 0) << 8) | 18;
                    state[6] = Tools.load32LE(key, 3);
                    state[12] = Tools.load32LE(key, 7);
                    state[18] = Tools.load32LE(key, 11);
                    state[24] = (Tools.load32LE(iv, 0) << 16) | 0x0100 | (key[15] & 0xff);
                    state[3] = Tools.load32LE(iv, 2);
                    state[9] = Tools.load32LE(iv, 6);
                    state[10] = Tools.load32LE(iv, 10);
                    state[16] = (iv[14] & 0xff) | ((iv[15] & 0xff) << 8) | 0x010000;

                    state[21] = 0x80000000;

                    KeccakP.keccak_p800(state, 12);
                }

                @Override
                protected void ingestOneBlock(MemorySegment aad, long offset) {
                    state[0] ^= aad.get(LAYOUT, offset + 0);
                    state[6] ^= aad.get(LAYOUT, offset + 4);
                    state[12] ^= aad.get(LAYOUT, offset + 8);
                    state[18] ^= aad.get(LAYOUT, offset + 12);
                    state[24] ^= 0b1100;

                    KeccakP.keccak_p800_oneround(state);
                }

                @Override
                protected void ingestLastBlock(MemorySegment aad, int length) {
                    if (length < 16) {
                        aad.set(ValueLayout.JAVA_BYTE, length, (byte) 0b110);
                        Tools.zeropad(aad, length + 1);
                        state[24] ^= 0b1000;
                    } else {
                        state[24] ^= 0b1110;
                    }
                    state[0] ^= aad.get(LAYOUT, 0);
                    state[6] ^= aad.get(LAYOUT, 4);
                    state[12] ^= aad.get(LAYOUT, 8);
                    state[18] ^= aad.get(LAYOUT, 12);

                    KeccakP.keccak_p800_oneround(state);
                }

                @Override
                protected void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
                    state[0] ^= plaintext.get(LAYOUT, pOffset + 0);
                    state[6] ^= plaintext.get(LAYOUT, pOffset + 4);
                    state[12] ^= plaintext.get(LAYOUT, pOffset + 8);
                    state[18] ^= plaintext.get(LAYOUT, pOffset + 12);
                    state[24] ^= 0b1111;

                    ciphertext.set(LAYOUT, cOffset + 0, state[0]);
                    ciphertext.set(LAYOUT, cOffset + 4, state[6]);
                    ciphertext.set(LAYOUT, cOffset + 8, state[12]);
                    ciphertext.set(LAYOUT, cOffset + 12, state[18]);

                    KeccakP.keccak_p800_oneround(state);
                }

                @Override
                protected int encryptLastBlock(MemorySegment buffer, int length, MemorySegment ciphertext) {
                    if (length < 16) {
                        buffer.set(ValueLayout.JAVA_BYTE, length, (byte) 0b101);
                        Tools.zeropad(buffer, length + 1);
                        state[24] ^= 0b1000;
                    } else {
                        state[24] ^= 0b1101;
                    }

                    state[0] ^= buffer.get(LAYOUT, 0);
                    state[6] ^= buffer.get(LAYOUT, 4);
                    state[12] ^= buffer.get(LAYOUT, 8);
                    state[18] ^= buffer.get(LAYOUT, 12);

                    if (length > 0) {
                        buffer.set(LAYOUT, 0, state[0]);
                        buffer.set(LAYOUT, 4, state[6]);
                        buffer.set(LAYOUT, 8, state[12]);
                        buffer.set(LAYOUT, 12, state[18]);

                        MemorySegment.copy(buffer, 0, ciphertext, 0, length);
                    }

                    return length;
                }

                @Override
                protected void finalizeState() {
                    KeccakP.keccak_p800(state, 6);
                    enableAad(true);//this makes it a session-based cipher
                }

                @Override
                protected void generateTag(byte[] dest) {
                    Tools.store32LE(state[0], dest, 0);
                    Tools.store32LE(state[6], dest, 4);
                    Tools.store32LE(state[12], dest, 8);
                    Tools.store32LE(state[18], dest, 12);
                }

                @Override
                public AuthenticatedCipher getAlgorithm() {
                    return Ketje.KETJE_MINOR;
                }

            };
        }

        @Override
        public DecryptEngine startDecryption(byte[] key, byte[] iv) {
            return new AbstractVerifierEngine(16) {

                private final int[] state = new int[25];

                {
                    state[0] = (Tools.load32LE(key, 0) << 8) | 18;
                    state[6] = Tools.load32LE(key, 3);
                    state[12] = Tools.load32LE(key, 7);
                    state[18] = Tools.load32LE(key, 11);
                    state[24] = (Tools.load32LE(iv, 0) << 16) | 0x0100 | (key[15] & 0xff);
                    state[3] = Tools.load32LE(iv, 2);
                    state[9] = Tools.load32LE(iv, 6);
                    state[10] = Tools.load32LE(iv, 10);
                    state[16] = (iv[14] & 0xff) | ((iv[15] & 0xff) << 8) | 0x010000;

                    state[21] = 0x80000000;

                    KeccakP.keccak_p800(state, 12);
                }

                @Override
                protected void ingestOneBlock(MemorySegment aad, long offset) {
                    state[0] ^= aad.get(LAYOUT, offset + 0);
                    state[6] ^= aad.get(LAYOUT, offset + 4);
                    state[12] ^= aad.get(LAYOUT, offset + 8);
                    state[18] ^= aad.get(LAYOUT, offset + 12);
                    state[24] ^= 0b1100;

                    KeccakP.keccak_p800_oneround(state);
                }

                @Override
                protected void ingestLastBlock(MemorySegment aad, int length) {
                    if (length < 16) {
                        aad.set(ValueLayout.JAVA_BYTE, length, (byte) 0b110);
                        Tools.zeropad(aad, length + 1);
                        state[24] ^= 0b1000;
                    } else {
                        state[24] ^= 0b1110;
                    }
                    state[0] ^= aad.get(LAYOUT, 0);
                    state[6] ^= aad.get(LAYOUT, 4);
                    state[12] ^= aad.get(LAYOUT, 8);
                    state[18] ^= aad.get(LAYOUT, 12);

                    KeccakP.keccak_p800_oneround(state);
                }

                @Override
                protected void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset) {
                    int c;

                    c = ciphertext.get(LAYOUT, cOffset + 0);
                    plaintext.set(LAYOUT, pOffset + 0, state[0] ^ c);
                    state[0] = c;

                    c = ciphertext.get(LAYOUT, cOffset + 4);
                    plaintext.set(LAYOUT, pOffset + 4, state[6] ^ c);
                    state[6] = c;

                    c = ciphertext.get(LAYOUT, cOffset + 8);
                    plaintext.set(LAYOUT, pOffset + 8, state[12] ^ c);
                    state[12] = c;

                    c = ciphertext.get(LAYOUT, cOffset + 12);
                    plaintext.set(LAYOUT, pOffset + 12, state[18] ^ c);
                    state[18] = c;

                    state[24] ^= 0b1111;

                    KeccakP.keccak_p800_oneround(state);
                }

                @Override
                protected int decryptLastBlock(MemorySegment buffer, int length, MemorySegment plaintext) {
                    buffer.set(LAYOUT, 0, state[0] ^ buffer.get(LAYOUT, 0));
                    buffer.set(LAYOUT, 4, state[6] ^ buffer.get(LAYOUT, 4));
                    buffer.set(LAYOUT, 8, state[12] ^ buffer.get(LAYOUT, 8));
                    buffer.set(LAYOUT, 12, state[18] ^ buffer.get(LAYOUT, 12));

                    if (length < 16) {
                        state[24] ^= 0b1000;
                        buffer.set(ValueLayout.JAVA_BYTE, length, (byte) 0b101);
                        Tools.zeropad(buffer, length + 1);
                    } else {
                        state[24] ^= 0b1101;
                    }

                    state[0] ^= buffer.get(LAYOUT, 0);
                    state[6] ^= buffer.get(LAYOUT, 4);
                    state[12] ^= buffer.get(LAYOUT, 8);
                    state[18] ^= buffer.get(LAYOUT, 12);

                    if (length > 0) {
                        MemorySegment.copy(buffer, 0, plaintext, 0, length);
                    }

                    return length;
                }

                @Override
                protected void finalizeState() {
                    KeccakP.keccak_p800(state, 6);
                }

                @Override
                protected void generateTag(byte[] dest) {
                    Tools.store32LE(state[0], dest, 0);
                    Tools.store32LE(state[6], dest, 4);
                    Tools.store32LE(state[12], dest, 8);
                    Tools.store32LE(state[18], dest, 12);
                }

                @Override
                public boolean verify(byte[] tag, int offset, int length) {
                    var verified = super.verify(tag, offset, length);
                    if (verified) {
                        enableAad(true);//we will be able to continue wrapping only if the tag verifies
                    }
                    return verified;
                }

                @Override
                public AuthenticatedCipher getAlgorithm() {
                    return Ketje.KETJE_MINOR;
                }

            };
        }

    };

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
