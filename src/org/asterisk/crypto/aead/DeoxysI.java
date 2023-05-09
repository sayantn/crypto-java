/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.aead;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.function.Function;
import org.asterisk.crypto.helper.AbstractAuthenticaterEngine;
import org.asterisk.crypto.helper.AbstractVerifierEngine;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.interfaces.AuthenticatedCipher;
import org.asterisk.crypto.lowlevel.DeoxysTBC;

import static org.asterisk.crypto.helper.Tools.BIG_ENDIAN_32_BIT;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum DeoxysI implements AuthenticatedCipher {

    DEOXYS_I_128(DeoxysTBC.DeoxysTBC_256::new) {
        @Override
        public int keyLength() {
            return 16;
        }
    }, DEOXYS_I_256(DeoxysTBC.DeoxysTBC_256_128::new) {
        @Override
        public int keyLength() {
            return 32;
        }

    };

    private static final int AAD_BLOCK = 0x20000000, LAST = 0x40000000, FINAL = 0x10000000;

    private final Function<byte[], DeoxysTBC> constructor;

    private DeoxysI(Function<byte[], DeoxysTBC> constructor) {
        this.constructor = constructor;
    }

    @Override
    public EncryptEngine startEncryption(byte[] key, byte[] iv) {
        final int temp0 = Tools.load32BE(iv, 0), temp1 = Tools.load32BE(iv, 4);

        return new AbstractAuthenticaterEngine(16) {

            private final int[] tweak = new int[4], data = new int[4];

            private final DeoxysTBC blockCipher = constructor.apply(key);

            private final int[] auth = new int[4], checksum = new int[4];
            private long counter = 0;

            private final int iv0 = temp0 >>> 4,
                    iv1 = (temp0 << 28) | (temp1 >>> 4),
                    iv2 = temp1 << 28;

            {
                tweak[0] = AAD_BLOCK;
            }

            @Override
            protected void ingestOneBlock(MemorySegment aad, long offset) {
                tweak[2] = (int) (counter >>> 32);
                tweak[3] = (int) counter;

                data[0] = aad.get(BIG_ENDIAN_32_BIT, offset + 0);
                data[1] = aad.get(BIG_ENDIAN_32_BIT, offset + 4);
                data[2] = aad.get(BIG_ENDIAN_32_BIT, offset + 8);
                data[3] = aad.get(BIG_ENDIAN_32_BIT, offset + 12);

                blockCipher.setTweak(tweak);
                blockCipher.encryptBlock(data, 0, data, 0);

                auth[0] ^= data[0];
                auth[1] ^= data[1];
                auth[2] ^= data[2];
                auth[3] ^= data[3];

                counter++;

            }

            @Override
            protected void ingestLastBlock(MemorySegment aad, int length) {
                if (length == 16) {
                    ingestOneBlock(aad, 0);
                } else if (length > 0) {
                    tweak[0] |= LAST;
                    aad.set(ValueLayout.JAVA_BYTE, length, (byte) 0x80);
                    aad.asSlice(length + 1).fill((byte) 0);
                    ingestOneBlock(aad, 0);
                }
                tweak[0] = iv0;
                tweak[1] = iv1;
                counter = 0;
            }

            @Override
            protected void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
                data[0] = plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 0);
                data[1] = plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 4);
                data[2] = plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 8);
                data[3] = plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 12);

                checksum[0] ^= data[0];
                checksum[1] ^= data[1];
                checksum[2] ^= data[2];
                checksum[3] ^= data[3];

                tweak[2] = iv2 | (int) (counter >>> 32);
                tweak[3] = (int) counter;

                blockCipher.setTweak(tweak);
                blockCipher.encryptBlock(data, 0, data, 0);

                ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 0, data[0]);
                ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 4, data[1]);
                ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 8, data[2]);
                ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 12, data[3]);

                counter++;

            }

            @Override
            protected int encryptLastBlock(MemorySegment buffer, int length, MemorySegment ciphertext) {
                if (length == 16) {
                    encryptOneBlock(buffer, 0, ciphertext, 0);
                } else if (length > 0) {
                    buffer.set(ValueLayout.JAVA_BYTE, length, (byte) 0x80);
                    buffer.asSlice(length + 1).fill((byte) 0);

                    int m0 = buffer.get(BIG_ENDIAN_32_BIT, 0);
                    int m1 = buffer.get(BIG_ENDIAN_32_BIT, 4);
                    int m2 = buffer.get(BIG_ENDIAN_32_BIT, 8);
                    int m3 = buffer.get(BIG_ENDIAN_32_BIT, 12);

                    checksum[0] ^= m0;
                    checksum[1] ^= m1;
                    checksum[2] ^= m2;
                    checksum[3] ^= m3;

                    tweak[0] |= LAST;
                    tweak[2] = iv2 | (int) (counter >>> 32);
                    tweak[3] = (int) counter;

                    data[0] = 0;
                    data[1] = 0;
                    data[2] = 0;
                    data[3] = 0;

                    blockCipher.setTweak(tweak);
                    blockCipher.encryptBlock(data, 0, data, 0);

                    buffer.set(BIG_ENDIAN_32_BIT, 0, m0 ^ data[0]);
                    buffer.set(BIG_ENDIAN_32_BIT, 4, m1 ^ data[1]);
                    buffer.set(BIG_ENDIAN_32_BIT, 8, m2 ^ data[2]);
                    buffer.set(BIG_ENDIAN_32_BIT, 12, m3 ^ data[3]);

                    counter++;

                    MemorySegment.copy(buffer, 0, ciphertext, 0, length);
                }
                return length;
            }

            @Override
            protected void finalizeState() {
                tweak[0] |= FINAL;
                tweak[2] = iv2 | (int) (counter >>> 32);
                tweak[3] = (int) counter;

                blockCipher.setTweak(tweak);
                blockCipher.encryptBlock(checksum, 0, checksum, 0);

            }

            @Override
            protected void generateTag(byte[] dest) {
                Tools.store32BE(auth[0] ^ checksum[0], dest, 0);
                Tools.store32BE(auth[1] ^ checksum[1], dest, 4);
                Tools.store32BE(auth[2] ^ checksum[2], dest, 8);
                Tools.store32BE(auth[3] ^ checksum[3], dest, 12);
            }

            @Override
            public AuthenticatedCipher getAlgorithm() {
                return DeoxysI.this;
            }
        };
    }

    @Override
    public DecryptEngine startDecryption(byte[] key, byte[] iv) {
        final int temp0 = Tools.load32BE(iv, 0), temp1 = Tools.load32BE(iv, 4);
        return new AbstractVerifierEngine(16) {
            private final int[] tweak = new int[4], data = new int[4];

            private final DeoxysTBC blockCipher = constructor.apply(key);

            private final int[] auth = new int[4], checksum = new int[4];
            private long counter = 0;

            private final int iv0 = temp0 >>> 4,
                    iv1 = (temp0 << 28) | (temp1 >>> 4),
                    iv2 = temp1 << 28;

            {
                tweak[0] = AAD_BLOCK;
            }

            @Override
            protected void ingestOneBlock(MemorySegment aad, long offset) {
                tweak[2] = (int) (counter >>> 32);
                tweak[3] = (int) counter;

                data[0] = aad.get(BIG_ENDIAN_32_BIT, offset + 0);
                data[1] = aad.get(BIG_ENDIAN_32_BIT, offset + 4);
                data[2] = aad.get(BIG_ENDIAN_32_BIT, offset + 8);
                data[3] = aad.get(BIG_ENDIAN_32_BIT, offset + 12);

                blockCipher.setTweak(tweak);
                blockCipher.encryptBlock(data, 0, data, 0);

                auth[0] ^= data[0];
                auth[1] ^= data[1];
                auth[2] ^= data[2];
                auth[3] ^= data[3];

                counter++;

            }

            @Override
            protected void ingestLastBlock(MemorySegment aad, int length) {
                if (length == 16) {
                    ingestOneBlock(aad, 0);
                } else if (length > 0) {
                    tweak[0] |= LAST;
                    aad.set(ValueLayout.JAVA_BYTE, length, (byte) 0x80);
                    aad.asSlice(length + 1).fill((byte) 0);
                    ingestOneBlock(aad, 0);
                }
                tweak[0] = iv0;
                tweak[1] = iv1;
                counter = 0;
            }

            @Override
            protected void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset) {
                tweak[2] = iv2 | (int) (counter >>> 32);
                tweak[3] = (int) counter;

                data[0] = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 0);
                data[1] = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 4);
                data[2] = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 8);
                data[3] = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 12);

                blockCipher.setTweak(tweak);
                blockCipher.decryptBlock(data, 0, data, 0);

                checksum[0] ^= data[0];
                checksum[1] ^= data[1];
                checksum[2] ^= data[2];
                checksum[3] ^= data[3];

                plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 0, data[0]);
                plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 4, data[1]);
                plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 8, data[2]);
                plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 12, data[3]);

                counter++;

            }

            @Override
            protected int decryptLastBlock(MemorySegment buffer, int length, MemorySegment plaintext) {
                if (length == 16) {
                    decryptOneBlock(buffer, 0, plaintext, 0);
                } else if (length > 0) {
                    tweak[0] |= LAST;
                    tweak[2] = iv2 | (int) (counter >>> 32);
                    tweak[3] = (int) counter;

                    data[0] = 0;
                    data[1] = 0;
                    data[2] = 0;
                    data[3] = 0;

                    blockCipher.setTweak(tweak);
                    blockCipher.encryptBlock(data, 0, data, 0);

                    buffer.set(BIG_ENDIAN_32_BIT, 0, buffer.get(BIG_ENDIAN_32_BIT, 0) ^ data[0]);
                    buffer.set(BIG_ENDIAN_32_BIT, 4, buffer.get(BIG_ENDIAN_32_BIT, 4) ^ data[1]);
                    buffer.set(BIG_ENDIAN_32_BIT, 8, buffer.get(BIG_ENDIAN_32_BIT, 8) ^ data[2]);
                    buffer.set(BIG_ENDIAN_32_BIT, 12, buffer.get(BIG_ENDIAN_32_BIT, 12) ^ data[3]);

                    buffer.set(ValueLayout.JAVA_BYTE, length, (byte) 0x80);
                    buffer.asSlice(length + 1).fill((byte) 0);

                    checksum[0] ^= buffer.get(BIG_ENDIAN_32_BIT, 0);
                    checksum[1] ^= buffer.get(BIG_ENDIAN_32_BIT, 4);
                    checksum[2] ^= buffer.get(BIG_ENDIAN_32_BIT, 8);
                    checksum[3] ^= buffer.get(BIG_ENDIAN_32_BIT, 12);

                    counter++;

                    MemorySegment.copy(buffer, 0, plaintext, 0, length);
                }
                return length;
            }

            @Override
            protected void finalizeState() {
                tweak[0] |= FINAL;
                tweak[2] = iv2 | (int) (counter >>> 32);
                tweak[3] = (int) counter;

                blockCipher.setTweak(tweak);
                blockCipher.encryptBlock(checksum, 0, checksum, 0);

            }

            @Override
            protected void generateTag(byte[] dest) {
                Tools.store32BE(auth[0] ^ checksum[0], dest, 0);
                Tools.store32BE(auth[1] ^ checksum[1], dest, 4);
                Tools.store32BE(auth[2] ^ checksum[2], dest, 8);
                Tools.store32BE(auth[3] ^ checksum[3], dest, 12);
            }

            @Override
            public AuthenticatedCipher getAlgorithm() {
                return DeoxysI.this;
            }
        };
    }

    @Override
    public int ivLength() {
        return 8;
    }

    @Override
    public int tagLength() {
        return 16;
    }

}
