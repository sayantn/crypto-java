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
import org.asterisk.crypto.lowlevel.DeoxysTBC;

import static org.asterisk.crypto.helper.Tools.BIG_ENDIAN_32_BIT;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum DeoxysAE1 implements AuthenticatedCipher {

    DEOXYS_AE1;

    private static final int AAD_BLOCK = 0x02000000, LAST = 0x04000000, MSG_BLOCK = 0, FINAL = 0x01000000;

    @Override
    public EncryptEngine startEncryption(byte[] key, byte[] iv) {
        return new AbstractAuthenticaterEngine(16, 32) {

            private final int[] tweak = new int[8], data = new int[4];

            private final int[] auth = new int[4], checksum = new int[4];

            private final DeoxysTBC.DeoxysTBC_128_256 blockCipher = new DeoxysTBC.DeoxysTBC_128_256(key);

            private long counter = 0;

            private final int[] savednonce = {
                Tools.load32BE(iv, 0), Tools.load32BE(iv, 4), Tools.load32BE(iv, 8), Tools.load32BE(iv, 12)
            };

            {
                tweak[4] = AAD_BLOCK;
            }

            @Override
            protected void ingestOneBlock(MemorySegment aad, long offset) {
                tweak[0] = aad.get(BIG_ENDIAN_32_BIT, offset + 0);
                tweak[1] = aad.get(BIG_ENDIAN_32_BIT, offset + 4);
                tweak[2] = aad.get(BIG_ENDIAN_32_BIT, offset + 8);
                tweak[3] = aad.get(BIG_ENDIAN_32_BIT, offset + 12);

                tweak[6] = (int) (counter >>> 32);
                tweak[7] = (int) counter;

                data[0] = aad.get(BIG_ENDIAN_32_BIT, offset + 16);
                data[1] = aad.get(BIG_ENDIAN_32_BIT, offset + 20);
                data[2] = aad.get(BIG_ENDIAN_32_BIT, offset + 24);
                data[3] = aad.get(BIG_ENDIAN_32_BIT, offset + 28);

                blockCipher.setTweak(tweak);
                blockCipher.encryptBlock(data, 0, data, 0);

                auth[0] ^= data[0];
                auth[1] ^= data[1];
                auth[2] ^= data[2];
                auth[3] ^= data[3];

                counter++;

            }

            @Override
            protected void ingestLastBlock(MemorySegment buffer, int position) {
                if (position == 32) {
                    ingestOneBlock(buffer, 0);
                } else if (position > 0) {
                    Tools.ozpad(buffer, position);

                    tweak[4] |= LAST;
                    ingestOneBlock(buffer, 0);
                }
                tweak[0] = MSG_BLOCK;
                tweak[1] = 0;
                counter = 0;
                blockCipher.setTweak0(savednonce);
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

                tweak[2] = (int) (counter >>> 32);
                tweak[3] = (int) counter;

                blockCipher.setTweak1(tweak);
                blockCipher.encryptBlock(data, 0, data, 0);

                ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 0, data[0]);
                ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 4, data[1]);
                ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 8, data[2]);
                ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 12, data[3]);

                counter++;

            }

            @Override
            protected int encryptLastBlock(MemorySegment buffer, int position, MemorySegment ciphertext) {
                if (position == 16) {
                    encryptOneBlock(buffer, 0, ciphertext, 0);
                } else if (position > 0) {
                    buffer.set(ValueLayout.JAVA_BYTE, position, (byte) 0x80);
                    buffer.asSlice(position + 1).fill((byte) 0);

                    int m0 = buffer.get(BIG_ENDIAN_32_BIT, 0);
                    int m1 = buffer.get(BIG_ENDIAN_32_BIT, 4);
                    int m2 = buffer.get(BIG_ENDIAN_32_BIT, 8);
                    int m3 = buffer.get(BIG_ENDIAN_32_BIT, 12);

                    checksum[0] ^= m0;
                    checksum[1] ^= m1;
                    checksum[2] ^= m2;
                    checksum[3] ^= m3;

                    tweak[0] |= LAST;
                    tweak[2] = (int) (counter >>> 32);
                    tweak[3] = (int) counter;

                    data[0] = 0;
                    data[1] = 0;
                    data[2] = 0;
                    data[3] = 0;

                    blockCipher.setTweak1(tweak);
                    blockCipher.encryptBlock(data, 0, data, 0);

                    buffer.set(BIG_ENDIAN_32_BIT, 0, m0 ^ data[0]);
                    buffer.set(BIG_ENDIAN_32_BIT, 4, m1 ^ data[1]);
                    buffer.set(BIG_ENDIAN_32_BIT, 8, m2 ^ data[2]);
                    buffer.set(BIG_ENDIAN_32_BIT, 12, m3 ^ data[3]);

                    counter++;

                    MemorySegment.copy(buffer, 0, ciphertext, 0, position);
                }
                return position;
            }

            @Override
            protected void finalizeState() {
                tweak[0] |= FINAL;
                tweak[2] = (int) (counter >>> 32);
                tweak[3] = (int) counter;
                blockCipher.setTweak1(tweak);
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
                return DEOXYS_AE1;
            }
        };
    }

    @Override
    public DecryptEngine startDecryption(byte[] key, byte[] iv) {
        return new AbstractVerifierEngine(16, 32) {

            private final int[] tweak = new int[8], data = new int[4];

            private final int[] auth = new int[4], checksum = new int[4];

            private final DeoxysTBC.DeoxysTBC_128_256 blockCipher = new DeoxysTBC.DeoxysTBC_128_256(key);

            private long counter = 0;

            private final int[] savednonce = {
                Tools.load32BE(iv, 0), Tools.load32BE(iv, 4), Tools.load32BE(iv, 8), Tools.load32BE(iv, 12)
            };

            {
                tweak[4] = AAD_BLOCK;
            }

            @Override
            protected void ingestOneBlock(MemorySegment aad, long offset) {
                tweak[0] = aad.get(BIG_ENDIAN_32_BIT, offset + 0);
                tweak[1] = aad.get(BIG_ENDIAN_32_BIT, offset + 4);
                tweak[2] = aad.get(BIG_ENDIAN_32_BIT, offset + 8);
                tweak[3] = aad.get(BIG_ENDIAN_32_BIT, offset + 12);

                tweak[6] = (int) (counter >>> 32);
                tweak[7] = (int) counter;

                data[0] = aad.get(BIG_ENDIAN_32_BIT, offset + 16);
                data[1] = aad.get(BIG_ENDIAN_32_BIT, offset + 20);
                data[2] = aad.get(BIG_ENDIAN_32_BIT, offset + 24);
                data[3] = aad.get(BIG_ENDIAN_32_BIT, offset + 28);

                blockCipher.setTweak(tweak);
                blockCipher.encryptBlock(data, 0, data, 0);

                auth[0] ^= data[0];
                auth[1] ^= data[1];
                auth[2] ^= data[2];
                auth[3] ^= data[3];

                counter++;

            }

            @Override
            protected void ingestLastBlock(MemorySegment buffer, int position) {
                if (position == 32) {
                    ingestOneBlock(buffer, 0);
                } else if (position > 0) {
                    buffer.set(ValueLayout.JAVA_BYTE, position, (byte) 0x80);
                    buffer.asSlice(position + 1).fill((byte) 0);

                    tweak[4] |= LAST;
                    ingestOneBlock(buffer, 0);
                }
                tweak[0] = MSG_BLOCK;
                tweak[1] = 0;
                counter = 0;
                blockCipher.setTweak0(savednonce);
            }

            @Override
            protected void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset) {
                tweak[2] = (int) (counter >>> 32);
                tweak[3] = (int) counter;

                data[0] = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 0);
                data[1] = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 4);
                data[2] = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 8);
                data[3] = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 12);

                blockCipher.setTweak1(tweak);
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
            protected int decryptLastBlock(MemorySegment buffer, int position, MemorySegment plaintext) {
                if (position == 16) {
                    decryptOneBlock(buffer, 0, plaintext, 0);
                } else if (position > 0) {
                    tweak[0] |= LAST;
                    tweak[2] = (int) (counter >>> 32);
                    tweak[3] = (int) counter;

                    data[0] = 0;
                    data[1] = 0;
                    data[2] = 0;
                    data[3] = 0;

                    blockCipher.setTweak1(tweak);
                    blockCipher.encryptBlock(data, 0, data, 0);

                    buffer.set(BIG_ENDIAN_32_BIT, 0, buffer.get(BIG_ENDIAN_32_BIT, 0) ^ data[0]);
                    buffer.set(BIG_ENDIAN_32_BIT, 4, buffer.get(BIG_ENDIAN_32_BIT, 4) ^ data[1]);
                    buffer.set(BIG_ENDIAN_32_BIT, 8, buffer.get(BIG_ENDIAN_32_BIT, 8) ^ data[2]);
                    buffer.set(BIG_ENDIAN_32_BIT, 12, buffer.get(BIG_ENDIAN_32_BIT, 12) ^ data[3]);

                    buffer.set(ValueLayout.JAVA_BYTE, position, (byte) 0x80);
                    buffer.asSlice(position + 1).fill((byte) 0);

                    checksum[0] ^= buffer.get(BIG_ENDIAN_32_BIT, 0);
                    checksum[1] ^= buffer.get(BIG_ENDIAN_32_BIT, 4);
                    checksum[2] ^= buffer.get(BIG_ENDIAN_32_BIT, 8);
                    checksum[3] ^= buffer.get(BIG_ENDIAN_32_BIT, 12);

                    counter++;

                    MemorySegment.copy(buffer, 0, plaintext, 0, position);
                }
                return position;
            }

            @Override
            protected void finalizeState() {
                tweak[0] |= FINAL;
                tweak[2] = (int) (counter >>> 32);
                tweak[3] = (int) counter;
                blockCipher.setTweak1(tweak);
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
                return DEOXYS_AE1;
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

    @Override
    public int tagLength() {
        return 16;
    }

}
