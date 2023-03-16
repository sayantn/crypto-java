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
import org.asterisk.crypto.lowlevel.AesEncApi;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum AesSilc implements AuthenticatedCipher {

    AES_128_SILC;

    private static final ValueLayout.OfInt LAYOUT = Tools.BIG_ENDIAN_32_BIT;

    private static final int PARAM = 0xc0;

    private static void g(int[] src, long length, int[] dest) {
        dest[2] = src[2] ^ ((int) (length >>> 32));
        dest[3] = src[3] ^ (int) length;

        int temp = src[0];
        dest[0] = (temp << 8) | (src[1] >>> 24);
        dest[1] = (src[1] << 8) | (dest[2] >>> 24);
        dest[2] = (dest[2] << 8) | (dest[3] >>> 24);
        dest[3] = (dest[3] << 8) | ((temp >>> 24) ^ ((temp >>> 16) & 0xff));
    }

    private static void g(int[] src, int[] dest) {
        int temp = src[0];
        dest[0] = (temp << 8) | (src[1] >>> 24);
        dest[1] = (src[1] << 8) | (src[2] >>> 24);
        dest[2] = (src[2] << 8) | (src[3] >>> 24);
        dest[3] = (src[3] << 8) | ((temp >>> 24) ^ ((temp >>> 16) & 0xff));
    }

    @Override
    public EncryptEngine startEncryption(byte[] key, byte[] iv) {
        return new AbstractAuthenticaterEngine(16) {

            private final AesEncApi.Aes128EncApi aes = new AesEncApi.Aes128EncApi(key);

            private final int[] state = {
                PARAM, Tools.load32BE(iv, 0), Tools.load32BE(iv, 4), Tools.load32BE(iv, 8)
            };

            private final int[] checksum = new int[4];

            private long aadlen = 0, msglen = 0;

            {
                aes.encryptBlock(state, 0, state, 0);
            }

            @Override
            protected void ingestOneBlock(MemorySegment aad, long offset) {
                state[0] ^= aad.get(LAYOUT, offset + 0);
                state[1] ^= aad.get(LAYOUT, offset + 4);
                state[2] ^= aad.get(LAYOUT, offset + 8);
                state[3] ^= aad.get(LAYOUT, offset + 12);

                aes.encryptBlock(state, 0, state, 0);

                aadlen += 16;
            }

            @Override
            protected void ingestLastBlock(MemorySegment aad, int length) {
                if (length > 0) {
                    Tools.zeropad(aad, length);

                    state[0] ^= aad.get(LAYOUT, 0);
                    state[1] ^= aad.get(LAYOUT, 4);
                    state[2] ^= aad.get(LAYOUT, 8);
                    state[3] ^= aad.get(LAYOUT, 12);

                    aes.encryptBlock(state, 0, state, 0);

                    aadlen += length;
                }

                g(state, aadlen, state);

                g(state, checksum);

                aes.encryptBlock(state, 0, state, 0);

                aes.encryptBlock(checksum, 0, checksum, 0);

            }

            @Override
            protected void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
                state[0] ^= plaintext.get(LAYOUT, pOffset + 0);
                state[1] ^= plaintext.get(LAYOUT, pOffset + 4);
                state[2] ^= plaintext.get(LAYOUT, pOffset + 8);
                state[3] ^= plaintext.get(LAYOUT, pOffset + 12);

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

                aes.encryptBlock(checksum, 0, checksum, 0);

                msglen += 16;

            }

            @Override
            protected int encryptLastBlock(MemorySegment buffer, int length, MemorySegment ciphertext) {
                if (length > 0) {
                    buffer.set(LAYOUT, 0, state[0] ^ buffer.get(LAYOUT, 0));
                    buffer.set(LAYOUT, 4, state[1] ^ buffer.get(LAYOUT, 4));
                    buffer.set(LAYOUT, 8, state[2] ^ buffer.get(LAYOUT, 8));
                    buffer.set(LAYOUT, 12, state[3] ^ buffer.get(LAYOUT, 12));

                    Tools.zeropad(buffer, length);

                    checksum[0] ^= buffer.get(LAYOUT, 0);
                    checksum[1] ^= buffer.get(LAYOUT, 4);
                    checksum[2] ^= buffer.get(LAYOUT, 8);
                    checksum[3] ^= buffer.get(LAYOUT, 12);

                    aes.encryptBlock(checksum, 0, checksum, 0);

                    msglen += length;

                    MemorySegment.copy(buffer, 0, ciphertext, 0, length);
                }
                return length;
            }

            @Override
            protected void finalizeState() {
                g(checksum, msglen, checksum);
                aes.encryptBlock(checksum, 0, checksum, 0);
            }

            @Override
            protected void generateTag(byte[] dest) {
                Tools.store32BE(checksum[0], dest, 0);
                Tools.store32BE(checksum[1], dest, 4);
            }

            @Override
            public AuthenticatedCipher getAlgorithm() {
                return AES_128_SILC;
            }
        };
    }

    @Override
    public DecryptEngine startDecryption(byte[] key, byte[] iv) {
        return new AbstractVerifierEngine(16) {

            private final AesEncApi.Aes128EncApi aes = new AesEncApi.Aes128EncApi(key);

            private final int[] state = {
                PARAM, Tools.load32BE(iv, 0), Tools.load32BE(iv, 4), Tools.load32BE(iv, 8)
            };

            private final int[] checksum = new int[4], data = new int[4];

            private long aadlen = 0, msglen = 0;

            {
                aes.encryptBlock(state, 0, state, 0);
            }

            @Override
            protected void ingestOneBlock(MemorySegment aad, long offset) {
                state[0] ^= aad.get(LAYOUT, offset + 0);
                state[1] ^= aad.get(LAYOUT, offset + 4);
                state[2] ^= aad.get(LAYOUT, offset + 8);
                state[3] ^= aad.get(LAYOUT, offset + 12);

                aes.encryptBlock(state, 0, state, 0);

                aadlen += 16;
            }

            @Override
            protected void ingestLastBlock(MemorySegment aad, int length) {
                if (length > 0) {
                    Tools.zeropad(aad, length);

                    state[0] ^= aad.get(LAYOUT, 0);
                    state[1] ^= aad.get(LAYOUT, 4);
                    state[2] ^= aad.get(LAYOUT, 8);
                    state[3] ^= aad.get(LAYOUT, 12);

                    aes.encryptBlock(state, 0, state, 0);

                    aadlen += length;
                }

                g(state, aadlen, state);

                g(state, checksum);

                aes.encryptBlock(state, 0, state, 0);

                aes.encryptBlock(checksum, 0, checksum, 0);

            }

            @Override
            protected void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset) {
                data[0] = ciphertext.get(LAYOUT, cOffset + 0);
                data[1] = ciphertext.get(LAYOUT, cOffset + 4);
                data[2] = ciphertext.get(LAYOUT, cOffset + 8);
                data[3] = ciphertext.get(LAYOUT, cOffset + 12);

                plaintext.set(LAYOUT, pOffset + 0, state[0] ^ data[0]);
                plaintext.set(LAYOUT, pOffset + 4, state[1] ^ data[1]);
                plaintext.set(LAYOUT, pOffset + 8, state[2] ^ data[2]);
                plaintext.set(LAYOUT, pOffset + 12, state[3] ^ data[3]);

                checksum[0] ^= data[0];
                checksum[1] ^= data[1];
                checksum[2] ^= data[2];
                checksum[3] ^= data[3];

                data[0] |= 0x80000000;

                aes.encryptBlock(data, 0, state, 0);

                aes.encryptBlock(checksum, 0, checksum, 0);

                msglen += 16;

            }

            @Override
            protected int decryptLastBlock(MemorySegment buffer, int length, MemorySegment plaintext) {
                if (length > 0) {
                    Tools.zeropad(buffer, length);

                    data[0] = buffer.get(LAYOUT, 0);
                    data[1] = buffer.get(LAYOUT, 4);
                    data[2] = buffer.get(LAYOUT, 8);
                    data[3] = buffer.get(LAYOUT, 12);

                    buffer.set(LAYOUT, 0, state[0] ^ data[0]);
                    buffer.set(LAYOUT, 4, state[1] ^ data[1]);
                    buffer.set(LAYOUT, 8, state[2] ^ data[2]);
                    buffer.set(LAYOUT, 12, state[3] ^ data[3]);

                    checksum[0] ^= data[0];
                    checksum[1] ^= data[1];
                    checksum[2] ^= data[2];
                    checksum[3] ^= data[3];

                    aes.encryptBlock(checksum, 0, checksum, 0);

                    msglen += length;

                    MemorySegment.copy(buffer, 0, plaintext, 0, length);
                }
                return length;
            }

            @Override
            protected void finalizeState() {
                g(checksum, msglen, checksum);
                aes.encryptBlock(checksum, 0, checksum, 0);
            }

            @Override
            protected void generateTag(byte[] dest) {
                Tools.store32BE(checksum[0], dest, 0);
                Tools.store32BE(checksum[1], dest, 4);
            }

            @Override
            public AuthenticatedCipher getAlgorithm() {
                return AES_128_SILC;
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
