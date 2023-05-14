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
public enum AesJambu implements AuthenticatedCipher {

    AES_JAMBU;

    private static final ValueLayout.OfInt LAYOUT = Tools.BIG_ENDIAN_32_BIT;

    @Override
    public EncryptEngine startEncryption(byte[] key, byte[] iv) {
        return new AbstractAuthenticaterEngine(8) {

            private final int[] state;
            private int r0, r1;

            private final AesEncApi.Aes128EncApi aes = new AesEncApi.Aes128EncApi(key);

            {
                state = new int[]{
                    0, 0, Tools.load32BE(iv, 0), Tools.load32BE(iv, 4)
                };
                aes.encryptBlock(state, 0, state, 0);

                r0 = state[0];
                r1 = state[1];

                state[3] ^= 5;
            }

            @Override
            protected void ingestOneBlock(MemorySegment aad, long offset) {
                aes.encryptBlock(state, 0, state, 0);

                state[0] ^= aad.get(LAYOUT, offset + 0);
                state[1] ^= aad.get(LAYOUT, offset + 4);
                state[2] ^= r0;
                state[3] ^= r1 ^ 1;

                r0 ^= state[0];
                r1 ^= state[1];
            }

            @Override
            protected void ingestLastBlock(MemorySegment aad, int length) {
                if (length == 16) {
                    ingestOneBlock(aad, 0);
                    length = 0;
                }
                Tools.ozpad(aad, length);
                ingestOneBlock(aad, 0);
            }

            @Override
            protected void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
                aes.encryptBlock(state, 0, state, 0);

                int m0 = plaintext.get(LAYOUT, pOffset + 0);
                int m1 = plaintext.get(LAYOUT, pOffset + 4);

                state[0] ^= m0;
                state[1] ^= m1;
                state[2] ^= r0;
                state[3] ^= r1;

                r0 ^= state[0];
                r1 ^= state[1];

                ciphertext.set(LAYOUT, cOffset + 0, m0 ^ state[2]);
                ciphertext.set(LAYOUT, cOffset + 4, m1 ^ state[3]);

            }

            @Override
            protected int encryptLastBlock(MemorySegment buffer, int length, MemorySegment ciphertext) {
                if (length == 8) {
                    encryptOneBlock(buffer, 0, ciphertext, 0);
                    length = 0;
                }
                Tools.ozpad(buffer, length);
                encryptOneBlock(buffer, 0, buffer, 0);
                MemorySegment.copy(buffer, 0, ciphertext, 0, length);

                return length;
            }

            @Override
            protected void finalizeState() {
                aes.encryptBlock(state, 0, state, 0);

                state[2] ^= r0;
                state[3] ^= r1 ^ 3;

                r0 ^= state[0];
                r1 ^= state[1];

                aes.encryptBlock(state, 0, state, 0);
            }

            @Override
            protected void generateTag(byte[] dest) {
                Tools.store32BE(r0 ^ state[0] ^ state[2], dest, 0);
                Tools.store32BE(r1 ^ state[1] ^ state[3], dest, 4);
            }

            @Override
            public AuthenticatedCipher getAlgorithm() {
                return AES_JAMBU;
            }
        };
    }

    @Override
    public DecryptEngine startDecryption(byte[] key, byte[] iv) {
        return new AbstractVerifierEngine(8) {

            private final int[] state;
            private int r0, r1;

            private final AesEncApi.Aes128EncApi aes = new AesEncApi.Aes128EncApi(key);

            {
                state = new int[]{
                    0, 0, Tools.load32BE(iv, 0), Tools.load32BE(iv, 4)
                };
                aes.encryptBlock(state, 0, state, 0);

                r0 = state[0];
                r1 = state[1];

                state[3] ^= 5;
            }

            @Override
            protected void ingestOneBlock(MemorySegment aad, long offset) {
                aes.encryptBlock(state, 0, state, 0);

                state[0] ^= aad.get(LAYOUT, offset + 0);
                state[1] ^= aad.get(LAYOUT, offset + 4);
                state[2] ^= r0;
                state[3] ^= r1 ^ 1;

                r0 ^= state[0];
                r1 ^= state[1];
            }

            @Override
            protected void ingestLastBlock(MemorySegment aad, int length) {
                if (length == 16) {
                    ingestOneBlock(aad, 0);
                    length = 0;
                }
                Tools.ozpad(aad, length);
                ingestOneBlock(aad, 0);
            }

            @Override
            protected void decryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
                aes.encryptBlock(state, 0, state, 0);

                state[2] ^= r0;
                state[3] ^= r1;

                int m0 = plaintext.get(LAYOUT, pOffset + 0) ^ state[2];
                int m1 = plaintext.get(LAYOUT, pOffset + 4) ^ state[3];

                state[0] ^= m0;
                state[1] ^= m1;

                r0 ^= state[0];
                r1 ^= state[1];

                ciphertext.set(LAYOUT, cOffset + 0, m0);
                ciphertext.set(LAYOUT, cOffset + 4, m1);

            }

            @Override
            protected int decryptLastBlock(MemorySegment buffer, int length, MemorySegment ciphertext) {
                if (length == 8) {
                    decryptOneBlock(buffer, 0, ciphertext, 0);
                }
                if (length == 8 || length == 0) {
                    aes.encryptBlock(state, 0, state, 0);

                    state[0] ^= 0x80000000;
                    state[2] ^= r0;
                    state[3] ^= r1;

                    r0 ^= state[0];
                    r1 ^= state[1];
                } else {
                    aes.encryptBlock(state, 0, state, 0);

                    state[2] ^= r0;
                    state[3] ^= r1;

                    buffer.set(LAYOUT, 0, buffer.get(LAYOUT, 0) ^ state[2]);
                    buffer.set(LAYOUT, 4, buffer.get(LAYOUT, 4) ^ state[3]);

                    Tools.ozpad(buffer, length);

                    state[0] ^= buffer.get(LAYOUT, 0);
                    state[1] ^= buffer.get(LAYOUT, 4);

                    r0 ^= state[0];
                    r1 ^= state[1];

                    MemorySegment.copy(buffer, 0, ciphertext, 0, length);
                }
                return length;
            }

            @Override
            protected void finalizeState() {
                aes.encryptBlock(state, 0, state, 0);

                state[2] ^= r0;
                state[3] ^= r1 ^ 3;

                r0 ^= state[0];
                r1 ^= state[1];

                aes.encryptBlock(state, 0, state, 0);
            }

            @Override
            protected void generateTag(byte[] dest) {
                Tools.store32BE(r0 ^ state[0] ^ state[2], dest, 0);
                Tools.store32BE(r1 ^ state[1] ^ state[3], dest, 4);
            }

            @Override
            public AuthenticatedCipher getAlgorithm() {
                return AES_JAMBU;
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

    @Override
    public int tagLength() {
        return 8;
    }

}
