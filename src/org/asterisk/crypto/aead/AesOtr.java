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

import static org.asterisk.crypto.helper.GfHelper.*;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum AesOtr implements AuthenticatedCipher {

    AES_128_OTR_P(16) {
        @Override
        public EncryptEngine startEncryption(byte[] key, byte[] iv) {
            return new OtrPEncrypter(new AesEncApi.Aes128EncApi(key), iv);
        }

        @Override
        public DecryptEngine startDecryption(byte[] key, byte[] iv) {
            return new OtrPDecrypter(new AesEncApi.Aes128EncApi(key), iv);
        }
    }, AES_128_OTR_S(16) {
        @Override
        public EncryptEngine startEncryption(byte[] key, byte[] iv) {
            return new OtrSEncrypter(new AesEncApi.Aes128EncApi(key), iv);
        }

        @Override
        public DecryptEngine startDecryption(byte[] key, byte[] iv) {
            return new OtrSDecrypter(new AesEncApi.Aes128EncApi(key), iv);
        }
    }, AES_192_OTR_P(16) {
        @Override
        public EncryptEngine startEncryption(byte[] key, byte[] iv) {
            return new OtrPEncrypter(new AesEncApi.Aes192EncApi(key), iv);
        }

        @Override
        public DecryptEngine startDecryption(byte[] key, byte[] iv) {
            return new OtrPDecrypter(new AesEncApi.Aes192EncApi(key), iv);
        }
    }, AES_192_OTR_S(16) {
        @Override
        public EncryptEngine startEncryption(byte[] key, byte[] iv) {
            return new OtrSEncrypter(new AesEncApi.Aes192EncApi(key), iv);
        }

        @Override
        public DecryptEngine startDecryption(byte[] key, byte[] iv) {
            return new OtrSDecrypter(new AesEncApi.Aes192EncApi(key), iv);
        }
    }, AES_256_OTR_P(16) {
        @Override
        public EncryptEngine startEncryption(byte[] key, byte[] iv) {
            return new OtrPEncrypter(new AesEncApi.Aes256EncApi(key), iv);
        }

        @Override
        public DecryptEngine startDecryption(byte[] key, byte[] iv) {
            return new OtrPDecrypter(new AesEncApi.Aes256EncApi(key), iv);
        }
    }, AES_256_OTR_S(16) {
        @Override
        public EncryptEngine startEncryption(byte[] key, byte[] iv) {
            return new OtrSEncrypter(new AesEncApi.Aes256EncApi(key), iv);
        }

        @Override
        public DecryptEngine startDecryption(byte[] key, byte[] iv) {
            return new OtrSDecrypter(new AesEncApi.Aes256EncApi(key), iv);
        }
    };

    private static final ValueLayout.OfInt LAYOUT = Tools.BIG_ENDIAN_32_BIT;

    private final int keyLength;

    private AesOtr(int keyLength) {
        this.keyLength = keyLength;
    }

    @Override
    public int keyLength() {
        return keyLength;
    }

    @Override
    public int ivLength() {
        return 15;
    }

    @Override
    public int tagLength() {
        return 16;
    }

    @Override
    public long ciphertextSize(long plaintextSize) {
        return plaintextSize;
    }

    @Override
    public long plaintextSize(long ciphertextSize) {
        return ciphertextSize;
    }

    private final class OtrPEncrypter extends AbstractAuthenticaterEngine {

        private final AesEncApi aes;

        private final int[] deltaM = new int[4], deltaC = new int[4], deltaA = new int[4], checksum = new int[4], auth = new int[4];

        private final int[] data = new int[4];

        private OtrPEncrypter(AesEncApi aes, byte[] iv) {
            super(32, 16);

            this.aes = aes;

            aes.encryptBlock(deltaM, 0, deltaA, 0);

            deltaM[0] = 0x01000000 | (Tools.load32BE(iv, 0) >>> 8);
            deltaM[1] = Tools.load32BE(iv, 3);
            deltaM[2] = Tools.load32BE(iv, 7);
            deltaM[3] = Tools.load32BE(iv, 11);

            aes.encryptBlock(deltaM, 0, deltaM, 0);

            x3(deltaM, deltaC);

        }

        @Override
        protected void ingestOneBlock(MemorySegment aad, long offset) {
            data[0] = deltaA[0] ^ aad.get(LAYOUT, offset + 0);
            data[1] = deltaA[1] ^ aad.get(LAYOUT, offset + 4);
            data[2] = deltaA[2] ^ aad.get(LAYOUT, offset + 8);
            data[3] = deltaA[3] ^ aad.get(LAYOUT, offset + 12);

            aes.encryptBlock(data, 0, data, 0);

            auth[0] ^= data[0];
            auth[1] ^= data[1];
            auth[2] ^= data[2];
            auth[3] ^= data[3];

            x2(deltaA);

        }

        @Override
        protected void ingestLastBlock(MemorySegment aad, int length) {
            if (length > 0) {
                if (length < 16) {
                    Tools.ozpad(aad.asSlice(0, 16), length);
                }

                auth[0] ^= aad.get(LAYOUT, 0);
                auth[1] ^= aad.get(LAYOUT, 4);
                auth[2] ^= aad.get(LAYOUT, 8);
                auth[3] ^= aad.get(LAYOUT, 12);

                x3(deltaA, deltaA);
                if (length == 16) {
                    x3(deltaA, deltaA);
                }

                auth[0] ^= deltaA[0];
                auth[1] ^= deltaA[1];
                auth[2] ^= deltaA[2];
                auth[3] ^= deltaA[3];

                aes.encryptBlock(auth, 0, auth, 0);
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

            data[0] = deltaM[0] ^ m0;
            data[1] = deltaM[1] ^ m1;
            data[2] = deltaM[2] ^ m2;
            data[3] = deltaM[3] ^ m3;

            aes.encryptBlock(data, 0, data, 0);

            data[0] ^= m4;
            data[1] ^= m5;
            data[2] ^= m6;
            data[3] ^= m7;

            ciphertext.set(LAYOUT, cOffset + 0, data[0]);
            ciphertext.set(LAYOUT, cOffset + 4, data[1]);
            ciphertext.set(LAYOUT, cOffset + 8, data[2]);
            ciphertext.set(LAYOUT, cOffset + 12, data[3]);

            data[0] ^= deltaC[0];
            data[1] ^= deltaC[1];
            data[2] ^= deltaC[2];
            data[3] ^= deltaC[3];

            aes.encryptBlock(data, 0, data, 0);

            ciphertext.set(LAYOUT, cOffset + 16, data[0] ^ m0);
            ciphertext.set(LAYOUT, cOffset + 20, data[1] ^ m1);
            ciphertext.set(LAYOUT, cOffset + 24, data[2] ^ m2);
            ciphertext.set(LAYOUT, cOffset + 28, data[3] ^ m3);

            checksum[0] ^= m4;
            checksum[1] ^= m5;
            checksum[2] ^= m6;
            checksum[3] ^= m7;

            deltaM[0] ^= deltaC[0];
            deltaM[1] ^= deltaC[1];
            deltaM[2] ^= deltaC[2];
            deltaM[3] ^= deltaC[3];

            x2(deltaC);

        }

        @Override
        protected int encryptLastBlock(MemorySegment buffer, int length, MemorySegment ciphertext) {
            final int[] lStar;
            if (length > 16) {
                int m0 = buffer.get(LAYOUT, 0);
                int m1 = buffer.get(LAYOUT, 4);
                int m2 = buffer.get(LAYOUT, 8);
                int m3 = buffer.get(LAYOUT, 12);

                data[0] = deltaM[0] ^ m0;
                data[1] = deltaM[1] ^ m1;
                data[2] = deltaM[2] ^ m2;
                data[3] = deltaM[3] ^ m3;

                aes.encryptBlock(data, 0, data, 0);

                buffer.set(LAYOUT, 16, data[0] ^ buffer.get(LAYOUT, 16));
                buffer.set(LAYOUT, 20, data[1] ^ buffer.get(LAYOUT, 20));
                buffer.set(LAYOUT, 24, data[2] ^ buffer.get(LAYOUT, 24));
                buffer.set(LAYOUT, 28, data[3] ^ buffer.get(LAYOUT, 28));

                if (length < 32) {
                    Tools.ozpad(buffer, length);
                }
                int c0 = buffer.get(LAYOUT, 16);
                int c1 = buffer.get(LAYOUT, 20);
                int c2 = buffer.get(LAYOUT, 24);
                int c3 = buffer.get(LAYOUT, 28);

                checksum[0] ^= data[0] ^ c0;
                checksum[1] ^= data[1] ^ c1;
                checksum[2] ^= data[2] ^ c2;
                checksum[3] ^= data[3] ^ c3;

                data[0] = deltaC[0] ^ c0;
                data[1] = deltaC[1] ^ c1;
                data[2] = deltaC[2] ^ c2;
                data[3] = deltaC[3] ^ c3;

                aes.encryptBlock(data, 0, data, 0);

                buffer.set(LAYOUT, 0, data[0] ^ m0);
                buffer.set(LAYOUT, 4, data[1] ^ m1);
                buffer.set(LAYOUT, 8, data[2] ^ m2);
                buffer.set(LAYOUT, 12, data[3] ^ m3);

                lStar = deltaC;
            } else {
                Tools.ozpad(buffer, length);
                int m0 = buffer.get(LAYOUT, 0);
                int m1 = buffer.get(LAYOUT, 4);
                int m2 = buffer.get(LAYOUT, 8);
                int m3 = buffer.get(LAYOUT, 12);

                checksum[0] ^= m0;
                checksum[1] ^= m1;
                checksum[2] ^= m2;
                checksum[3] ^= m3;

                aes.encryptBlock(deltaM, 0, data, 0);

                buffer.set(LAYOUT, 0, data[0] ^ m0);
                buffer.set(LAYOUT, 4, data[1] ^ m1);
                buffer.set(LAYOUT, 8, data[2] ^ m2);
                buffer.set(LAYOUT, 12, data[3] ^ m3);

                lStar = deltaM;
            }

            MemorySegment.copy(buffer, 0, ciphertext, 0, length);

            if (length == 32) {
                x3(lStar, data);
                x3(data, data);
            } else {
                x7(lStar, data);
            }

            return length;
        }

        @Override
        protected void finalizeState() {
            checksum[0] ^= data[0];
            checksum[1] ^= data[1];
            checksum[2] ^= data[2];
            checksum[3] ^= data[3];

            aes.encryptBlock(checksum, 0, checksum, 0);
        }

        @Override
        protected void generateTag(byte[] dest) {
            Tools.store32BE(checksum[0] ^ auth[0], dest, 0);
            Tools.store32BE(checksum[1] ^ auth[1], dest, 4);
            Tools.store32BE(checksum[2] ^ auth[2], dest, 8);
            Tools.store32BE(checksum[3] ^ auth[3], dest, 12);
        }

        @Override
        public AuthenticatedCipher getAlgorithm() {
            return AesOtr.this;
        }

    }

    private final class OtrPDecrypter extends AbstractVerifierEngine {

        private final AesEncApi aes;

        private final int[] deltaM = new int[4], deltaC = new int[4], deltaA = new int[4], checksum = new int[4], auth = new int[4];

        private final int[] data = new int[4];

        private OtrPDecrypter(AesEncApi aes, byte[] iv) {
            super(32, 16);

            this.aes = aes;

            aes.encryptBlock(deltaM, 0, deltaA, 0);

            deltaM[0] = 0x01000000 | (Tools.load32BE(iv, 0) >>> 8);
            deltaM[1] = Tools.load32BE(iv, 3);
            deltaM[2] = Tools.load32BE(iv, 7);
            deltaM[3] = Tools.load32BE(iv, 11);

            aes.encryptBlock(deltaM, 0, deltaM, 0);

            x3(deltaM, deltaC);

        }

        @Override
        protected void ingestOneBlock(MemorySegment aad, long offset) {
            data[0] = deltaA[0] ^ aad.get(LAYOUT, offset + 0);
            data[1] = deltaA[1] ^ aad.get(LAYOUT, offset + 4);
            data[2] = deltaA[2] ^ aad.get(LAYOUT, offset + 8);
            data[3] = deltaA[3] ^ aad.get(LAYOUT, offset + 12);

            aes.encryptBlock(data, 0, data, 0);

            auth[0] ^= data[0];
            auth[1] ^= data[1];
            auth[2] ^= data[2];
            auth[3] ^= data[3];

            x2(deltaA);

        }

        @Override
        protected void ingestLastBlock(MemorySegment aad, int length) {
            if (length > 0) {
                if (length < 16) {
                    Tools.ozpad(aad.asSlice(0, 16), length);
                }

                auth[0] ^= aad.get(LAYOUT, 0);
                auth[1] ^= aad.get(LAYOUT, 4);
                auth[2] ^= aad.get(LAYOUT, 8);
                auth[3] ^= aad.get(LAYOUT, 12);

                x3(deltaA, deltaA);
                if (length == 16) {
                    x3(deltaA, deltaA);
                }

                auth[0] ^= deltaA[0];
                auth[1] ^= deltaA[1];
                auth[2] ^= deltaA[2];
                auth[3] ^= deltaA[3];

                aes.encryptBlock(auth, 0, auth, 0);
            }
        }

        @Override
        protected void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset) {

            int c0 = ciphertext.get(LAYOUT, cOffset + 0);
            int c1 = ciphertext.get(LAYOUT, cOffset + 4);
            int c2 = ciphertext.get(LAYOUT, cOffset + 8);
            int c3 = ciphertext.get(LAYOUT, cOffset + 12);

            data[0] = deltaC[0] ^ c0;
            data[1] = deltaC[1] ^ c1;
            data[2] = deltaC[2] ^ c2;
            data[3] = deltaC[3] ^ c3;

            aes.encryptBlock(data, 0, data, 0);

            data[0] ^= ciphertext.get(LAYOUT, cOffset + 16);
            data[1] ^= ciphertext.get(LAYOUT, cOffset + 20);
            data[2] ^= ciphertext.get(LAYOUT, cOffset + 24);
            data[3] ^= ciphertext.get(LAYOUT, cOffset + 28);

            plaintext.set(LAYOUT, pOffset + 0, data[0]);
            plaintext.set(LAYOUT, pOffset + 4, data[1]);
            plaintext.set(LAYOUT, pOffset + 8, data[2]);
            plaintext.set(LAYOUT, pOffset + 12, data[3]);

            data[0] ^= deltaM[0];
            data[1] ^= deltaM[1];
            data[2] ^= deltaM[2];
            data[3] ^= deltaM[3];

            aes.encryptBlock(data, 0, data, 0);

            data[0] ^= c0;
            data[1] ^= c1;
            data[2] ^= c2;
            data[3] ^= c3;

            plaintext.set(LAYOUT, pOffset + 16, data[0]);
            plaintext.set(LAYOUT, pOffset + 20, data[1]);
            plaintext.set(LAYOUT, pOffset + 24, data[2]);
            plaintext.set(LAYOUT, pOffset + 28, data[3]);

            checksum[0] ^= data[0];
            checksum[1] ^= data[1];
            checksum[2] ^= data[2];
            checksum[3] ^= data[3];

            deltaM[0] ^= deltaC[0];
            deltaM[1] ^= deltaC[1];
            deltaM[2] ^= deltaC[2];
            deltaM[3] ^= deltaC[3];

            x2(deltaC);

        }

        @Override
        protected int decryptLastBlock(MemorySegment buffer, int length, MemorySegment plaintext) {
            final int[] lStar;
            if (length > 16) {
                if (length < 32) {
                    Tools.ozpad(buffer, length);
                }
                int c4 = buffer.get(LAYOUT, 16);
                int c5 = buffer.get(LAYOUT, 20);
                int c6 = buffer.get(LAYOUT, 24);
                int c7 = buffer.get(LAYOUT, 28);

                data[0] = deltaC[0] ^ c4;
                data[1] = deltaC[1] ^ c5;
                data[2] = deltaC[2] ^ c6;
                data[3] = deltaC[3] ^ c7;

                aes.encryptBlock(data, 0, data, 0);

                data[0] ^= buffer.get(LAYOUT, 0);
                data[1] ^= buffer.get(LAYOUT, 4);
                data[2] ^= buffer.get(LAYOUT, 8);
                data[3] ^= buffer.get(LAYOUT, 12);

                plaintext.set(LAYOUT, 0, data[0]);
                plaintext.set(LAYOUT, 4, data[1]);
                plaintext.set(LAYOUT, 8, data[2]);
                plaintext.set(LAYOUT, 12, data[3]);

                data[0] ^= deltaM[0];
                data[1] ^= deltaM[1];
                data[2] ^= deltaM[2];
                data[3] ^= deltaM[3];

                aes.encryptBlock(data, 0, data, 0);

                data[0] ^= c4;
                data[1] ^= c5;
                data[2] ^= c6;
                data[3] ^= c7;

                buffer.set(LAYOUT, 0, data[0]);
                buffer.set(LAYOUT, 4, data[1]);
                buffer.set(LAYOUT, 8, data[2]);
                buffer.set(LAYOUT, 12, data[3]);

                checksum[0] ^= data[0];
                checksum[1] ^= data[1];
                checksum[2] ^= data[2];
                checksum[3] ^= data[3];

                lStar = deltaC;

                MemorySegment.copy(buffer, 0, plaintext, 16, length - 16);

            } else {

                aes.encryptBlock(deltaM, 0, data, 0);

                buffer.set(LAYOUT, 0, data[0] ^ buffer.get(LAYOUT, 0));
                buffer.set(LAYOUT, 4, data[1] ^ buffer.get(LAYOUT, 4));
                buffer.set(LAYOUT, 8, data[2] ^ buffer.get(LAYOUT, 8));
                buffer.set(LAYOUT, 12, data[3] ^ buffer.get(LAYOUT, 12));

                if (length < 16) {
                    Tools.ozpad(buffer, length);
                }

                checksum[0] ^= buffer.get(LAYOUT, 0);
                checksum[1] ^= buffer.get(LAYOUT, 4);
                checksum[2] ^= buffer.get(LAYOUT, 8);
                checksum[3] ^= buffer.get(LAYOUT, 12);

                MemorySegment.copy(buffer, 0, plaintext, 0, length);

                lStar = deltaM;
            }

            if (length == 32) {
                x3(lStar, data);
                x3(data, data);
            } else {
                x7(lStar, data);
            }

            return length;
        }

        @Override
        protected void finalizeState() {
            checksum[0] ^= data[0];
            checksum[1] ^= data[1];
            checksum[2] ^= data[2];
            checksum[3] ^= data[3];

            aes.encryptBlock(checksum, 0, checksum, 0);
        }

        @Override
        protected void generateTag(byte[] dest) {
            Tools.store32BE(checksum[0] ^ auth[0], dest, 0);
            Tools.store32BE(checksum[1] ^ auth[1], dest, 4);
            Tools.store32BE(checksum[2] ^ auth[2], dest, 8);
            Tools.store32BE(checksum[3] ^ auth[3], dest, 12);
        }

        @Override
        public AuthenticatedCipher getAlgorithm() {
            return AesOtr.this;
        }

    }

    private final class OtrSEncrypter extends AbstractAuthenticaterEngine {

        private final int[] checksum = new int[4], data = new int[4], deltaM = new int[4], deltaC = new int[4];

        private final AesEncApi aes;

        private OtrSEncrypter(AesEncApi aes, byte[] iv) {
            super(32, 16);
            this.aes = aes;

            deltaM[0] = 0x01000000 | (Tools.load32BE(iv, 0) >>> 8);
            deltaM[1] = Tools.load32BE(iv, 3);
            deltaM[2] = Tools.load32BE(iv, 7);
            deltaM[3] = Tools.load32BE(iv, 11);

            aes.encryptBlock(deltaM, 0, deltaM, 0);
        }

        @Override
        protected void ingestOneBlock(MemorySegment aad, long offset) {
            checksum[0] ^= aad.get(LAYOUT, offset + 0);
            checksum[1] ^= aad.get(LAYOUT, offset + 4);
            checksum[2] ^= aad.get(LAYOUT, offset + 8);
            checksum[3] ^= aad.get(LAYOUT, offset + 12);

            aes.encryptBlock(checksum, 0, checksum, 0);
        }

        @Override
        protected void ingestLastBlock(MemorySegment aad, int length) {
            if (length > 0) {
                aes.encryptBlock(data, 0, data, 0);
                x2(data);
                if (length < 16) {
                    Tools.ozpad(aad, length);
                    x2(data);
                }
                checksum[0] ^= aad.get(LAYOUT, 0) ^ data[0];
                checksum[1] ^= aad.get(LAYOUT, 4) ^ data[1];
                checksum[2] ^= aad.get(LAYOUT, 8) ^ data[2];
                checksum[3] ^= aad.get(LAYOUT, 12) ^ data[3];

                aes.encryptBlock(checksum, 0, checksum, 0);
            }
            deltaM[0] ^= checksum[0];
            deltaM[1] ^= checksum[1];
            deltaM[2] ^= checksum[2];
            deltaM[3] ^= checksum[3];

            x2(deltaM);
            x3(deltaM, deltaC);

            checksum[0] = 0;
            checksum[1] = 0;
            checksum[2] = 0;
            checksum[3] = 0;
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

            data[0] = deltaM[0] ^ m0;
            data[1] = deltaM[1] ^ m1;
            data[2] = deltaM[2] ^ m2;
            data[3] = deltaM[3] ^ m3;

            aes.encryptBlock(data, 0, data, 0);

            data[0] ^= m4;
            data[1] ^= m5;
            data[2] ^= m6;
            data[3] ^= m7;

            ciphertext.set(LAYOUT, cOffset + 0, data[0]);
            ciphertext.set(LAYOUT, cOffset + 4, data[1]);
            ciphertext.set(LAYOUT, cOffset + 8, data[2]);
            ciphertext.set(LAYOUT, cOffset + 12, data[3]);

            data[0] ^= deltaC[0];
            data[1] ^= deltaC[1];
            data[2] ^= deltaC[2];
            data[3] ^= deltaC[3];

            aes.encryptBlock(data, 0, data, 0);

            ciphertext.set(LAYOUT, cOffset + 16, data[0] ^ m0);
            ciphertext.set(LAYOUT, cOffset + 20, data[1] ^ m1);
            ciphertext.set(LAYOUT, cOffset + 24, data[2] ^ m2);
            ciphertext.set(LAYOUT, cOffset + 28, data[3] ^ m3);

            checksum[0] ^= m4;
            checksum[1] ^= m5;
            checksum[2] ^= m6;
            checksum[3] ^= m7;

            deltaM[0] ^= deltaC[0];
            deltaM[1] ^= deltaC[1];
            deltaM[2] ^= deltaC[2];
            deltaM[3] ^= deltaC[3];

            x2(deltaC);
        }

        @Override
        protected int encryptLastBlock(MemorySegment buffer, int length, MemorySegment ciphertext) {
            final int[] lStar;
            if (length > 16) {
                int m0 = buffer.get(LAYOUT, 0);
                int m1 = buffer.get(LAYOUT, 4);
                int m2 = buffer.get(LAYOUT, 8);
                int m3 = buffer.get(LAYOUT, 12);

                data[0] = deltaM[0] ^ m0;
                data[1] = deltaM[1] ^ m1;
                data[2] = deltaM[2] ^ m2;
                data[3] = deltaM[3] ^ m3;

                aes.encryptBlock(data, 0, data, 0);

                buffer.set(LAYOUT, 16, data[0] ^ buffer.get(LAYOUT, 16));
                buffer.set(LAYOUT, 20, data[1] ^ buffer.get(LAYOUT, 20));
                buffer.set(LAYOUT, 24, data[2] ^ buffer.get(LAYOUT, 24));
                buffer.set(LAYOUT, 28, data[3] ^ buffer.get(LAYOUT, 28));

                if (length < 32) {
                    Tools.ozpad(buffer, length);
                }
                int c0 = buffer.get(LAYOUT, 16);
                int c1 = buffer.get(LAYOUT, 20);
                int c2 = buffer.get(LAYOUT, 24);
                int c3 = buffer.get(LAYOUT, 28);

                checksum[0] ^= data[0] ^ c0;
                checksum[1] ^= data[1] ^ c1;
                checksum[2] ^= data[2] ^ c2;
                checksum[3] ^= data[3] ^ c3;

                data[0] = deltaC[0] ^ c0;
                data[1] = deltaC[1] ^ c1;
                data[2] = deltaC[2] ^ c2;
                data[3] = deltaC[3] ^ c3;

                aes.encryptBlock(data, 0, data, 0);

                buffer.set(LAYOUT, 0, data[0] ^ m0);
                buffer.set(LAYOUT, 4, data[1] ^ m1);
                buffer.set(LAYOUT, 8, data[2] ^ m2);
                buffer.set(LAYOUT, 12, data[3] ^ m3);

                lStar = deltaC;
            } else {
                Tools.ozpad(buffer, length);
                int m0 = buffer.get(LAYOUT, 0);
                int m1 = buffer.get(LAYOUT, 4);
                int m2 = buffer.get(LAYOUT, 8);
                int m3 = buffer.get(LAYOUT, 12);

                checksum[0] ^= m0;
                checksum[1] ^= m1;
                checksum[2] ^= m2;
                checksum[3] ^= m3;

                aes.encryptBlock(deltaM, 0, data, 0);

                buffer.set(LAYOUT, 0, data[0] ^ m0);
                buffer.set(LAYOUT, 4, data[1] ^ m1);
                buffer.set(LAYOUT, 8, data[2] ^ m2);
                buffer.set(LAYOUT, 12, data[3] ^ m3);

                lStar = deltaM;
            }

            MemorySegment.copy(buffer, 0, ciphertext, 0, length);

            if (length == 32) {
                x3(lStar, data);
                x3(data, data);
            } else {
                x7(lStar, data);
            }

            return length;
        }

        @Override
        protected void finalizeState() {
            checksum[0] ^= data[0];
            checksum[1] ^= data[1];
            checksum[2] ^= data[2];
            checksum[3] ^= data[3];

            aes.encryptBlock(checksum, 0, checksum, 0);
        }

        @Override
        protected void generateTag(byte[] dest) {
            Tools.store32BE(checksum[0], dest, 0);
            Tools.store32BE(checksum[1], dest, 4);
            Tools.store32BE(checksum[2], dest, 8);
            Tools.store32BE(checksum[3], dest, 12);
        }

        @Override
        public AuthenticatedCipher getAlgorithm() {
            return AesOtr.this;
        }

    }

    private final class OtrSDecrypter extends AbstractVerifierEngine {

        private final int[] checksum = new int[4], data = new int[4], deltaM = new int[4], deltaC = new int[4];

        private final AesEncApi aes;

        private OtrSDecrypter(AesEncApi aes, byte[] iv) {
            super(32, 16);
            this.aes = aes;

            deltaM[0] = 0x01000000 | (Tools.load32BE(iv, 0) >>> 8);
            deltaM[1] = Tools.load32BE(iv, 3);
            deltaM[2] = Tools.load32BE(iv, 7);
            deltaM[3] = Tools.load32BE(iv, 11);

            aes.encryptBlock(deltaM, 0, deltaM, 0);
        }

        @Override
        protected void ingestOneBlock(MemorySegment aad, long offset) {
            checksum[0] ^= aad.get(LAYOUT, offset + 0);
            checksum[1] ^= aad.get(LAYOUT, offset + 4);
            checksum[2] ^= aad.get(LAYOUT, offset + 8);
            checksum[3] ^= aad.get(LAYOUT, offset + 12);

            aes.encryptBlock(checksum, 0, checksum, 0);
        }

        @Override
        protected void ingestLastBlock(MemorySegment aad, int length) {
            if (length > 0) {
                aes.encryptBlock(data, 0, data, 0);
                x2(data);
                if (length < 16) {
                    Tools.ozpad(aad, length);
                    x2(data);
                }
                checksum[0] ^= aad.get(LAYOUT, 0) ^ data[0];
                checksum[1] ^= aad.get(LAYOUT, 4) ^ data[1];
                checksum[2] ^= aad.get(LAYOUT, 8) ^ data[2];
                checksum[3] ^= aad.get(LAYOUT, 12) ^ data[3];

                aes.encryptBlock(checksum, 0, checksum, 0);
            }
            deltaM[0] ^= checksum[0];
            deltaM[1] ^= checksum[1];
            deltaM[2] ^= checksum[2];
            deltaM[3] ^= checksum[3];

            x2(deltaM);
            x3(deltaM, deltaC);

            checksum[0] = 0;
            checksum[1] = 0;
            checksum[2] = 0;
            checksum[3] = 0;
        }

        @Override
        protected void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset) {

            int c0 = ciphertext.get(LAYOUT, cOffset + 0);
            int c1 = ciphertext.get(LAYOUT, cOffset + 4);
            int c2 = ciphertext.get(LAYOUT, cOffset + 8);
            int c3 = ciphertext.get(LAYOUT, cOffset + 12);

            data[0] = deltaC[0] ^ c0;
            data[1] = deltaC[1] ^ c1;
            data[2] = deltaC[2] ^ c2;
            data[3] = deltaC[3] ^ c3;

            aes.encryptBlock(data, 0, data, 0);

            data[0] ^= ciphertext.get(LAYOUT, cOffset + 16);
            data[1] ^= ciphertext.get(LAYOUT, cOffset + 20);
            data[2] ^= ciphertext.get(LAYOUT, cOffset + 24);
            data[3] ^= ciphertext.get(LAYOUT, cOffset + 28);

            plaintext.set(LAYOUT, pOffset + 0, data[0]);
            plaintext.set(LAYOUT, pOffset + 4, data[1]);
            plaintext.set(LAYOUT, pOffset + 8, data[2]);
            plaintext.set(LAYOUT, pOffset + 12, data[3]);

            data[0] ^= deltaM[0];
            data[1] ^= deltaM[1];
            data[2] ^= deltaM[2];
            data[3] ^= deltaM[3];

            aes.encryptBlock(data, 0, data, 0);

            data[0] ^= c0;
            data[1] ^= c1;
            data[2] ^= c2;
            data[3] ^= c3;

            plaintext.set(LAYOUT, pOffset + 16, data[0]);
            plaintext.set(LAYOUT, pOffset + 20, data[1]);
            plaintext.set(LAYOUT, pOffset + 24, data[2]);
            plaintext.set(LAYOUT, pOffset + 28, data[3]);

            checksum[0] ^= data[0];
            checksum[1] ^= data[1];
            checksum[2] ^= data[2];
            checksum[3] ^= data[3];

            deltaM[0] ^= deltaC[0];
            deltaM[1] ^= deltaC[1];
            deltaM[2] ^= deltaC[2];
            deltaM[3] ^= deltaC[3];

            x2(deltaC);

        }

        @Override
        protected int decryptLastBlock(MemorySegment buffer, int length, MemorySegment plaintext) {
            final int[] lStar;
            if (length > 16) {
                if (length < 32) {
                    Tools.ozpad(buffer, length);
                }
                int c4 = buffer.get(LAYOUT, 16);
                int c5 = buffer.get(LAYOUT, 20);
                int c6 = buffer.get(LAYOUT, 24);
                int c7 = buffer.get(LAYOUT, 28);

                data[0] = deltaC[0] ^ c4;
                data[1] = deltaC[1] ^ c5;
                data[2] = deltaC[2] ^ c6;
                data[3] = deltaC[3] ^ c7;

                aes.encryptBlock(data, 0, data, 0);

                data[0] ^= buffer.get(LAYOUT, 0);
                data[1] ^= buffer.get(LAYOUT, 4);
                data[2] ^= buffer.get(LAYOUT, 8);
                data[3] ^= buffer.get(LAYOUT, 12);

                plaintext.set(LAYOUT, 0, data[0]);
                plaintext.set(LAYOUT, 4, data[1]);
                plaintext.set(LAYOUT, 8, data[2]);
                plaintext.set(LAYOUT, 12, data[3]);

                data[0] ^= deltaM[0];
                data[1] ^= deltaM[1];
                data[2] ^= deltaM[2];
                data[3] ^= deltaM[3];

                aes.encryptBlock(data, 0, data, 0);

                data[0] ^= c4;
                data[1] ^= c5;
                data[2] ^= c6;
                data[3] ^= c7;

                buffer.set(LAYOUT, 0, data[0]);
                buffer.set(LAYOUT, 4, data[1]);
                buffer.set(LAYOUT, 8, data[2]);
                buffer.set(LAYOUT, 12, data[3]);

                checksum[0] ^= data[0];
                checksum[1] ^= data[1];
                checksum[2] ^= data[2];
                checksum[3] ^= data[3];

                lStar = deltaC;

                MemorySegment.copy(buffer, 0, plaintext, 16, length - 16);

            } else {

                aes.encryptBlock(deltaM, 0, data, 0);

                buffer.set(LAYOUT, 0, data[0] ^ buffer.get(LAYOUT, 0));
                buffer.set(LAYOUT, 4, data[1] ^ buffer.get(LAYOUT, 4));
                buffer.set(LAYOUT, 8, data[2] ^ buffer.get(LAYOUT, 8));
                buffer.set(LAYOUT, 12, data[3] ^ buffer.get(LAYOUT, 12));

                if (length < 16) {
                    Tools.ozpad(buffer.asSlice(0, 16), length);
                }

                checksum[0] ^= buffer.get(LAYOUT, 0);
                checksum[1] ^= buffer.get(LAYOUT, 4);
                checksum[2] ^= buffer.get(LAYOUT, 8);
                checksum[3] ^= buffer.get(LAYOUT, 12);

                lStar = deltaM;
            }

            if (length == 32) {
                x3(lStar, data);
                x3(data, data);
            } else {
                x7(lStar, data);
            }

            return length;
        }

        @Override
        protected void finalizeState() {
            checksum[0] ^= data[0];
            checksum[1] ^= data[1];
            checksum[2] ^= data[2];
            checksum[3] ^= data[3];

            aes.encryptBlock(checksum, 0, checksum, 0);
        }

        @Override
        protected void generateTag(byte[] dest) {
            Tools.store32BE(checksum[0], dest, 0);
            Tools.store32BE(checksum[1], dest, 4);
            Tools.store32BE(checksum[2], dest, 8);
            Tools.store32BE(checksum[3], dest, 12);
        }

        @Override
        public AuthenticatedCipher getAlgorithm() {
            return AesOtr.this;
        }

    }

}
