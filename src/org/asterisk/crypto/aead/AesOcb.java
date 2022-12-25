/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.aead;

import org.asterisk.crypto.helper.GfHelper;
import java.lang.foreign.MemorySegment;
import java.util.function.Function;
import java.util.stream.Stream;
import org.asterisk.crypto.Tested;
import org.asterisk.crypto.helper.AbstractAuthenticaterEngine;
import org.asterisk.crypto.helper.AbstractVerifierEngine;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.interfaces.AuthenticatedCipher;
import org.asterisk.crypto.lowlevel.AesDecApi;
import org.asterisk.crypto.lowlevel.AesEncApi;
import org.asterisk.crypto.lowlevel.AesEncApi.Aes128EncApi;
import org.asterisk.crypto.lowlevel.AesEncApi.Aes192EncApi;
import org.asterisk.crypto.lowlevel.AesEncApi.Aes256EncApi;

import static org.asterisk.crypto.helper.Tools.BIG_ENDIAN_32_BIT;

/**
 *
 * @author Sayantan Chakraborty
 */
public class AesOcb implements AuthenticatedCipher {

    @Tested
    public static AesOcb aes128_ocb(int taglen) {
        return new AesOcb(Aes128EncApi::new, 16, taglen);
    }

    @Tested
    public static AesOcb aes192_ocb(int taglen) {
        return new AesOcb(Aes192EncApi::new, 24, taglen);
    }

    @Tested
    public static AesOcb aes256_ocb(int taglen) {
        return new AesOcb(Aes256EncApi::new, 32, taglen);
    }

    private static int[] ocbDouble(int[] src) {
        int[] ret = new int[4];
        GfHelper.x2(src, ret);
        return ret;
    }

    private final Function<byte[], AesEncApi> constructor;
    private final int keyLength, tagLength;

    private AesOcb(Function<byte[], AesEncApi> constructor, int keyLength, int tagLength) {
        this.constructor = constructor;
        this.keyLength = keyLength;
        this.tagLength = tagLength;
    }

    private int[] getOffset0(byte[] iv, AesEncApi engine) {
        int ivLen = Math.min(iv.length, 15);
        byte[] copy = new byte[16];
        System.arraycopy(iv, 0, copy, 16 - ivLen, ivLen);
        copy[15 - ivLen] = 0x01;

        int[] nonce = {
            (tagLength << 28) | Tools.load32BE(copy, 0),
            Tools.load32BE(copy, 4),
            Tools.load32BE(copy, 8),
            Tools.load32BE(copy, 12)
        };

        int bottom = nonce[3] & 63;
        nonce[3] &= 0xffffffc0;
        engine.encryptBlock(nonce, 0, nonce, 0);
        int nonce4 = nonce[0] ^ ((nonce[0] << 8) | (nonce[1] >>> 24));
        int nonce5 = nonce[1] ^ ((nonce[1] << 8) | (nonce[2] >>> 24));

        if (bottom == 0) {
            return new int[]{
                nonce[0], nonce[1], nonce[2], nonce[3]
            };
        } else if (bottom < 32) {
            return new int[]{
                (nonce[0] << bottom) | (nonce[1] >>> -bottom),
                (nonce[1] << bottom) | (nonce[2] >>> -bottom),
                (nonce[2] << bottom) | (nonce[3] >>> -bottom),
                (nonce[3] << bottom) | (nonce4 >>> -bottom)
            };
        } else if (bottom == 32) {
            return new int[]{
                nonce[1], nonce[2], nonce[3], nonce4
            };
        } else {
            return new int[]{
                (nonce[1] << bottom) | (nonce[2] >>> -bottom),
                (nonce[2] << bottom) | (nonce[3] >>> -bottom),
                (nonce[3] << bottom) | (nonce4 >>> -bottom),
                (nonce4 << bottom) | (nonce5 >>> -bottom)
            };
        }
    }

    @Override
    public EncryptEngine startEncryption(byte[] key, byte[] iv) {
        return new AbstractAuthenticaterEngine(16) {

            private final AesEncApi engine = constructor.apply(key);

            private final int[] lStar = new int[4], lDollar;
            private final int[][] lValues;

            private final int[] sum = new int[4], offset = new int[4], data = new int[4], mOffset = getOffset0(iv, engine), checksum = new int[4];

            private long counter = 0;

            {
                engine.encryptBlock(lStar, 0, lStar, 0);
                lDollar = ocbDouble(lStar);
                lValues = Stream.iterate(ocbDouble(lDollar), AesOcb::ocbDouble).limit(64).toArray(int[][]::new);
            }

            @Override
            protected void ingestOneBlock(MemorySegment aad, long off) {
                var lValue = lValues[Long.numberOfTrailingZeros(++counter)];
                offset[0] ^= lValue[0];
                offset[1] ^= lValue[1];
                offset[2] ^= lValue[2];
                offset[3] ^= lValue[3];

                data[0] = aad.get(BIG_ENDIAN_32_BIT, off + 0) ^ offset[0];
                data[1] = aad.get(BIG_ENDIAN_32_BIT, off + 4) ^ offset[1];
                data[2] = aad.get(BIG_ENDIAN_32_BIT, off + 8) ^ offset[2];
                data[3] = aad.get(BIG_ENDIAN_32_BIT, off + 12) ^ offset[3];

                engine.encryptBlock(data, 0, data, 0);

                sum[0] ^= data[0];
                sum[1] ^= data[1];
                sum[2] ^= data[2];
                sum[3] ^= data[3];
            }

            @Override
            protected void ingestLastBlock(MemorySegment aad, int length) {
                if (length == 16) {
                    ingestOneBlock(aad, 0);
                } else if (length > 0) {
                    offset[0] ^= lStar[0];
                    offset[1] ^= lStar[1];
                    offset[2] ^= lStar[2];
                    offset[3] ^= lStar[3];

                    Tools.ozpad(aad, length);

                    data[0] = aad.get(BIG_ENDIAN_32_BIT, 0) ^ offset[0];
                    data[1] = aad.get(BIG_ENDIAN_32_BIT, 4) ^ offset[1];
                    data[2] = aad.get(BIG_ENDIAN_32_BIT, 8) ^ offset[2];
                    data[3] = aad.get(BIG_ENDIAN_32_BIT, 12) ^ offset[3];

                    engine.encryptBlock(data, 0, data, 0);

                    sum[0] ^= data[0];
                    sum[1] ^= data[1];
                    sum[2] ^= data[2];
                    sum[3] ^= data[3];
                }
                counter = 0;
                System.arraycopy(mOffset, 0, offset, 0, 4);
            }

            @Override
            protected void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
                int[] lValue = lValues[Long.numberOfTrailingZeros(++counter)];
                offset[0] ^= lValue[0];
                offset[1] ^= lValue[1];
                offset[2] ^= lValue[2];
                offset[3] ^= lValue[3];

                data[0] = plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 0);
                data[1] = plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 4);
                data[2] = plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 8);
                data[3] = plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 12);

                checksum[0] ^= data[0];
                checksum[1] ^= data[1];
                checksum[2] ^= data[2];
                checksum[3] ^= data[3];

                data[0] ^= offset[0];
                data[1] ^= offset[1];
                data[2] ^= offset[2];
                data[3] ^= offset[3];

                engine.encryptBlock(data, 0, data, 0);

                ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 0, offset[0] ^ data[0]);
                ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 4, offset[1] ^ data[1]);
                ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 8, offset[2] ^ data[2]);
                ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 12, offset[3] ^ data[3]);
            }

            @Override
            protected int encryptLastBlock(MemorySegment buffer, int length, MemorySegment ciphertext) {
                if (length == 16) {
                    encryptOneBlock(buffer, 0, ciphertext, 0);
                } else if (length > 0) {
                    offset[0] ^= lStar[0];
                    offset[1] ^= lStar[1];
                    offset[2] ^= lStar[2];
                    offset[3] ^= lStar[3];

                    engine.encryptBlock(offset, 0, data, 0);

                    Tools.ozpad(buffer, length);

                    int m0 = buffer.get(BIG_ENDIAN_32_BIT, 0);
                    int m1 = buffer.get(BIG_ENDIAN_32_BIT, 4);
                    int m2 = buffer.get(BIG_ENDIAN_32_BIT, 8);
                    int m3 = buffer.get(BIG_ENDIAN_32_BIT, 12);

                    buffer.set(BIG_ENDIAN_32_BIT, 0, m0 ^ data[0]);
                    buffer.set(BIG_ENDIAN_32_BIT, 4, m1 ^ data[1]);
                    buffer.set(BIG_ENDIAN_32_BIT, 8, m2 ^ data[2]);
                    buffer.set(BIG_ENDIAN_32_BIT, 12, m3 ^ data[3]);

                    checksum[0] ^= m0;
                    checksum[1] ^= m1;
                    checksum[2] ^= m2;
                    checksum[3] ^= m3;

                    MemorySegment.copy(buffer, 0, ciphertext, 0, length);
                }
                return length;
            }

            @Override
            protected void finalizeState() {
                checksum[0] ^= offset[0] ^ lDollar[0];
                checksum[1] ^= offset[1] ^ lDollar[1];
                checksum[2] ^= offset[2] ^ lDollar[2];
                checksum[3] ^= offset[3] ^ lDollar[3];

                engine.encryptBlock(checksum, 0, checksum, 0);

                checksum[0] ^= sum[0];
                checksum[1] ^= sum[1];
                checksum[2] ^= sum[2];
                checksum[3] ^= sum[3];
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
                return AesOcb.this;
            }
        };
    }

    @Override
    public DecryptEngine startDecryption(byte[] key, byte[] iv) {
        return new AbstractVerifierEngine(16) {

            private final AesEncApi engine = constructor.apply(key);

            private final AesDecApi decEngine = engine.decrypter();

            private final int[] lStar = new int[4], lDollar;
            private final int[][] lValues;

            private final int[] sum = new int[4], offset = new int[4], data = new int[4], mOffset = getOffset0(iv, engine), checksum = new int[4];

            private long counter = 0;

            {
                engine.encryptBlock(lStar, 0, lStar, 0);
                lDollar = ocbDouble(lStar);
                lValues = Stream.iterate(ocbDouble(lDollar), AesOcb::ocbDouble).limit(64).toArray(int[][]::new);
            }

            @Override
            protected void ingestOneBlock(MemorySegment aad, long off) {
                var lValue = lValues[Long.numberOfTrailingZeros(++counter)];
                offset[0] ^= lValue[0];
                offset[1] ^= lValue[1];
                offset[2] ^= lValue[2];
                offset[3] ^= lValue[3];

                data[0] = aad.get(BIG_ENDIAN_32_BIT, off + 0) ^ offset[0];
                data[1] = aad.get(BIG_ENDIAN_32_BIT, off + 4) ^ offset[1];
                data[2] = aad.get(BIG_ENDIAN_32_BIT, off + 8) ^ offset[2];
                data[3] = aad.get(BIG_ENDIAN_32_BIT, off + 12) ^ offset[3];

                engine.encryptBlock(data, 0, data, 0);

                sum[0] ^= data[0];
                sum[1] ^= data[1];
                sum[2] ^= data[2];
                sum[3] ^= data[3];
            }

            @Override
            protected void ingestLastBlock(MemorySegment aad, int length) {
                if (length == 16) {
                    ingestOneBlock(aad, 0);
                } else if (length > 0) {
                    offset[0] ^= lStar[0];
                    offset[1] ^= lStar[1];
                    offset[2] ^= lStar[2];
                    offset[3] ^= lStar[3];

                    Tools.ozpad(aad, length);

                    data[0] = aad.get(BIG_ENDIAN_32_BIT, 0) ^ offset[0];
                    data[1] = aad.get(BIG_ENDIAN_32_BIT, 4) ^ offset[1];
                    data[2] = aad.get(BIG_ENDIAN_32_BIT, 8) ^ offset[2];
                    data[3] = aad.get(BIG_ENDIAN_32_BIT, 12) ^ offset[3];

                    engine.encryptBlock(data, 0, data, 0);

                    sum[0] ^= data[0];
                    sum[1] ^= data[1];
                    sum[2] ^= data[2];
                    sum[3] ^= data[3];
                }
                counter = 0;
                System.arraycopy(mOffset, 0, offset, 0, 4);
            }

            @Override
            protected void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset) {
                int[] lValue = lValues[Long.numberOfTrailingZeros(++counter)];
                offset[0] ^= lValue[0];
                offset[1] ^= lValue[1];
                offset[2] ^= lValue[2];
                offset[3] ^= lValue[3];

                data[0] = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 0) ^ offset[0];
                data[1] = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 4) ^ offset[1];
                data[2] = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 8) ^ offset[2];
                data[3] = ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 12) ^ offset[3];

                decEngine.decryptBlock(data, 0, data, 0);

                data[0] ^= offset[0];
                data[1] ^= offset[1];
                data[2] ^= offset[2];
                data[3] ^= offset[3];

                plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 0, data[0]);
                plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 4, data[1]);
                plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 8, data[2]);
                plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 12, data[3]);

                checksum[0] ^= data[0];
                checksum[1] ^= data[1];
                checksum[2] ^= data[2];
                checksum[3] ^= data[3];
            }

            @Override
            protected int decryptLastBlock(MemorySegment buffer, int length, MemorySegment plaintext) {
                if (length == 16) {
                    decryptOneBlock(buffer, 0, plaintext, 0);
                } else if (length > 0) {
                    offset[0] ^= lStar[0];
                    offset[1] ^= lStar[1];
                    offset[2] ^= lStar[2];
                    offset[3] ^= lStar[3];

                    engine.encryptBlock(offset, 0, data, 0);

                    buffer.set(BIG_ENDIAN_32_BIT, 0, buffer.get(BIG_ENDIAN_32_BIT, 0) ^ data[0]);
                    buffer.set(BIG_ENDIAN_32_BIT, 4, buffer.get(BIG_ENDIAN_32_BIT, 4) ^ data[1]);
                    buffer.set(BIG_ENDIAN_32_BIT, 8, buffer.get(BIG_ENDIAN_32_BIT, 8) ^ data[2]);
                    buffer.set(BIG_ENDIAN_32_BIT, 12, buffer.get(BIG_ENDIAN_32_BIT, 12) ^ data[3]);

                    Tools.ozpad(buffer, length);

                    checksum[0] ^= buffer.get(BIG_ENDIAN_32_BIT, 0);
                    checksum[1] ^= buffer.get(BIG_ENDIAN_32_BIT, 4);
                    checksum[2] ^= buffer.get(BIG_ENDIAN_32_BIT, 8);
                    checksum[3] ^= buffer.get(BIG_ENDIAN_32_BIT, 12);

                    MemorySegment.copy(buffer, 0, plaintext, 0, length);
                }
                return length;
            }

            @Override
            protected void finalizeState() {
                checksum[0] ^= offset[0] ^ lDollar[0];
                checksum[1] ^= offset[1] ^ lDollar[1];
                checksum[2] ^= offset[2] ^ lDollar[2];
                checksum[3] ^= offset[3] ^ lDollar[3];

                engine.encryptBlock(checksum, 0, checksum, 0);

                checksum[0] ^= sum[0];
                checksum[1] ^= sum[1];
                checksum[2] ^= sum[2];
                checksum[3] ^= sum[3];
            }

            @Override
            protected void generateTag(byte[] temp) {
                byte[] dest = new byte[16];
                Tools.store32BE(checksum[0], dest, 0);
                Tools.store32BE(checksum[1], dest, 4);
                Tools.store32BE(checksum[2], dest, 8);
                Tools.store32BE(checksum[3], dest, 12);

                System.arraycopy(dest, 0, temp, 0, tagLength);
            }

            @Override
            public AuthenticatedCipher getAlgorithm() {
                return AesOcb.this;
            }
        };
    }

    @Override
    public int keyLength() {
        return keyLength;
    }

    @Override
    public int ivLength() {
        return 16;
    }

    @Override
    public int tagLength() {
        return tagLength;
    }

    @Override
    public long ciphertextSize(long plaintextSize) {
        return plaintextSize;
    }

    @Override
    public long plaintextSize(long ciphertextSize) {
        return ciphertextSize;
    }

}
