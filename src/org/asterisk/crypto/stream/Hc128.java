/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.stream;

import org.asterisk.crypto.interfaces.StreamCipher;
import org.asterisk.crypto.helper.AbstractStreamEncrypter;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import org.asterisk.crypto.Tested;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.interfaces.Cipher;

import static org.asterisk.crypto.helper.Tools.load32BE;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum Hc128 implements StreamCipher {

    @Tested
    HC_128;

    private static final ValueLayout.OfInt LAYOUT = Tools.BIG_ENDIAN_32_BIT;

    private static int f1(int x) {
        return Integer.rotateRight(x, 7) ^ Integer.rotateRight(x, 18) ^ (x >>> 3);
    }

    private static int f2(int x) {
        return Integer.rotateRight(x, 17) ^ Integer.rotateRight(x, 19) ^ (x >>> 10);
    }

    private static int g1(int x, int y, int z) {
        return (Integer.rotateRight(x, 10) ^ Integer.rotateRight(z, 23)) + Integer.rotateRight(y, 8);
    }

    private static int g2(int x, int y, int z) {
        return (Integer.rotateLeft(x, 10) ^ Integer.rotateLeft(z, 23)) + Integer.rotateLeft(y, 8);
    }

    private static int[] setupP(byte[] key, byte[] iv) {
        if (key.length < 16) {
            throw new IllegalArgumentException("HC-128 requires a 16-byte key, " + key.length + " bytes provided");
        }
        if (iv.length < 16) {
            throw new IllegalArgumentException("HC-128 requires a 16-byte iv, " + iv.length + " bytes provided");
        }

        int[] P = new int[512];

        for (int i = 0; i < 4; i++) {
            P[i] = load32BE(key, 4 * i);
            P[i + 4] = P[i];
        }

        for (int i = 0; i < 4; i++) {
            P[i + 8] = load32BE(iv, 4 * i);
            P[i + 12] = P[i + 8];
        }

        for (int i = 16; i < 272; i++) {
            P[i] = f2(P[i - 2]) + P[i - 7] + f1(P[i - 15]) + P[i - 16] + i;
        }

        System.arraycopy(P, 256, P, 0, 16);

        for (int i = 16; i < 512; i++) {
            P[i] = f2(P[i - 2]) + P[i - 7] + f1(P[i - 15]) + P[i - 16] + (i + 256);
        }

        return P;
    }

    private static int[] setupQ(int[] P) {
        int[] Q = new int[512];

        System.arraycopy(P, 512 - 16, Q, 0, 16);

        for (int i = 16; i < 32; i++) {
            Q[i] = f2(Q[i - 2]) + Q[i - 7] + f1(Q[i - 15]) + Q[i - 16] + (i + 768 - 16);
        }

        System.arraycopy(Q, 16, Q, 0, 16);

        for (int i = 16; i < 512; i++) {
            Q[i] = f2(Q[i - 2]) + Q[i - 7] + f1(Q[i - 15]) + Q[i - 16] + (i + 768);
        }

        return Q;
    }

    @Override
    public EncryptEngine startEncryption(byte[] key, byte[] iv) {
        return new AbstractStreamEncrypter(64) {

            private final int[] P = setupP(key, iv);

            private final int[] Q = setupQ(P);

            private final int[] X = new int[16], Y = new int[16];

            private int counter = 0;

            {
                for (int i = 0; i < 511; i++) {
                    P[i] = (P[i] + g1(P[(i - 3) & 0x1ff], P[(i - 10) & 0x1ff], P[i + 1])) ^ h1(P[(i - 12) & 0x1ff]);
                }
                P[511] = (P[511] + g1(P[508], P[501], P[0])) ^ h1(P[499]);

                for (int i = 0; i < 511; i++) {
                    Q[i] = (Q[i] + g2(Q[(i - 3) & 0x1ff], Q[(i - 10) & 0x1ff], Q[i + 1])) ^ h2(Q[(i - 12) & 0x1ff]);
                }
                Q[511] = (Q[511] + g2(Q[508], Q[501], Q[0])) ^ h2(Q[499]);

                System.arraycopy(P, 512 - 16, X, 0, 16);
                System.arraycopy(Q, 512 - 16, Y, 0, 16);
            }

            private int h1(int x) {
                return Q[(x) & 0xff] + Q[0x100 | ((x >>> 16) & 0xff)];
            }

            private int h2(int x) {
                return P[(x) & 0xff] + P[0x100 | ((x >>> 16) & 0xff)];
            }

            @Override
            protected void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
                int j = counter & 0x1ff;
                if ((counter & 0x200) == 0) {
                    P[j + 0] += g1(X[13], X[6], P[j + 1]);
                    X[0] = P[j + 0];
                    ciphertext.set(LAYOUT, cOffset + 0, plaintext.get(LAYOUT, pOffset + 0) ^ h1(X[4]) ^ X[0]);

                    P[j + 1] += g1(X[14], X[7], P[j + 2]);
                    X[1] = P[j + 1];
                    ciphertext.set(LAYOUT, cOffset + 4, plaintext.get(LAYOUT, pOffset + 4) ^ h1(X[5]) ^ X[1]);

                    P[j + 2] += g1(X[15], X[8], P[j + 3]);
                    X[2] = P[j + 2];
                    ciphertext.set(LAYOUT, cOffset + 8, plaintext.get(LAYOUT, pOffset + 8) ^ h1(X[6]) ^ X[2]);

                    P[j + 3] += g1(X[0], X[9], P[j + 4]);
                    X[3] = P[j + 3];
                    ciphertext.set(LAYOUT, cOffset + 12, plaintext.get(LAYOUT, pOffset + 12) ^ h1(X[7]) ^ X[3]);

                    P[j + 4] += g1(X[1], X[10], P[j + 5]);
                    X[4] = P[j + 4];
                    ciphertext.set(LAYOUT, cOffset + 16, plaintext.get(LAYOUT, pOffset + 16) ^ h1(X[8]) ^ X[4]);

                    P[j + 5] += g1(X[2], X[11], P[j + 6]);
                    X[5] = P[j + 5];
                    ciphertext.set(LAYOUT, cOffset + 20, plaintext.get(LAYOUT, pOffset + 20) ^ h1(X[9]) ^ X[5]);

                    P[j + 6] += g1(X[3], X[12], P[j + 7]);
                    X[6] = P[j + 6];
                    ciphertext.set(LAYOUT, cOffset + 24, plaintext.get(LAYOUT, pOffset + 24) ^ h1(X[10]) ^ X[6]);

                    P[j + 7] += g1(X[4], X[13], P[j + 8]);
                    X[7] = P[j + 7];
                    ciphertext.set(LAYOUT, cOffset + 28, plaintext.get(LAYOUT, pOffset + 28) ^ h1(X[11]) ^ X[7]);

                    P[j + 8] += g1(X[5], X[14], P[j + 9]);
                    X[8] = P[j + 8];
                    ciphertext.set(LAYOUT, cOffset + 32, plaintext.get(LAYOUT, pOffset + 32) ^ h1(X[12]) ^ X[8]);

                    P[j + 9] += g1(X[6], X[15], P[j + 10]);
                    X[9] = P[j + 9];
                    ciphertext.set(LAYOUT, cOffset + 36, plaintext.get(LAYOUT, pOffset + 36) ^ h1(X[13]) ^ X[9]);

                    P[j + 10] += g1(X[7], X[0], P[j + 11]);
                    X[10] = P[j + 10];
                    ciphertext.set(LAYOUT, cOffset + 40, plaintext.get(LAYOUT, pOffset + 40) ^ h1(X[14]) ^ X[10]);

                    P[j + 11] += g1(X[8], X[1], P[j + 12]);
                    X[11] = P[j + 11];
                    ciphertext.set(LAYOUT, cOffset + 44, plaintext.get(LAYOUT, pOffset + 44) ^ h1(X[15]) ^ X[11]);

                    P[j + 12] += g1(X[9], X[2], P[j + 13]);
                    X[12] = P[j + 12];
                    ciphertext.set(LAYOUT, cOffset + 48, plaintext.get(LAYOUT, pOffset + 48) ^ h1(X[0]) ^ X[12]);

                    P[j + 13] += g1(X[10], X[3], P[j + 14]);
                    X[13] = P[j + 13];
                    ciphertext.set(LAYOUT, cOffset + 52, plaintext.get(LAYOUT, pOffset + 52) ^ h1(X[1]) ^ X[13]);

                    P[j + 14] += g1(X[11], X[4], P[j + 15]);
                    X[14] = P[j + 14];
                    ciphertext.set(LAYOUT, cOffset + 56, plaintext.get(LAYOUT, pOffset + 56) ^ h1(X[2]) ^ X[14]);

                    P[j + 15] += g1(X[12], X[5], P[(j + 16) & 0x1ff]);
                    X[15] = P[j + 15];
                    ciphertext.set(LAYOUT, cOffset + 60, plaintext.get(LAYOUT, pOffset + 60) ^ h1(X[3]) ^ X[15]);

                } else {

                    Q[j + 0] += g2(Y[13], Y[6], Q[j + 1]);
                    Y[0] = Q[j + 0];
                    ciphertext.set(LAYOUT, cOffset + 0, plaintext.get(LAYOUT, pOffset + 0) ^ h2(Y[4]) ^ Y[0]);

                    Q[j + 1] += g2(Y[14], Y[7], Q[j + 2]);
                    Y[1] = Q[j + 1];
                    ciphertext.set(LAYOUT, cOffset + 4, plaintext.get(LAYOUT, pOffset + 4) ^ h2(Y[5]) ^ Y[1]);

                    Q[j + 2] += g2(Y[15], Y[8], Q[j + 3]);
                    Y[2] = Q[j + 2];
                    ciphertext.set(LAYOUT, cOffset + 8, plaintext.get(LAYOUT, pOffset + 8) ^ h2(Y[6]) ^ Y[2]);

                    Q[j + 3] += g2(Y[0], Y[9], Q[j + 4]);
                    Y[3] = Q[j + 3];
                    ciphertext.set(LAYOUT, cOffset + 12, plaintext.get(LAYOUT, pOffset + 12) ^ h2(Y[7]) ^ Y[3]);

                    Q[j + 4] += g2(Y[1], Y[10], Q[j + 5]);
                    Y[4] = Q[j + 4];
                    ciphertext.set(LAYOUT, cOffset + 16, plaintext.get(LAYOUT, pOffset + 16) ^ h2(Y[8]) ^ Y[4]);

                    Q[j + 5] += g2(Y[2], Y[11], Q[j + 6]);
                    Y[5] = Q[j + 5];
                    ciphertext.set(LAYOUT, cOffset + 20, plaintext.get(LAYOUT, pOffset + 20) ^ h2(Y[9]) ^ Y[5]);

                    Q[j + 6] += g2(Y[3], Y[12], Q[j + 7]);
                    Y[6] = Q[j + 6];
                    ciphertext.set(LAYOUT, cOffset + 24, plaintext.get(LAYOUT, pOffset + 24) ^ h2(Y[10]) ^ Y[6]);

                    Q[j + 7] += g2(Y[4], Y[13], Q[j + 8]);
                    Y[7] = Q[j + 7];
                    ciphertext.set(LAYOUT, cOffset + 28, plaintext.get(LAYOUT, pOffset + 28) ^ h2(Y[11]) ^ Y[7]);

                    Q[j + 8] += g2(Y[5], Y[14], Q[j + 9]);
                    Y[8] = Q[j + 8];
                    ciphertext.set(LAYOUT, cOffset + 32, plaintext.get(LAYOUT, pOffset + 32) ^ h2(Y[12]) ^ Y[8]);

                    Q[j + 9] += g2(Y[6], Y[15], Q[j + 10]);
                    Y[9] = Q[j + 9];
                    ciphertext.set(LAYOUT, cOffset + 36, plaintext.get(LAYOUT, pOffset + 36) ^ h2(Y[13]) ^ Y[9]);

                    Q[j + 10] += g2(Y[7], Y[0], Q[j + 11]);
                    Y[10] = Q[j + 10];
                    ciphertext.set(LAYOUT, cOffset + 40, plaintext.get(LAYOUT, pOffset + 40) ^ h2(Y[14]) ^ Y[10]);

                    Q[j + 11] += g2(Y[8], Y[1], Q[j + 12]);
                    Y[11] = Q[j + 11];
                    ciphertext.set(LAYOUT, cOffset + 44, plaintext.get(LAYOUT, pOffset + 44) ^ h2(Y[15]) ^ Y[11]);

                    Q[j + 12] += g2(Y[9], Y[2], Q[j + 13]);
                    Y[12] = Q[j + 12];
                    ciphertext.set(LAYOUT, cOffset + 48, plaintext.get(LAYOUT, pOffset + 48) ^ h2(Y[0]) ^ Y[12]);

                    Q[j + 13] += g2(Y[10], Y[3], Q[j + 14]);
                    Y[13] = Q[j + 13];
                    ciphertext.set(LAYOUT, cOffset + 52, plaintext.get(LAYOUT, pOffset + 52) ^ h2(Y[1]) ^ Y[13]);

                    Q[j + 14] += g2(Y[11], Y[4], Q[j + 15]);
                    Y[14] = Q[j + 14];
                    ciphertext.set(LAYOUT, cOffset + 56, plaintext.get(LAYOUT, pOffset + 56) ^ h2(Y[2]) ^ Y[14]);

                    Q[j + 15] += g2(Y[12], Y[5], Q[(j + 16) & 0x1ff]);
                    Y[15] = Q[j + 15];
                    ciphertext.set(LAYOUT, cOffset + 60, plaintext.get(LAYOUT, pOffset + 60) ^ h2(Y[3]) ^ Y[15]);
                }
                counter += 16;
            }

            @Override
            public Cipher getAlgorithm() {
                return HC_128;
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

}
