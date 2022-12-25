/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.stream;

import org.asterisk.crypto.interfaces.StreamCipher;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import org.asterisk.crypto.helper.AbstractStreamEncrypter;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.interfaces.Cipher;

import static org.asterisk.crypto.lowlevel.AesPermutation.aesRound;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum SnowV implements StreamCipher {

    SNOW_V;

    private static final ValueLayout.OfInt LAYOUT = Tools.LITTLE_ENDIAN_32_BIT;

    private static int mulx(int x) {
        return ((x >> 15) & 0x990f0000) ^ (((x << 16) >> 31) & 0x990f) ^ ((x << 1) & 0xfffefffe);
    }

    private static int divx(int x) {
        return (-(x & 0x10000) & 0xcc870000) ^ (-(x & 1) & 0xcc87) ^ ((x >>> 1) & 0x7fff7fff);
    }

    private static int muly(int x) {
        return ((x >> 15) & 0xc9630000) ^ (((x << 16) >> 31) & 0xc963) ^ ((x << 1) & 0xfffefffe);
    }

    private static int divy(int x) {
        return (-(x & 0x10000) & 0xe4b10000) ^ (-(x & 1) & 0xe4b1) ^ ((x >>> 1) & 0x7fff7fff);
    }

    private static void permute(int[] dst, int src0, int src1, int src2, int src3) {
        dst[0] = ((src0 & 0xff000000))
                | ((src1 & 0xff000000) >>> 8)
                | ((src2 & 0xff000000) >>> 16)
                | ((src3 & 0xff000000) >>> 24);
        dst[1] = ((src0 & 0xff0000) << 8)
                | ((src1 & 0xff0000))
                | ((src2 & 0xff0000) >>> 8)
                | ((src3 & 0xff0000) >>> 16);
        dst[2] = ((src0 & 0xff00) << 16)
                | ((src1 & 0xff00) << 8)
                | ((src2 & 0xff00))
                | ((src3 & 0xff00) >>> 8);
        dst[3] = ((src0 & 0xff) << 24)
                | ((src1 & 0xff) << 16)
                | ((src2 & 0xff) << 8)
                | ((src3 & 0xff));
    }

    private static void fsmUpdate(int[] register, int a0, int a1, int a2, int a3) {
        a0 = (a0 ^ register[8]) + register[4];
        a1 = (a1 ^ register[9]) + register[5];
        a2 = (a2 ^ register[10]) + register[6];
        a3 = (a3 ^ register[11]) + register[7];

        aesRound(register, 4, register, 8, 0, 0, 0, 0);
        aesRound(register, 0, register, 4, 0, 0, 0, 0);
        permute(register, a0, a1, a2, a3);
    }

    private static void initRound(int[] a, int[] b, int[] register) {

        int a8 = mulx(a[0]) ^ ((a[0] >>> 16) | (a[1] << 16)) ^ divx(a[4]) ^ b[0] ^ (b[4] + register[0]) ^ register[4];
        int a9 = mulx(a[1]) ^ ((a[1] >>> 16) | (a[2] << 16)) ^ divx(a[5]) ^ b[1] ^ (b[5] + register[1]) ^ register[5];
        int a10 = mulx(a[2]) ^ ((a[2] >>> 16) | (a[3] << 16)) ^ divx(a[6]) ^ b[2] ^ (b[6] + register[2]) ^ register[6];
        int a11 = mulx(a[3]) ^ ((a[3] >>> 16) | (a[4] << 16)) ^ divx(a[7]) ^ b[3] ^ (b[7] + register[3]) ^ register[7];

        int b8 = muly(b[0]) ^ ((b[1] >>> 16) | (b[2] << 16)) ^ divy(b[4]) ^ a[0];
        int b9 = muly(b[1]) ^ ((b[2] >>> 16) | (b[3] << 16)) ^ divy(b[5]) ^ a[1];
        int b10 = muly(b[2]) ^ ((b[3] >>> 16) | (b[4] << 16)) ^ divy(b[6]) ^ a[2];
        int b11 = muly(b[3]) ^ ((b[4] >>> 16) | (b[5] << 16)) ^ divy(b[7]) ^ a[3];

        fsmUpdate(register, a[0], a[1], a[2], a[3]);

        int a12 = mulx(a[4]) ^ ((a[4] >>> 16) | (a[5] << 16)) ^ divx(a8) ^ b[4] ^ (b8 + register[0]) ^ register[4];
        int a13 = mulx(a[5]) ^ ((a[5] >>> 16) | (a[6] << 16)) ^ divx(a9) ^ b[5] ^ (b9 + register[0]) ^ register[4];
        int a14 = mulx(a[6]) ^ ((a[6] >>> 16) | (a[7] << 16)) ^ divx(a10) ^ b[6] ^ (b10 + register[0]) ^ register[4];
        int a15 = mulx(a[7]) ^ ((a[7] >>> 16) | (a8 << 16)) ^ divx(a11) ^ b[7] ^ (b11 + register[0]) ^ register[4];

        int b12 = muly(b[4]) ^ ((b[5] >>> 16) | (b[6] << 16)) ^ divy(b8) ^ a[4];
        int b13 = muly(b[5]) ^ ((b[6] >>> 16) | (b[7] << 16)) ^ divy(b9) ^ a[5];
        int b14 = muly(b[6]) ^ ((b[7] >>> 16) | (b8 << 16)) ^ divy(b10) ^ a[6];
        int b15 = muly(b[7]) ^ ((b8 >>> 16) | (b9 << 16)) ^ divy(b11) ^ a[7];

        fsmUpdate(register, a[4], a[5], a[6], a[7]);

        a[0] = mulx(a8) ^ ((a8 >>> 16) | (a9 << 16)) ^ divx(a12) ^ b8 ^ (b12 + register[0]) ^ register[4];
        a[1] = mulx(a9) ^ ((a9 >>> 16) | (a10 << 16)) ^ divx(a13) ^ b9 ^ (b13 + register[0]) ^ register[4];
        a[2] = mulx(a10) ^ ((a10 >>> 16) | (a11 << 16)) ^ divx(a14) ^ b10 ^ (b14 + register[0]) ^ register[4];
        a[3] = mulx(a11) ^ ((a11 >>> 16) | (a12 << 16)) ^ divx(a15) ^ b11 ^ (b15 + register[0]) ^ register[4];

        b[0] = muly(b8) ^ ((b9 >>> 16) | (b10 << 16)) ^ divy(b12) ^ a8;
        b[1] = muly(b9) ^ ((b10 >>> 16) | (b11 << 16)) ^ divy(b13) ^ a9;
        b[2] = muly(b10) ^ ((b11 >>> 16) | (b12 << 16)) ^ divy(b14) ^ a10;
        b[3] = muly(b11) ^ ((b12 >>> 16) | (b13 << 16)) ^ divy(b15) ^ a11;

        fsmUpdate(register, a8, a9, a10, a11);

        a[4] = mulx(a12) ^ ((a12 >>> 16) | (a13 << 16)) ^ divx(a[0]) ^ b12 ^ (b[0] + register[0]) ^ register[4];
        a[5] = mulx(a13) ^ ((a13 >>> 16) | (a14 << 16)) ^ divx(a[1]) ^ b13 ^ (b[1] + register[0]) ^ register[4];
        a[6] = mulx(a14) ^ ((a14 >>> 16) | (a15 << 16)) ^ divx(a[2]) ^ b14 ^ (b[2] + register[0]) ^ register[4];
        a[7] = mulx(a15) ^ ((a15 >>> 16) | (a[0] << 16)) ^ divx(a[3]) ^ b15 ^ (b[3] + register[0]) ^ register[4];

        b[4] = muly(b12) ^ ((b13 >>> 16) | (b14 << 16)) ^ divy(b[0]) ^ a12;
        b[5] = muly(b13) ^ ((b14 >>> 16) | (b15 << 16)) ^ divy(b[1]) ^ a13;
        b[6] = muly(b14) ^ ((b15 >>> 16) | (b[0] << 16)) ^ divy(b[2]) ^ a14;
        b[7] = muly(b15) ^ ((b[0] >>> 16) | (b[1] << 16)) ^ divy(b[3]) ^ a15;

        fsmUpdate(register, a12, a13, a14, a15);
    }

    private static void initRoundLast(int[] a, int[] b, int[] register, int k0, int k1, int k2, int k3, int k4, int k5, int k6, int k7) {

        int a8 = mulx(a[0]) ^ ((a[0] >>> 16) | (a[1] << 16)) ^ divx(a[4]) ^ b[0] ^ (b[4] + register[0]) ^ register[4];
        int a9 = mulx(a[1]) ^ ((a[1] >>> 16) | (a[2] << 16)) ^ divx(a[5]) ^ b[1] ^ (b[5] + register[1]) ^ register[5];
        int a10 = mulx(a[2]) ^ ((a[2] >>> 16) | (a[3] << 16)) ^ divx(a[6]) ^ b[2] ^ (b[6] + register[2]) ^ register[6];
        int a11 = mulx(a[3]) ^ ((a[3] >>> 16) | (a[4] << 16)) ^ divx(a[7]) ^ b[3] ^ (b[7] + register[3]) ^ register[7];

        int b8 = muly(b[0]) ^ ((b[1] >>> 16) | (b[2] << 16)) ^ divy(b[4]) ^ a[0];
        int b9 = muly(b[1]) ^ ((b[2] >>> 16) | (b[3] << 16)) ^ divy(b[5]) ^ a[1];
        int b10 = muly(b[2]) ^ ((b[3] >>> 16) | (b[4] << 16)) ^ divy(b[6]) ^ a[2];
        int b11 = muly(b[3]) ^ ((b[4] >>> 16) | (b[5] << 16)) ^ divy(b[7]) ^ a[3];

        fsmUpdate(register, a[0], a[1], a[2], a[3]);

        int a12 = mulx(a[4]) ^ ((a[4] >>> 16) | (a[5] << 16)) ^ divx(a8) ^ b[4] ^ (b8 + register[0]) ^ register[4];
        int a13 = mulx(a[5]) ^ ((a[5] >>> 16) | (a[6] << 16)) ^ divx(a9) ^ b[5] ^ (b9 + register[0]) ^ register[4];
        int a14 = mulx(a[6]) ^ ((a[6] >>> 16) | (a[7] << 16)) ^ divx(a10) ^ b[6] ^ (b10 + register[0]) ^ register[4];
        int a15 = mulx(a[7]) ^ ((a[7] >>> 16) | (a8 << 16)) ^ divx(a11) ^ b[7] ^ (b11 + register[0]) ^ register[4];

        int b12 = muly(b[4]) ^ ((b[5] >>> 16) | (b[6] << 16)) ^ divy(b8) ^ a[4];
        int b13 = muly(b[5]) ^ ((b[6] >>> 16) | (b[7] << 16)) ^ divy(b9) ^ a[5];
        int b14 = muly(b[6]) ^ ((b[7] >>> 16) | (b8 << 16)) ^ divy(b10) ^ a[6];
        int b15 = muly(b[7]) ^ ((b8 >>> 16) | (b9 << 16)) ^ divy(b11) ^ a[7];

        fsmUpdate(register, a[4], a[5], a[6], a[7]);

        a[0] = mulx(a8) ^ ((a8 >>> 16) | (a9 << 16)) ^ divx(a12) ^ b8 ^ (b12 + register[0]) ^ register[4];
        a[1] = mulx(a9) ^ ((a9 >>> 16) | (a10 << 16)) ^ divx(a13) ^ b9 ^ (b13 + register[0]) ^ register[4];
        a[2] = mulx(a10) ^ ((a10 >>> 16) | (a11 << 16)) ^ divx(a14) ^ b10 ^ (b14 + register[0]) ^ register[4];
        a[3] = mulx(a11) ^ ((a11 >>> 16) | (a12 << 16)) ^ divx(a15) ^ b11 ^ (b15 + register[0]) ^ register[4];

        b[0] = muly(b8) ^ ((b9 >>> 16) | (b10 << 16)) ^ divy(b12) ^ a8;
        b[1] = muly(b9) ^ ((b10 >>> 16) | (b11 << 16)) ^ divy(b13) ^ a9;
        b[2] = muly(b10) ^ ((b11 >>> 16) | (b12 << 16)) ^ divy(b14) ^ a10;
        b[3] = muly(b11) ^ ((b12 >>> 16) | (b13 << 16)) ^ divy(b15) ^ a11;

        fsmUpdate(register, a8, a9, a10, a11);

        register[0] ^= k0;
        register[1] ^= k1;
        register[2] ^= k2;
        register[3] ^= k3;

        a[4] = mulx(a12) ^ ((a12 >>> 16) | (a13 << 16)) ^ divx(a[0]) ^ b12 ^ (b[0] + register[0]) ^ register[4];
        a[5] = mulx(a13) ^ ((a13 >>> 16) | (a14 << 16)) ^ divx(a[1]) ^ b13 ^ (b[1] + register[0]) ^ register[4];
        a[6] = mulx(a14) ^ ((a14 >>> 16) | (a15 << 16)) ^ divx(a[2]) ^ b14 ^ (b[2] + register[0]) ^ register[4];
        a[7] = mulx(a15) ^ ((a15 >>> 16) | (a[0] << 16)) ^ divx(a[3]) ^ b15 ^ (b[3] + register[0]) ^ register[4];

        b[4] = muly(b12) ^ ((b13 >>> 16) | (b14 << 16)) ^ divy(b[0]) ^ a12;
        b[5] = muly(b13) ^ ((b14 >>> 16) | (b15 << 16)) ^ divy(b[1]) ^ a13;
        b[6] = muly(b14) ^ ((b15 >>> 16) | (b[0] << 16)) ^ divy(b[2]) ^ a14;
        b[7] = muly(b15) ^ ((b[0] >>> 16) | (b[1] << 16)) ^ divy(b[3]) ^ a15;

        fsmUpdate(register, a12, a13, a14, a15);

        register[0] ^= k4;
        register[1] ^= k5;
        register[2] ^= k6;
        register[3] ^= k7;
    }

    private static void keystream(int[] a, int[] b, int[] register, int[] buffer) {

        buffer[0] = (b[4] + register[0]) ^ register[4];
        buffer[1] = (b[5] + register[1]) ^ register[5];
        buffer[2] = (b[6] + register[2]) ^ register[6];
        buffer[3] = (b[7] + register[3]) ^ register[7];

        int a8 = mulx(a[0]) ^ ((a[0] >>> 16) | (a[1] << 16)) ^ divx(a[4]) ^ b[0];
        int a9 = mulx(a[1]) ^ ((a[1] >>> 16) | (a[2] << 16)) ^ divx(a[5]) ^ b[1];
        int a10 = mulx(a[2]) ^ ((a[2] >>> 16) | (a[3] << 16)) ^ divx(a[6]) ^ b[2];
        int a11 = mulx(a[3]) ^ ((a[3] >>> 16) | (a[4] << 16)) ^ divx(a[7]) ^ b[3];

        int b8 = muly(b[0]) ^ ((b[1] >>> 16) | (b[2] << 16)) ^ divy(b[4]) ^ a[0];
        int b9 = muly(b[1]) ^ ((b[2] >>> 16) | (b[3] << 16)) ^ divy(b[5]) ^ a[1];
        int b10 = muly(b[2]) ^ ((b[3] >>> 16) | (b[4] << 16)) ^ divy(b[6]) ^ a[2];
        int b11 = muly(b[3]) ^ ((b[4] >>> 16) | (b[5] << 16)) ^ divy(b[7]) ^ a[3];

        fsmUpdate(register, a[0], a[1], a[2], a[3]);

        buffer[4] = (b8 + register[0]) ^ register[4];
        buffer[5] = (b9 + register[1]) ^ register[5];
        buffer[6] = (b10 + register[2]) ^ register[6];
        buffer[7] = (b11 + register[3]) ^ register[7];

        int a12 = mulx(a[4]) ^ ((a[4] >>> 16) | (a[5] << 16)) ^ divx(a8) ^ b[4];
        int a13 = mulx(a[5]) ^ ((a[5] >>> 16) | (a[6] << 16)) ^ divx(a9) ^ b[5];
        int a14 = mulx(a[6]) ^ ((a[6] >>> 16) | (a[7] << 16)) ^ divx(a10) ^ b[6];
        int a15 = mulx(a[7]) ^ ((a[7] >>> 16) | (a8 << 16)) ^ divx(a11) ^ b[7];

        int b12 = muly(b[4]) ^ ((b[5] >>> 16) | (b[6] << 16)) ^ divy(b8) ^ a[4];
        int b13 = muly(b[5]) ^ ((b[6] >>> 16) | (b[7] << 16)) ^ divy(b9) ^ a[5];
        int b14 = muly(b[6]) ^ ((b[7] >>> 16) | (b8 << 16)) ^ divy(b10) ^ a[6];
        int b15 = muly(b[7]) ^ ((b8 >>> 16) | (b9 << 16)) ^ divy(b11) ^ a[7];

        fsmUpdate(register, a[4], a[5], a[6], a[7]);

        buffer[8] = (b12 + register[0]) ^ register[4];
        buffer[9] = (b13 + register[1]) ^ register[5];
        buffer[10] = (b14 + register[2]) ^ register[6];
        buffer[11] = (b15 + register[3]) ^ register[7];

        a[0] = mulx(a8) ^ ((a8 >>> 16) | (a9 << 16)) ^ divx(a12) ^ b8;
        a[1] = mulx(a9) ^ ((a9 >>> 16) | (a10 << 16)) ^ divx(a13) ^ b9;
        a[2] = mulx(a10) ^ ((a10 >>> 16) | (a11 << 16)) ^ divx(a14) ^ b10;
        a[3] = mulx(a11) ^ ((a11 >>> 16) | (a12 << 16)) ^ divx(a15) ^ b11;

        b[0] = muly(b8) ^ ((b9 >>> 16) | (b10 << 16)) ^ divy(b12) ^ a8;
        b[1] = muly(b9) ^ ((b10 >>> 16) | (b11 << 16)) ^ divy(b13) ^ a9;
        b[2] = muly(b10) ^ ((b11 >>> 16) | (b12 << 16)) ^ divy(b14) ^ a10;
        b[3] = muly(b11) ^ ((b12 >>> 16) | (b13 << 16)) ^ divy(b15) ^ a11;

        fsmUpdate(register, a8, a9, a10, a11);

        buffer[12] = (b[0] + register[0]) ^ register[4];
        buffer[13] = (b[1] + register[1]) ^ register[5];
        buffer[14] = (b[2] + register[2]) ^ register[6];
        buffer[15] = (b[3] + register[3]) ^ register[7];

        a[4] = mulx(a12) ^ ((a12 >>> 16) | (a13 << 16)) ^ divx(a[0]) ^ b12;
        a[5] = mulx(a13) ^ ((a13 >>> 16) | (a14 << 16)) ^ divx(a[1]) ^ b13;
        a[6] = mulx(a14) ^ ((a14 >>> 16) | (a15 << 16)) ^ divx(a[2]) ^ b14;
        a[7] = mulx(a15) ^ ((a15 >>> 16) | (a[0] << 16)) ^ divx(a[3]) ^ b15;

        b[4] = muly(b12) ^ ((b13 >>> 16) | (b14 << 16)) ^ divy(b[0]) ^ a12;
        b[5] = muly(b13) ^ ((b14 >>> 16) | (b15 << 16)) ^ divy(b[1]) ^ a13;
        b[6] = muly(b14) ^ ((b15 >>> 16) | (b[0] << 16)) ^ divy(b[2]) ^ a14;
        b[7] = muly(b15) ^ ((b[0] >>> 16) | (b[1] << 16)) ^ divy(b[3]) ^ a15;

        fsmUpdate(register, a12, a13, a14, a15);

    }

    @Override
    public EncryptEngine startEncryption(byte[] key, byte[] iv) {
        if (key.length < 32) {
            throw new IllegalArgumentException("SNOW-V requires a 32 byte key, " + key.length + " bytes provided!");
        }
        if (iv.length < 16) {
            throw new IllegalArgumentException("SNOW-V requires a 16 byte iv, " + iv.length + " bytes provided!");
        }

        return new AbstractStreamEncrypter(64) {

            private final int[] a, b, register = new int[12], buffer = new int[16];

            {
                int k0 = Tools.load32LE(key, 0);
                int k1 = Tools.load32LE(key, 4);
                int k2 = Tools.load32LE(key, 8);
                int k3 = Tools.load32LE(key, 12);
                int k4 = Tools.load32LE(key, 16);
                int k5 = Tools.load32LE(key, 20);
                int k6 = Tools.load32LE(key, 24);
                int k7 = Tools.load32LE(key, 28);

                a = new int[]{
                    Tools.load32BE(iv, 0), Tools.load32BE(iv, 4), Tools.load32BE(iv, 8), Tools.load32BE(iv, 12),
                    k0, k1, k2, k3
                };

                b = new int[]{
                    0, 0, 0, 0,
                    k4, k5, k6, k7
                };

                initRound(a, b, register);
                initRound(a, b, register);
                initRound(a, b, register);

                initRoundLast(a, b, register, k0, k1, k2, k3, k4, k5, k6, k7);
            }

            @Override
            protected void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
                keystream(a, b, register, buffer);

                ciphertext.set(LAYOUT, cOffset + 0, plaintext.get(LAYOUT, pOffset + 0) ^ buffer[0]);
                ciphertext.set(LAYOUT, cOffset + 4, plaintext.get(LAYOUT, pOffset + 4) ^ buffer[1]);
                ciphertext.set(LAYOUT, cOffset + 8, plaintext.get(LAYOUT, pOffset + 8) ^ buffer[2]);
                ciphertext.set(LAYOUT, cOffset + 12, plaintext.get(LAYOUT, pOffset + 12) ^ buffer[3]);
                ciphertext.set(LAYOUT, cOffset + 16, plaintext.get(LAYOUT, pOffset + 16) ^ buffer[4]);
                ciphertext.set(LAYOUT, cOffset + 20, plaintext.get(LAYOUT, pOffset + 20) ^ buffer[5]);
                ciphertext.set(LAYOUT, cOffset + 24, plaintext.get(LAYOUT, pOffset + 24) ^ buffer[6]);
                ciphertext.set(LAYOUT, cOffset + 28, plaintext.get(LAYOUT, pOffset + 28) ^ buffer[7]);
                ciphertext.set(LAYOUT, cOffset + 32, plaintext.get(LAYOUT, pOffset + 32) ^ buffer[8]);
                ciphertext.set(LAYOUT, cOffset + 36, plaintext.get(LAYOUT, pOffset + 36) ^ buffer[9]);
                ciphertext.set(LAYOUT, cOffset + 40, plaintext.get(LAYOUT, pOffset + 40) ^ buffer[10]);
                ciphertext.set(LAYOUT, cOffset + 44, plaintext.get(LAYOUT, pOffset + 44) ^ buffer[11]);
                ciphertext.set(LAYOUT, cOffset + 48, plaintext.get(LAYOUT, pOffset + 48) ^ buffer[12]);
                ciphertext.set(LAYOUT, cOffset + 52, plaintext.get(LAYOUT, pOffset + 52) ^ buffer[13]);
                ciphertext.set(LAYOUT, cOffset + 56, plaintext.get(LAYOUT, pOffset + 56) ^ buffer[14]);
                ciphertext.set(LAYOUT, cOffset + 60, plaintext.get(LAYOUT, pOffset + 60) ^ buffer[15]);
            }

            @Override
            public Cipher getAlgorithm() {
                return SNOW_V;
            }
        };
    }

    @Override
    public int keyLength() {
        return 32;
    }

    @Override
    public int ivLength() {
        return 16;
    }

}
