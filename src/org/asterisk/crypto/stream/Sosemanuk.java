/*
 * Copyright (C) 2023 Sayantan Chakraborty
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
package org.asterisk.crypto.stream;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import org.asterisk.crypto.helper.AbstractStreamEncrypter;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.interfaces.Cipher;
import org.asterisk.crypto.interfaces.StreamCipher;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum Sosemanuk implements StreamCipher {

    SOSEMANUK;

    private static final ValueLayout.OfInt LAYOUT = Tools.BIG_ENDIAN_32_BIT;

    private static final int CONST = 0x54655307;

    private static final int[] MUL_A = new int[256], DIV_A = new int[256];

    private static void keystream(int[] state, int[] register, int[] keystream) {
        int s0 = state[0], s1 = state[1], s2 = state[2], s3 = state[3], s4 = state[4];
        int s5 = state[5], s6 = state[6], s7 = state[7], s8 = state[8], s9 = state[9];
        int r1 = register[0], r2 = register[1];

        int tt, f0, f1, f2, f3, f4;

        tt = r1;
        r1 = r2 + s1 ^ (-(r1 & 1) & s8);
        r2 = Integer.rotateLeft(tt * CONST, 7);
        int s10 = ((s0 << 8) ^ MUL_A[s0 & 0xff]) ^ ((s3 >>> 8) ^ DIV_A[s3 & 0xff]) ^ s9;
        f0 = (s9 + r1) ^ r2;

        tt = r1;
        r1 = r2 + s2 ^ (-(r1 & 1) & s9);
        r2 = Integer.rotateLeft(tt * CONST, 7);
        int s11 = ((s1 << 8) ^ MUL_A[s1 & 0xff]) ^ ((s4 >>> 8) ^ DIV_A[s4 & 0xff]) ^ s10;
        f1 = (s10 + r1) ^ r2;

        tt = r1;
        r1 = r2 + s3 ^ (-(r1 & 1) & s10);
        r2 = Integer.rotateLeft(tt * CONST, 7);
        int s12 = ((s2 << 8) ^ MUL_A[s2 & 0xff]) ^ ((s5 >>> 8) ^ DIV_A[s5 & 0xff]) ^ s11;
        f2 = (s11 + r1) ^ r2;

        tt = r1;
        r1 = r2 + s4 ^ (-(r1 & 1) & s11);
        r2 = Integer.rotateLeft(tt * CONST, 7);
        int s13 = ((s3 << 8) ^ MUL_A[s3 & 0xff]) ^ ((s6 >>> 8) ^ DIV_A[s6 & 0xff]) ^ s12;
        f3 = (s12 + r1) ^ r2;

        f4 = f0;
        f0 = (f0 & f2) ^ f3;
        f2 ^= f0 ^ f1;
        f3 = (f3 | f4) ^ f1;
        f4 ^= f2;
        f1 = f3;
        f3 = (f3 | f4) ^ f0;
        f4 ^= f0 & f1;

        keystream[0] = f2 ^ s0;
        keystream[1] = f3 ^ s1;
        keystream[2] = f1 ^ f3 ^ f4 ^ s2;
        keystream[3] = ~f4 ^ s3;

        tt = r1;
        r1 = r2 + s5 ^ (-(r1 & 1) & s12);
        r2 = Integer.rotateLeft(tt * CONST, 7);
        int s14 = ((s4 << 8) ^ MUL_A[s4 & 0xff]) ^ ((s7 >>> 8) ^ DIV_A[s7 & 0xff]) ^ s13;
        f0 = (s13 + r1) ^ r2;

        tt = r1;
        r1 = r2 + s6 ^ (-(r1 & 1) & s13);
        r2 = Integer.rotateLeft(tt * CONST, 7);
        int s15 = ((s5 << 8) ^ MUL_A[s5 & 0xff]) ^ ((s8 >>> 8) ^ DIV_A[s8 & 0xff]) ^ s14;
        f1 = (s14 + r1) ^ r2;

        tt = r1;
        r1 = r2 + s7 ^ (-(r1 & 1) & s14);
        r2 = Integer.rotateLeft(tt * CONST, 7);
        int s16 = ((s6 << 8) ^ MUL_A[s6 & 0xff]) ^ ((s9 >>> 8) ^ DIV_A[s9 & 0xff]) ^ s15;
        f2 = (s15 + r1) ^ r2;

        tt = r1;
        r1 = r2 + s8 ^ (-(r1 & 1) & s15);
        r2 = Integer.rotateLeft(tt * CONST, 7);
        int s17 = ((s7 << 8) ^ MUL_A[s7 & 0xff]) ^ ((s10 >>> 8) ^ DIV_A[s10 & 0xff]) ^ s16;
        f3 = (s16 + r1) ^ r2;

        f4 = f0;
        f0 = (f0 & f2) ^ f3;
        f2 ^= f0 ^ f1;
        f3 = (f3 | f4) ^ f1;
        f4 ^= f2;
        f1 = f3;
        f3 = (f3 | f4) ^ f0;
        f4 ^= f0 & f1;

        keystream[4] = f2 ^ s4;
        keystream[5] = f3 ^ s5;
        keystream[6] = f1 ^ f3 ^ f4 ^ s6;
        keystream[7] = ~f4 ^ s7;

        tt = r1;
        r1 = r2 + s9 ^ (-(r1 & 1) & s16);
        r2 = Integer.rotateLeft(tt * CONST, 7);
        int s18 = ((s8 << 8) ^ MUL_A[s8 & 0xff]) ^ ((s11 >>> 8) ^ DIV_A[s11 & 0xff]) ^ s17;
        f0 = (s17 + r1) ^ r2;

        tt = r1;
        r1 = r2 + s10 ^ (-(r1 & 1) & s17);
        r2 = Integer.rotateLeft(tt * CONST, 7);
        int s19 = ((s9 << 8) ^ MUL_A[s9 & 0xff]) ^ ((s12 >>> 8) ^ DIV_A[s12 & 0xff]) ^ s18;
        f1 = (s18 + r1) ^ r2;

        tt = r1;
        r1 = r2 + s11 ^ (-(r1 & 1) & s18);
        r2 = Integer.rotateLeft(tt * CONST, 7);
        s0 = ((s10 << 8) ^ MUL_A[s10 & 0xff]) ^ ((s13 >>> 8) ^ DIV_A[s13 & 0xff]) ^ s19;
        f2 = (s19 + r1) ^ r2;

        tt = r1;
        r1 = r2 + s12 ^ (-(r1 & 1) & s19);
        r2 = Integer.rotateLeft(tt * CONST, 7);
        s1 = ((s11 << 8) ^ MUL_A[s11 & 0xff]) ^ ((s14 >>> 8) ^ DIV_A[s14 & 0xff]) ^ s0;
        f3 = (s0 + r1) ^ r2;

        f4 = f0;
        f0 = (f0 & f2) ^ f3;
        f2 ^= f0 ^ f1;
        f3 = (f3 | f4) ^ f1;
        f4 ^= f2;
        f1 = f3;
        f3 = (f3 | f4) ^ f0;
        f4 ^= f0 & f1;

        keystream[8] = f2 ^ s8;
        keystream[9] = f3 ^ s9;
        keystream[10] = f1 ^ f3 ^ f4 ^ s10;
        keystream[11] = ~f4 ^ s11;

        tt = r1;
        r1 = r2 + s13 ^ (-(r1 & 1) & s0);
        r2 = Integer.rotateLeft(tt * CONST, 7);
        s2 = ((s12 << 8) ^ MUL_A[s12 & 0xff]) ^ ((s15 >>> 8) ^ DIV_A[s15 & 0xff]) ^ s1;
        f0 = (s1 + r1) ^ r2;

        tt = r1;
        r1 = r2 + s14 ^ (-(r1 & 1) & s1);
        r2 = Integer.rotateLeft(tt * CONST, 7);
        s3 = ((s13 << 8) ^ MUL_A[s13 & 0xff]) ^ ((s16 >>> 8) ^ DIV_A[s16 & 0xff]) ^ s2;
        f1 = (s2 + r1) ^ r2;

        tt = r1;
        r1 = r2 + s15 ^ (-(r1 & 1) & s2);
        r2 = Integer.rotateLeft(tt * CONST, 7);
        s4 = ((s14 << 8) ^ MUL_A[s14 & 0xff]) ^ ((s17 >>> 8) ^ DIV_A[s17 & 0xff]) ^ s3;
        f2 = (s3 + r1) ^ r2;

        tt = r1;
        r1 = r2 + s16 ^ (-(r1 & 1) & s3);
        r2 = Integer.rotateLeft(tt * CONST, 7);
        s5 = ((s15 << 8) ^ MUL_A[s15 & 0xff]) ^ ((s18 >>> 8) ^ DIV_A[s18 & 0xff]) ^ s4;
        f3 = (s4 + r1) ^ r2;

        f4 = f0;
        f0 = (f0 & f2) ^ f3;
        f2 ^= f0 ^ f1;
        f3 = (f3 | f4) ^ f1;
        f4 ^= f2;
        f1 = f3;
        f3 = (f3 | f4) ^ f0;
        f4 ^= f0 & f1;

        keystream[12] = f2 ^ s12;
        keystream[13] = f3 ^ s13;
        keystream[14] = f1 ^ f3 ^ f4 ^ s14;
        keystream[15] = ~f4 ^ s15;

        tt = r1;
        r1 = r2 + s17 ^ (-(r1 & 1) & s4);
        r2 = Integer.rotateLeft(tt * CONST, 7);
        s6 = ((s16 << 8) ^ MUL_A[s16 & 0xff]) ^ ((s19 >>> 8) ^ DIV_A[s19 & 0xff]) ^ s5;
        f0 = (s5 + r1) ^ r2;

        tt = r1;
        r1 = r2 + s18 ^ (-(r1 & 1) & s5);
        r2 = Integer.rotateLeft(tt * CONST, 7);
        s7 = ((s17 << 8) ^ MUL_A[s17 & 0xff]) ^ ((s0 >>> 8) ^ DIV_A[s0 & 0xff]) ^ s6;
        f1 = (s6 + r1) ^ r2;

        tt = r1;
        r1 = r2 + s19 ^ (-(r1 & 1) & s6);
        r2 = Integer.rotateLeft(tt * CONST, 7);
        s8 = ((s18 << 8) ^ MUL_A[s18 & 0xff]) ^ ((s1 >>> 8) ^ DIV_A[s1 & 0xff]) ^ s7;
        f2 = (s7 + r1) ^ r2;

        tt = r1;
        r1 = r2 + s0 ^ (-(r1 & 1) & s7);
        r2 = Integer.rotateLeft(tt * CONST, 7);
        s9 = ((s19 << 8) ^ MUL_A[s19 & 0xff]) ^ ((s2 >>> 8) ^ DIV_A[s2 & 0xff]) ^ s8;
        f3 = (s8 + r1) ^ r2;

        f4 = f0;
        f0 = (f0 & f2) ^ f3;
        f2 ^= f0 ^ f1;
        f3 = (f3 | f4) ^ f1;
        f4 ^= f2;
        f1 = f3;
        f3 = (f3 | f4) ^ f0;
        f4 ^= f0 & f1;

        keystream[16] = f2 ^ s16;
        keystream[17] = f3 ^ s17;
        keystream[18] = f1 ^ f3 ^ f4 ^ s18;
        keystream[19] = ~f4 ^ s19;

        state[0] = s0;
        state[1] = s1;
        state[2] = s2;
        state[3] = s3;
        state[4] = s4;
        state[5] = s5;
        state[6] = s6;
        state[7] = s7;
        state[8] = s8;
        state[9] = s9;

        register[0] = r1;
        register[1] = r2;

    }

    @Override
    public EncryptEngine startEncryption(byte[] key, byte[] iv) {
        return new AbstractStreamEncrypter(80) {

            private final int[] state = new int[16], register = new int[2], keystream = new int[20];

            @Override
            protected void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
                keystream(state, register, keystream);

                ciphertext.set(LAYOUT, cOffset + 0, plaintext.get(LAYOUT, pOffset + 0) ^ keystream[0]);
                ciphertext.set(LAYOUT, cOffset + 4, plaintext.get(LAYOUT, pOffset + 4) ^ keystream[1]);
                ciphertext.set(LAYOUT, cOffset + 8, plaintext.get(LAYOUT, pOffset + 8) ^ keystream[2]);
                ciphertext.set(LAYOUT, cOffset + 12, plaintext.get(LAYOUT, pOffset + 12) ^ keystream[3]);
                ciphertext.set(LAYOUT, cOffset + 16, plaintext.get(LAYOUT, pOffset + 16) ^ keystream[4]);
                ciphertext.set(LAYOUT, cOffset + 20, plaintext.get(LAYOUT, pOffset + 20) ^ keystream[5]);
                ciphertext.set(LAYOUT, cOffset + 24, plaintext.get(LAYOUT, pOffset + 24) ^ keystream[6]);
                ciphertext.set(LAYOUT, cOffset + 28, plaintext.get(LAYOUT, pOffset + 28) ^ keystream[7]);
                ciphertext.set(LAYOUT, cOffset + 32, plaintext.get(LAYOUT, pOffset + 32) ^ keystream[8]);
                ciphertext.set(LAYOUT, cOffset + 36, plaintext.get(LAYOUT, pOffset + 36) ^ keystream[9]);
                ciphertext.set(LAYOUT, cOffset + 40, plaintext.get(LAYOUT, pOffset + 40) ^ keystream[10]);
                ciphertext.set(LAYOUT, cOffset + 44, plaintext.get(LAYOUT, pOffset + 44) ^ keystream[11]);
                ciphertext.set(LAYOUT, cOffset + 48, plaintext.get(LAYOUT, pOffset + 48) ^ keystream[12]);
                ciphertext.set(LAYOUT, cOffset + 52, plaintext.get(LAYOUT, pOffset + 52) ^ keystream[13]);
                ciphertext.set(LAYOUT, cOffset + 56, plaintext.get(LAYOUT, pOffset + 56) ^ keystream[14]);
                ciphertext.set(LAYOUT, cOffset + 60, plaintext.get(LAYOUT, pOffset + 60) ^ keystream[15]);
                ciphertext.set(LAYOUT, cOffset + 64, plaintext.get(LAYOUT, pOffset + 64) ^ keystream[16]);
                ciphertext.set(LAYOUT, cOffset + 68, plaintext.get(LAYOUT, pOffset + 68) ^ keystream[17]);
                ciphertext.set(LAYOUT, cOffset + 72, plaintext.get(LAYOUT, pOffset + 72) ^ keystream[18]);
                ciphertext.set(LAYOUT, cOffset + 76, plaintext.get(LAYOUT, pOffset + 76) ^ keystream[19]);
            }

            @Override
            public Cipher getAlgorithm() {
                return SOSEMANUK;
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
