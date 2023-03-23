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
package org.asterisk.crypto.hash;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.SegmentScope;
import java.lang.foreign.ValueLayout;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.interfaces.Xof;

import static org.asterisk.crypto.helper.Tools.store32LE;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum Blake3 implements Xof {

    BLAKE3;

    private static final ValueLayout.OfInt LAYOUT = Tools.LITTLE_ENDIAN_32_BIT;

    private static final int[] DEFAULT_IV = {
        0x6a09e667, 0xbb67ae85, 0x3c63f372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    private static final int DEFAULT_HASH_LEN = 32,
            BLOCK_LEN = 64,
            CHUNK_LEN = 1024;

    private static final int CHUNK_START = 0b1,
            CHUNK_END = 0b10,
            PARENT = 0b100,
            ROOT = 0b1000,
            KEYED_HASH = 0b10000,
            DERIVE_KEY_CONTEXT = 0b100000,
            DERIVE_KEY_MATERIAL = 0b1000000;

    private static void compress(int[] src, MemorySegment input, long offset, long counter, int blockLen, int flags) {
        compress(src, input, offset, counter, blockLen, flags, src);
    }

    private static void compress(int[] src, MemorySegment input, long offset, long counter, int blockLen, int flags, int[] dest) {
        int x0 = src[0];
        int x1 = src[1];
        int x2 = src[2];
        int x3 = src[3];
        int x4 = src[4];
        int x5 = src[5];
        int x6 = src[6];
        int x7 = src[7];
        int x8 = DEFAULT_IV[0];
        int x9 = DEFAULT_IV[1];
        int x10 = DEFAULT_IV[2];
        int x11 = DEFAULT_IV[3];
        int x12 = (int) counter;
        int x13 = (int) (counter >>> 32);
        int x14 = blockLen;
        int x15 = flags;

        int m0 = input.get(LAYOUT, offset + 0);
        int m1 = input.get(LAYOUT, offset + 4);
        int m2 = input.get(LAYOUT, offset + 8);
        int m3 = input.get(LAYOUT, offset + 12);
        int m4 = input.get(LAYOUT, offset + 16);
        int m5 = input.get(LAYOUT, offset + 20);
        int m6 = input.get(LAYOUT, offset + 24);
        int m7 = input.get(LAYOUT, offset + 28);
        int m8 = input.get(LAYOUT, offset + 32);
        int m9 = input.get(LAYOUT, offset + 36);
        int m10 = input.get(LAYOUT, offset + 40);
        int m11 = input.get(LAYOUT, offset + 44);
        int m12 = input.get(LAYOUT, offset + 48);
        int m13 = input.get(LAYOUT, offset + 52);
        int m14 = input.get(LAYOUT, offset + 56);
        int m15 = input.get(LAYOUT, offset + 60);

        x0 += x4 + m0;
        x12 = Integer.rotateRight(x12 ^ x0, 16);
        x8 += x12;
        x4 = Integer.rotateRight(x4 ^ x8, 12);
        x0 += x4 + m1;
        x12 = Integer.rotateRight(x12 ^ x0, 8);
        x8 += x12;
        x4 = Integer.rotateRight(x4 ^ x8, 7);
        x1 += x5 + m2;
        x13 = Integer.rotateRight(x13 ^ x1, 16);
        x9 += x13;
        x5 = Integer.rotateRight(x5 ^ x9, 12);
        x1 += x5 + m3;
        x13 = Integer.rotateRight(x13 ^ x1, 8);
        x9 += x13;
        x5 = Integer.rotateRight(x5 ^ x9, 7);
        x2 += x6 + m4;
        x14 = Integer.rotateRight(x14 ^ x2, 16);
        x10 += x14;
        x6 = Integer.rotateRight(x6 ^ x10, 12);
        x2 += x6 + m5;
        x14 = Integer.rotateRight(x14 ^ x2, 8);
        x10 += x14;
        x6 = Integer.rotateRight(x6 ^ x10, 7);
        x3 += x7 + m6;
        x15 = Integer.rotateRight(x15 ^ x3, 16);
        x11 += x15;
        x7 = Integer.rotateRight(x7 ^ x11, 12);
        x3 += x7 + m7;
        x15 = Integer.rotateRight(x15 ^ x3, 8);
        x11 += x15;
        x7 = Integer.rotateRight(x7 ^ x11, 7);
        x0 += x5 + m8;
        x15 = Integer.rotateRight(x15 ^ x0, 16);
        x10 += x15;
        x5 = Integer.rotateRight(x5 ^ x10, 12);
        x0 += x5 + m9;
        x15 = Integer.rotateRight(x15 ^ x0, 8);
        x10 += x15;
        x5 = Integer.rotateRight(x5 ^ x10, 7);
        x1 += x6 + m10;
        x12 = Integer.rotateRight(x12 ^ x1, 16);
        x11 += x12;
        x6 = Integer.rotateRight(x6 ^ x11, 12);
        x1 += x6 + m11;
        x12 = Integer.rotateRight(x12 ^ x1, 8);
        x11 += x12;
        x6 = Integer.rotateRight(x6 ^ x11, 7);
        x2 += x7 + m12;
        x13 = Integer.rotateRight(x13 ^ x2, 16);
        x8 += x13;
        x7 = Integer.rotateRight(x7 ^ x8, 12);
        x2 += x7 + m13;
        x13 = Integer.rotateRight(x13 ^ x2, 8);
        x8 += x13;
        x7 = Integer.rotateRight(x7 ^ x8, 7);
        x3 += x4 + m14;
        x14 = Integer.rotateRight(x14 ^ x3, 16);
        x9 += x14;
        x4 = Integer.rotateRight(x4 ^ x9, 12);
        x3 += x4 + m15;
        x14 = Integer.rotateRight(x14 ^ x3, 8);
        x9 += x14;
        x4 = Integer.rotateRight(x4 ^ x9, 7);

        x0 += x4 + m2;
        x12 = Integer.rotateRight(x12 ^ x0, 16);
        x8 += x12;
        x4 = Integer.rotateRight(x4 ^ x8, 12);
        x0 += x4 + m6;
        x12 = Integer.rotateRight(x12 ^ x0, 8);
        x8 += x12;
        x4 = Integer.rotateRight(x4 ^ x8, 7);
        x1 += x5 + m3;
        x13 = Integer.rotateRight(x13 ^ x1, 16);
        x9 += x13;
        x5 = Integer.rotateRight(x5 ^ x9, 12);
        x1 += x5 + m10;
        x13 = Integer.rotateRight(x13 ^ x1, 8);
        x9 += x13;
        x5 = Integer.rotateRight(x5 ^ x9, 7);
        x2 += x6 + m7;
        x14 = Integer.rotateRight(x14 ^ x2, 16);
        x10 += x14;
        x6 = Integer.rotateRight(x6 ^ x10, 12);
        x2 += x6 + m0;
        x14 = Integer.rotateRight(x14 ^ x2, 8);
        x10 += x14;
        x6 = Integer.rotateRight(x6 ^ x10, 7);
        x3 += x7 + m4;
        x15 = Integer.rotateRight(x15 ^ x3, 16);
        x11 += x15;
        x7 = Integer.rotateRight(x7 ^ x11, 12);
        x3 += x7 + m13;
        x15 = Integer.rotateRight(x15 ^ x3, 8);
        x11 += x15;
        x7 = Integer.rotateRight(x7 ^ x11, 7);
        x0 += x5 + m1;
        x15 = Integer.rotateRight(x15 ^ x0, 16);
        x10 += x15;
        x5 = Integer.rotateRight(x5 ^ x10, 12);
        x0 += x5 + m11;
        x15 = Integer.rotateRight(x15 ^ x0, 8);
        x10 += x15;
        x5 = Integer.rotateRight(x5 ^ x10, 7);
        x1 += x6 + m12;
        x12 = Integer.rotateRight(x12 ^ x1, 16);
        x11 += x12;
        x6 = Integer.rotateRight(x6 ^ x11, 12);
        x1 += x6 + m5;
        x12 = Integer.rotateRight(x12 ^ x1, 8);
        x11 += x12;
        x6 = Integer.rotateRight(x6 ^ x11, 7);
        x2 += x7 + m9;
        x13 = Integer.rotateRight(x13 ^ x2, 16);
        x8 += x13;
        x7 = Integer.rotateRight(x7 ^ x8, 12);
        x2 += x7 + m14;
        x13 = Integer.rotateRight(x13 ^ x2, 8);
        x8 += x13;
        x7 = Integer.rotateRight(x7 ^ x8, 7);
        x3 += x4 + m15;
        x14 = Integer.rotateRight(x14 ^ x3, 16);
        x9 += x14;
        x4 = Integer.rotateRight(x4 ^ x9, 12);
        x3 += x4 + m8;
        x14 = Integer.rotateRight(x14 ^ x3, 8);
        x9 += x14;
        x4 = Integer.rotateRight(x4 ^ x9, 7);

        x0 += x4 + m3;
        x12 = Integer.rotateRight(x12 ^ x0, 16);
        x8 += x12;
        x4 = Integer.rotateRight(x4 ^ x8, 12);
        x0 += x4 + m4;
        x12 = Integer.rotateRight(x12 ^ x0, 8);
        x8 += x12;
        x4 = Integer.rotateRight(x4 ^ x8, 7);
        x1 += x5 + m10;
        x13 = Integer.rotateRight(x13 ^ x1, 16);
        x9 += x13;
        x5 = Integer.rotateRight(x5 ^ x9, 12);
        x1 += x5 + m12;
        x13 = Integer.rotateRight(x13 ^ x1, 8);
        x9 += x13;
        x5 = Integer.rotateRight(x5 ^ x9, 7);
        x2 += x6 + m13;
        x14 = Integer.rotateRight(x14 ^ x2, 16);
        x10 += x14;
        x6 = Integer.rotateRight(x6 ^ x10, 12);
        x2 += x6 + m2;
        x14 = Integer.rotateRight(x14 ^ x2, 8);
        x10 += x14;
        x6 = Integer.rotateRight(x6 ^ x10, 7);
        x3 += x7 + m7;
        x15 = Integer.rotateRight(x15 ^ x3, 16);
        x11 += x15;
        x7 = Integer.rotateRight(x7 ^ x11, 12);
        x3 += x7 + m14;
        x15 = Integer.rotateRight(x15 ^ x3, 8);
        x11 += x15;
        x7 = Integer.rotateRight(x7 ^ x11, 7);
        x0 += x5 + m6;
        x15 = Integer.rotateRight(x15 ^ x0, 16);
        x10 += x15;
        x5 = Integer.rotateRight(x5 ^ x10, 12);
        x0 += x5 + m5;
        x15 = Integer.rotateRight(x15 ^ x0, 8);
        x10 += x15;
        x5 = Integer.rotateRight(x5 ^ x10, 7);
        x1 += x6 + m9;
        x12 = Integer.rotateRight(x12 ^ x1, 16);
        x11 += x12;
        x6 = Integer.rotateRight(x6 ^ x11, 12);
        x1 += x6 + m0;
        x12 = Integer.rotateRight(x12 ^ x1, 8);
        x11 += x12;
        x6 = Integer.rotateRight(x6 ^ x11, 7);
        x2 += x7 + m11;
        x13 = Integer.rotateRight(x13 ^ x2, 16);
        x8 += x13;
        x7 = Integer.rotateRight(x7 ^ x8, 12);
        x2 += x7 + m15;
        x13 = Integer.rotateRight(x13 ^ x2, 8);
        x8 += x13;
        x7 = Integer.rotateRight(x7 ^ x8, 7);
        x3 += x4 + m8;
        x14 = Integer.rotateRight(x14 ^ x3, 16);
        x9 += x14;
        x4 = Integer.rotateRight(x4 ^ x9, 12);
        x3 += x4 + m1;
        x14 = Integer.rotateRight(x14 ^ x3, 8);
        x9 += x14;
        x4 = Integer.rotateRight(x4 ^ x9, 7);

        x0 += x4 + m10;
        x12 = Integer.rotateRight(x12 ^ x0, 16);
        x8 += x12;
        x4 = Integer.rotateRight(x4 ^ x8, 12);
        x0 += x4 + m7;
        x12 = Integer.rotateRight(x12 ^ x0, 8);
        x8 += x12;
        x4 = Integer.rotateRight(x4 ^ x8, 7);
        x1 += x5 + m12;
        x13 = Integer.rotateRight(x13 ^ x1, 16);
        x9 += x13;
        x5 = Integer.rotateRight(x5 ^ x9, 12);
        x1 += x5 + m9;
        x13 = Integer.rotateRight(x13 ^ x1, 8);
        x9 += x13;
        x5 = Integer.rotateRight(x5 ^ x9, 7);
        x2 += x6 + m14;
        x14 = Integer.rotateRight(x14 ^ x2, 16);
        x10 += x14;
        x6 = Integer.rotateRight(x6 ^ x10, 12);
        x2 += x6 + m3;
        x14 = Integer.rotateRight(x14 ^ x2, 8);
        x10 += x14;
        x6 = Integer.rotateRight(x6 ^ x10, 7);
        x3 += x7 + m13;
        x15 = Integer.rotateRight(x15 ^ x3, 16);
        x11 += x15;
        x7 = Integer.rotateRight(x7 ^ x11, 12);
        x3 += x7 + m15;
        x15 = Integer.rotateRight(x15 ^ x3, 8);
        x11 += x15;
        x7 = Integer.rotateRight(x7 ^ x11, 7);
        x0 += x5 + m4;
        x15 = Integer.rotateRight(x15 ^ x0, 16);
        x10 += x15;
        x5 = Integer.rotateRight(x5 ^ x10, 12);
        x0 += x5 + m0;
        x15 = Integer.rotateRight(x15 ^ x0, 8);
        x10 += x15;
        x5 = Integer.rotateRight(x5 ^ x10, 7);
        x1 += x6 + m11;
        x12 = Integer.rotateRight(x12 ^ x1, 16);
        x11 += x12;
        x6 = Integer.rotateRight(x6 ^ x11, 12);
        x1 += x6 + m2;
        x12 = Integer.rotateRight(x12 ^ x1, 8);
        x11 += x12;
        x6 = Integer.rotateRight(x6 ^ x11, 7);
        x2 += x7 + m5;
        x13 = Integer.rotateRight(x13 ^ x2, 16);
        x8 += x13;
        x7 = Integer.rotateRight(x7 ^ x8, 12);
        x2 += x7 + m8;
        x13 = Integer.rotateRight(x13 ^ x2, 8);
        x8 += x13;
        x7 = Integer.rotateRight(x7 ^ x8, 7);
        x3 += x4 + m1;
        x14 = Integer.rotateRight(x14 ^ x3, 16);
        x9 += x14;
        x4 = Integer.rotateRight(x4 ^ x9, 12);
        x3 += x4 + m6;
        x14 = Integer.rotateRight(x14 ^ x3, 8);
        x9 += x14;
        x4 = Integer.rotateRight(x4 ^ x9, 7);

        x0 += x4 + m12;
        x12 = Integer.rotateRight(x12 ^ x0, 16);
        x8 += x12;
        x4 = Integer.rotateRight(x4 ^ x8, 12);
        x0 += x4 + m13;
        x12 = Integer.rotateRight(x12 ^ x0, 8);
        x8 += x12;
        x4 = Integer.rotateRight(x4 ^ x8, 7);
        x1 += x5 + m9;
        x13 = Integer.rotateRight(x13 ^ x1, 16);
        x9 += x13;
        x5 = Integer.rotateRight(x5 ^ x9, 12);
        x1 += x5 + m11;
        x13 = Integer.rotateRight(x13 ^ x1, 8);
        x9 += x13;
        x5 = Integer.rotateRight(x5 ^ x9, 7);
        x2 += x6 + m15;
        x14 = Integer.rotateRight(x14 ^ x2, 16);
        x10 += x14;
        x6 = Integer.rotateRight(x6 ^ x10, 12);
        x2 += x6 + m10;
        x14 = Integer.rotateRight(x14 ^ x2, 8);
        x10 += x14;
        x6 = Integer.rotateRight(x6 ^ x10, 7);
        x3 += x7 + m14;
        x15 = Integer.rotateRight(x15 ^ x3, 16);
        x11 += x15;
        x7 = Integer.rotateRight(x7 ^ x11, 12);
        x3 += x7 + m8;
        x15 = Integer.rotateRight(x15 ^ x3, 8);
        x11 += x15;
        x7 = Integer.rotateRight(x7 ^ x11, 7);
        x0 += x5 + m7;
        x15 = Integer.rotateRight(x15 ^ x0, 16);
        x10 += x15;
        x5 = Integer.rotateRight(x5 ^ x10, 12);
        x0 += x5 + m2;
        x15 = Integer.rotateRight(x15 ^ x0, 8);
        x10 += x15;
        x5 = Integer.rotateRight(x5 ^ x10, 7);
        x1 += x6 + m5;
        x12 = Integer.rotateRight(x12 ^ x1, 16);
        x11 += x12;
        x6 = Integer.rotateRight(x6 ^ x11, 12);
        x1 += x6 + m3;
        x12 = Integer.rotateRight(x12 ^ x1, 8);
        x11 += x12;
        x6 = Integer.rotateRight(x6 ^ x11, 7);
        x2 += x7 + m0;
        x13 = Integer.rotateRight(x13 ^ x2, 16);
        x8 += x13;
        x7 = Integer.rotateRight(x7 ^ x8, 12);
        x2 += x7 + m1;
        x13 = Integer.rotateRight(x13 ^ x2, 8);
        x8 += x13;
        x7 = Integer.rotateRight(x7 ^ x8, 7);
        x3 += x4 + m6;
        x14 = Integer.rotateRight(x14 ^ x3, 16);
        x9 += x14;
        x4 = Integer.rotateRight(x4 ^ x9, 12);
        x3 += x4 + m4;
        x14 = Integer.rotateRight(x14 ^ x3, 8);
        x9 += x14;
        x4 = Integer.rotateRight(x4 ^ x9, 7);

        x0 += x4 + m9;
        x12 = Integer.rotateRight(x12 ^ x0, 16);
        x8 += x12;
        x4 = Integer.rotateRight(x4 ^ x8, 12);
        x0 += x4 + m14;
        x12 = Integer.rotateRight(x12 ^ x0, 8);
        x8 += x12;
        x4 = Integer.rotateRight(x4 ^ x8, 7);
        x1 += x5 + m11;
        x13 = Integer.rotateRight(x13 ^ x1, 16);
        x9 += x13;
        x5 = Integer.rotateRight(x5 ^ x9, 12);
        x1 += x5 + m5;
        x13 = Integer.rotateRight(x13 ^ x1, 8);
        x9 += x13;
        x5 = Integer.rotateRight(x5 ^ x9, 7);
        x2 += x6 + m8;
        x14 = Integer.rotateRight(x14 ^ x2, 16);
        x10 += x14;
        x6 = Integer.rotateRight(x6 ^ x10, 12);
        x2 += x6 + m12;
        x14 = Integer.rotateRight(x14 ^ x2, 8);
        x10 += x14;
        x6 = Integer.rotateRight(x6 ^ x10, 7);
        x3 += x7 + m15;
        x15 = Integer.rotateRight(x15 ^ x3, 16);
        x11 += x15;
        x7 = Integer.rotateRight(x7 ^ x11, 12);
        x3 += x7 + m1;
        x15 = Integer.rotateRight(x15 ^ x3, 8);
        x11 += x15;
        x7 = Integer.rotateRight(x7 ^ x11, 7);
        x0 += x5 + m13;
        x15 = Integer.rotateRight(x15 ^ x0, 16);
        x10 += x15;
        x5 = Integer.rotateRight(x5 ^ x10, 12);
        x0 += x5 + m3;
        x15 = Integer.rotateRight(x15 ^ x0, 8);
        x10 += x15;
        x5 = Integer.rotateRight(x5 ^ x10, 7);
        x1 += x6 + m0;
        x12 = Integer.rotateRight(x12 ^ x1, 16);
        x11 += x12;
        x6 = Integer.rotateRight(x6 ^ x11, 12);
        x1 += x6 + m10;
        x12 = Integer.rotateRight(x12 ^ x1, 8);
        x11 += x12;
        x6 = Integer.rotateRight(x6 ^ x11, 7);
        x2 += x7 + m2;
        x13 = Integer.rotateRight(x13 ^ x2, 16);
        x8 += x13;
        x7 = Integer.rotateRight(x7 ^ x8, 12);
        x2 += x7 + m6;
        x13 = Integer.rotateRight(x13 ^ x2, 8);
        x8 += x13;
        x7 = Integer.rotateRight(x7 ^ x8, 7);
        x3 += x4 + m4;
        x14 = Integer.rotateRight(x14 ^ x3, 16);
        x9 += x14;
        x4 = Integer.rotateRight(x4 ^ x9, 12);
        x3 += x4 + m7;
        x14 = Integer.rotateRight(x14 ^ x3, 8);
        x9 += x14;
        x4 = Integer.rotateRight(x4 ^ x9, 7);

        x0 += x4 + m11;
        x12 = Integer.rotateRight(x12 ^ x0, 16);
        x8 += x12;
        x4 = Integer.rotateRight(x4 ^ x8, 12);
        x0 += x4 + m15;
        x12 = Integer.rotateRight(x12 ^ x0, 8);
        x8 += x12;
        x4 = Integer.rotateRight(x4 ^ x8, 7);
        x1 += x5 + m5;
        x13 = Integer.rotateRight(x13 ^ x1, 16);
        x9 += x13;
        x5 = Integer.rotateRight(x5 ^ x9, 12);
        x1 += x5 + m0;
        x13 = Integer.rotateRight(x13 ^ x1, 8);
        x9 += x13;
        x5 = Integer.rotateRight(x5 ^ x9, 7);
        x2 += x6 + m1;
        x14 = Integer.rotateRight(x14 ^ x2, 16);
        x10 += x14;
        x6 = Integer.rotateRight(x6 ^ x10, 12);
        x2 += x6 + m9;
        x14 = Integer.rotateRight(x14 ^ x2, 8);
        x10 += x14;
        x6 = Integer.rotateRight(x6 ^ x10, 7);
        x3 += x7 + m8;
        x15 = Integer.rotateRight(x15 ^ x3, 16);
        x11 += x15;
        x7 = Integer.rotateRight(x7 ^ x11, 12);
        x3 += x7 + m6;
        x15 = Integer.rotateRight(x15 ^ x3, 8);
        x11 += x15;
        x7 = Integer.rotateRight(x7 ^ x11, 7);
        x0 += x5 + m14;
        x15 = Integer.rotateRight(x15 ^ x0, 16);
        x10 += x15;
        x5 = Integer.rotateRight(x5 ^ x10, 12);
        x0 += x5 + m10;
        x15 = Integer.rotateRight(x15 ^ x0, 8);
        x10 += x15;
        x5 = Integer.rotateRight(x5 ^ x10, 7);
        x1 += x6 + m2;
        x12 = Integer.rotateRight(x12 ^ x1, 16);
        x11 += x12;
        x6 = Integer.rotateRight(x6 ^ x11, 12);
        x1 += x6 + m12;
        x12 = Integer.rotateRight(x12 ^ x1, 8);
        x11 += x12;
        x6 = Integer.rotateRight(x6 ^ x11, 7);
        x2 += x7 + m3;
        x13 = Integer.rotateRight(x13 ^ x2, 16);
        x8 += x13;
        x7 = Integer.rotateRight(x7 ^ x8, 12);
        x2 += x7 + m4;
        x13 = Integer.rotateRight(x13 ^ x2, 8);
        x8 += x13;
        x7 = Integer.rotateRight(x7 ^ x8, 7);
        x3 += x4 + m7;
        x14 = Integer.rotateRight(x14 ^ x3, 16);
        x9 += x14;
        x4 = Integer.rotateRight(x4 ^ x9, 12);
        x3 += x4 + m13;
        x14 = Integer.rotateRight(x14 ^ x3, 8);
        x9 += x14;
        x4 = Integer.rotateRight(x4 ^ x9, 7);

        dest[8] = x8 ^ src[0];
        dest[9] = x9 ^ src[1];
        dest[10] = x10 ^ src[2];
        dest[11] = x11 ^ src[3];
        dest[12] = x12 ^ src[4];
        dest[13] = x13 ^ src[5];
        dest[14] = x14 ^ src[6];
        dest[15] = x15 ^ src[7];

        dest[0] = x0 ^ x8;
        dest[1] = x1 ^ x9;
        dest[2] = x2 ^ x10;
        dest[3] = x3 ^ x11;
        dest[4] = x4 ^ x12;
        dest[5] = x5 ^ x13;
        dest[6] = x6 ^ x14;
        dest[7] = x7 ^ x15;
    }

    @Override
    public Engine start() {
        return new Xof.Engine() {

            private final ChunkState state = new ChunkState(DEFAULT_IV, 0);
            private int position = 0;

            @Override
            public void ingest(MemorySegment input) {
                long length = input.byteSize(), offset = 0;
                if (position > 0) {
                    int take = (int) Math.min(length, CHUNK_LEN - position);
                    state.ingest(input, offset, take);
                    offset += take;
                    length -= take;
                    position += take;
                    if (position == CHUNK_LEN) {
                        state.chain();
                        state.reset(DEFAULT_IV);
                        position = 0;
                    }
                }
                while (length >= CHUNK_LEN) {
                    state.ingestFullChunk(input, offset);
                    offset += CHUNK_LEN;
                    length -= CHUNK_LEN;
                }
                if (length > 0) {
                    state.ingest(input, offset, length);
                    position = (int) length;
                }
            }

            @Override
            public void startDigesting() {
                throw new UnsupportedOperationException();
            }

            @Override
            public void continueDigesting(byte[] dest, int offset, int length) {
            }

            @Override
            public Xof getAlgorithm() {
                return BLAKE3;
            }
        };
    }

    @Override
    public int digestSize() {
        return DEFAULT_HASH_LEN;
    }

    @Override
    public int blockSize() {
        return BLOCK_LEN;
    }

    private static class ChunkState {

        private final int[] state = new int[16];
        private long counter = 0;
        private final int flags;

        private final MemorySegment buffer = MemorySegment.allocateNative(BLOCK_LEN, SegmentScope.auto());
        private int position = 0;

        private boolean compressed = false;

        private ChunkState(int[] key, int flags) {
            System.arraycopy(key, 0, state, 0, 8);
            this.flags = flags;
        }

        private int startFlag() {
            return compressed ? 0 : CHUNK_START;
        }

        public int[] ingestFullChunk(MemorySegment input, long offset) {
            assert position == 0;
            assert !compressed;

            int[] ret = this.state.clone();

            compress(ret, input, offset + 0, counter, BLOCK_LEN, flags | CHUNK_START);
            compress(ret, input, offset + 64, counter, BLOCK_LEN, flags);
            compress(ret, input, offset + 128, counter, BLOCK_LEN, flags);
            compress(ret, input, offset + 192, counter, BLOCK_LEN, flags);
            compress(ret, input, offset + 256, counter, BLOCK_LEN, flags);
            compress(ret, input, offset + 320, counter, BLOCK_LEN, flags);
            compress(ret, input, offset + 384, counter, BLOCK_LEN, flags);
            compress(ret, input, offset + 448, counter, BLOCK_LEN, flags);
            compress(ret, input, offset + 512, counter, BLOCK_LEN, flags);
            compress(ret, input, offset + 576, counter, BLOCK_LEN, flags);
            compress(ret, input, offset + 640, counter, BLOCK_LEN, flags);
            compress(ret, input, offset + 704, counter, BLOCK_LEN, flags);
            compress(ret, input, offset + 768, counter, BLOCK_LEN, flags);
            compress(ret, input, offset + 832, counter, BLOCK_LEN, flags);
            compress(ret, input, offset + 896, counter, BLOCK_LEN, flags);
            compress(ret, input, offset + 960, counter, BLOCK_LEN, flags | CHUNK_END);

            counter++;

            return ret;
        }

        public void ingest(MemorySegment input, long offset, long length) {
            if (position > 0) {
                int take = (int) Math.min(length, BLOCK_LEN - position);
                MemorySegment.copy(input, offset, buffer, position, take);
                offset += take;
                length -= take;
                position += take;
                if (position == BLOCK_LEN && length > 0) {
                    compress(state, buffer, 0, counter, BLOCK_LEN, flags | startFlag());
                    compressed = true;
                    position = 0;
                }
            }
            if (!compressed && length > BLOCK_LEN) {
                compress(state, input, offset, counter, BLOCK_LEN, flags | CHUNK_START);
                compressed = true;
                offset += BLOCK_LEN;
                length -= BLOCK_LEN;
            }
            while (length > BLOCK_LEN) {
                compress(state, input, offset, counter, BLOCK_LEN, flags);
                offset += BLOCK_LEN;
                length -= BLOCK_LEN;
            }
            if (length > 0) {
                MemorySegment.copy(input, offset, buffer, 0, length);
                position = (int) length;
            }
        }

        public int[] chain() {
            Tools.zeropad(buffer, position);
            var ret = new int[16];
            compress(state, buffer, 0, counter, position, flags | startFlag() | CHUNK_END, ret);
            return ret;
        }

        public void reset(int[] key) {
            System.arraycopy(key, 0, state, 0, 8);
            counter++;
            position = 0;
            compressed = false;
        }

    }

    private static class Node {

        private final int[] inputCV;
        private final MemorySegment blockWords;
        private final long counter;
        private final int blockLen, flags;

        private int outputCounter = 0;
        private final byte[] outputBuffer = new byte[64];
        private int outputPosition = 0;

        private Node(int[] inputCV, MemorySegment blockWords, long counter, int blockLen, int flags) {
            this.inputCV = inputCV;
            this.blockWords = blockWords;
            this.counter = counter;
            this.blockLen = blockLen;
            this.flags = flags;
        }

        private int[] chain() {
            int[] ret = new int[16];
            compress(inputCV, blockWords, 0, counter, blockLen, flags, ret);
            return ret;
        }

        private void outputOneBlock(int[] words, byte[] output, int offset) {
            compress(inputCV, blockWords, 0, outputCounter++, blockLen, flags | ROOT, words);

            store32LE(words[0], output, offset + 0);
            store32LE(words[1], output, offset + 4);
            store32LE(words[2], output, offset + 8);
            store32LE(words[3], output, offset + 12);
            store32LE(words[4], output, offset + 16);
            store32LE(words[5], output, offset + 20);
            store32LE(words[6], output, offset + 24);
            store32LE(words[7], output, offset + 28);
            store32LE(words[8], output, offset + 32);
            store32LE(words[9], output, offset + 36);
            store32LE(words[10], output, offset + 40);
            store32LE(words[11], output, offset + 44);
            store32LE(words[12], output, offset + 48);
            store32LE(words[13], output, offset + 52);
            store32LE(words[14], output, offset + 56);
            store32LE(words[15], output, offset + 60);
        }

        private void outputBytes(byte[] output, int offset, int length) {
            if (outputPosition > 0) {
                int take = Math.min(length, 64 - outputPosition);
                System.arraycopy(outputBuffer, outputPosition, output, offset, take);
                offset += take;
                length -= take;
                outputPosition = (outputPosition + take) & 0x3f;
            }
            int[] words = length >= 64 ? new int[16] : null;

            while (length >= 64) {
                outputOneBlock(words, output, offset);

                offset += 64;
                length -= 64;
            }
            if (length > 0) {
                outputOneBlock(words, outputBuffer, 0);

                System.arraycopy(outputBuffer, 0, output, offset, length);
                outputPosition = length;
            }
        }

    }

}
