/*
 * Copyright (C) 2022 Sayantan Chakraborty
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
package org.asterisk.crypto.helper;

/**
 *
 * @author Sayantan Chakraborty
 */
public class GfHelper {

    private static final int POLY = 0x87;

    public static void x2(int[] src) {
        int x = src[0] >> 31;
        src[0] = (src[0] << 1) | (src[1] >>> 31);
        src[1] = (src[1] << 1) | (src[2] >>> 31);
        src[2] = (src[2] << 1) | (src[3] >>> 31);
        src[3] = (src[3] << 1) | (x & POLY);
    }

    public static void x2(int[] src, int[] dst) {
        dst[0] = (src[0] << 1) | (src[1] >>> 31);
        dst[1] = (src[1] << 1) | (src[2] >>> 31);
        dst[2] = (src[2] << 1) | (src[3] >>> 31);
        dst[3] = (src[3] << 1) | (src[0] & POLY);
    }

    public static void x3(int[] src, int[] dst) {
        int x = src[0] >> 31;
        dst[0] = ((src[0] << 1) | (src[1] >>> 31)) ^ src[0];
        dst[1] = ((src[1] << 1) | (src[2] >>> 31)) ^ src[1];
        dst[2] = ((src[2] << 1) | (src[3] >>> 31)) ^ src[2];
        dst[3] = ((src[3] << 1) | (x & POLY)) ^ src[3];
    }

    public static void x7(int[] src) {

        final int src0 = src[0], src1 = src[1], src2 = src[2], src3 = src[3];

        //7=3*2+1
        src[0] = (src0 << 1) | (src1 >>> 31);
        src[1] = (src1 << 1) | (src2 >>> 31);
        src[2] = (src2 << 1) | (src3 >>> 31);
        src[3] = (src3 << 1) | ((src0 >> 31) & POLY);

        src[0] ^= ((src[0] << 1) | (src[1] >>> 31)) ^ src0;
        src[1] ^= ((src[1] << 1) | (src[2] >>> 31)) ^ src1;
        src[2] ^= ((src[2] << 1) | (src[3] >>> 31)) ^ src2;
        src[3] ^= ((src[3] << 1) | ((src[0] >> 31) & POLY)) ^ src3;

    }

    public static void x7(int[] src, int[] dst) {
        //7=3*2+1
        dst[0] = (src[0] << 1) | (src[1] >>> 31);
        dst[1] = (src[1] << 1) | (src[2] >>> 31);
        dst[2] = (src[2] << 1) | (src[3] >>> 31);
        dst[3] = (src[3] << 1) | ((src[0] >> 31) & POLY);

        dst[0] ^= ((dst[0] << 1) | (dst[1] >>> 31)) ^ src[0];
        dst[1] ^= ((dst[1] << 1) | (dst[2] >>> 31)) ^ src[1];
        dst[2] ^= ((dst[2] << 1) | (dst[3] >>> 31)) ^ src[2];
        dst[3] ^= ((dst[3] << 1) | ((dst[0] >> 31) & POLY)) ^ src[3];

    }

    private GfHelper() {
    }

}
