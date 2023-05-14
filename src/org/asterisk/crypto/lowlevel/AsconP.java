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
package org.asterisk.crypto.lowlevel;

/**
 *
 * @author Sayantan Chakraborty
 */
public class AsconP {

    private static final long[] RND_CONST = {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b};

    /**
     * an implementation of the permutation function of the <i>Ascon</i> cipher
     * from the CAESAR portfolio (in use case 1:Lightweight applications)
     * <p>
     * each round takes 23 cycles to compute
     *
     * @param state  the 320 bit state, represented as 5 big-endian 64-bit words
     * @param rounds
     *
     * @throws IllegalArgumentException if {@literal rounds < 0} or
     *                                  {@literal rounds > 12}
     */
    public static void ascon_p(long[] state, int rounds) {

        if (rounds < 0 || rounds > 12) {
            throw new IllegalArgumentException("Rounds: " + rounds);
        }

        long x0 = state[0], x1 = state[1], x2 = state[2], x3 = state[3], x4 = state[4];
        long t0, t1, t2, t3, t4;

        for (int r = 12 - rounds; r < 12; r++) {
            x2 ^= RND_CONST[r];

            x0 ^= x4;
            x4 ^= x3;
            x2 ^= x1;

            t0 = ~x0 & x1;
            t1 = ~x1 & x2;
            t2 = ~x2 & x3;
            t3 = ~x3 & x4;
            t4 = ~x4 & x0;

            x0 ^= t1;
            x1 ^= t2;
            x2 ^= t3;
            x3 ^= t4;
            x4 ^= t0;

            x1 ^= x0;
            x0 ^= x4;
            x3 ^= x2;
            x2 = ~x2;

            x0 = x0 ^ Long.rotateRight(x0, 19) ^ Long.rotateRight(x0, 28);
            x1 = x1 ^ Long.rotateRight(x1, 61) ^ Long.rotateRight(x1, 39);
            x2 = x2 ^ Long.rotateRight(x2, 1) ^ Long.rotateRight(x2, 6);
            x3 = x3 ^ Long.rotateRight(x3, 10) ^ Long.rotateRight(x3, 17);
            x4 = x4 ^ Long.rotateRight(x4, 7) ^ Long.rotateRight(x4, 41);

        }

        state[0] = x0;
        state[1] = x1;
        state[2] = x2;
        state[3] = x3;
        state[4] = x4;
    }

    private AsconP() {
    }

}
