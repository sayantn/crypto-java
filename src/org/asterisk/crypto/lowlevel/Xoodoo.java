/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.lowlevel;

/**
 *
 * @author Sayantan Chakraborty
 */
public class Xoodoo {

    private static final int[] XOODOO_C = {
        0x58, 0x38, 0x3c0, 0xd0, 0x120, 0x14, 0x60, 0x2c, 0x80, 0xf0, 0x1a0, 0x12
    };

    /**
     * A very fast implementation of the Xoodoo permutation.
     * Each round takes only 53 cycles to complete
     *
     * @param state  the 384-bit Xoodoo state. The lanes are the elements of the
     *               array, the lanes in one plane are arranged consecutively, i.e lane 1 of
     *               plane 0 is at element 1, lane 3 of plane 1 is at element 7 etc. the
     *               lanes are loaded with completely Big-Endian byte order(and bit order too,
     *               but that is usually enforced by Java data types)
     * @param rounds number of rounds the permutation to repeat. minimum value
     *               is 0, maximum is 12
     *
     * @throws IllegalArgumentException if {@code rounds<0} or {@code rounds>12}
     */
    public static void xoodoo(int[] state, int rounds) {
        if (rounds < 0 || rounds > 12) {
            throw new IllegalArgumentException("rounds: " + rounds);
        }
        int temp0, temp1, temp2, temp3, temp4, temp5, temp6, temp7;
        int state0 = state[0];
        int state1 = state[1];
        int state2 = state[2];
        int state3 = state[3];
        int state4 = state[4];
        int state5 = state[5];
        int state6 = state[6];
        int state7 = state[7];
        int state8 = state[8];
        int state9 = state[9];
        int state10 = state[10];
        int state11 = state[11];

        for (int r = 12 - rounds; r < 12; r++) {
            temp0 = state0 ^ state4 ^ state8;
            temp1 = state1 ^ state5 ^ state9;
            temp2 = state2 ^ state6 ^ state10;
            temp3 = state3 ^ state7 ^ state11;

            temp4 = Integer.rotateRight(temp3, 5) ^ Integer.rotateRight(temp3, 14);
            temp5 = Integer.rotateRight(temp0, 5) ^ Integer.rotateRight(temp0, 14);
            temp6 = Integer.rotateRight(temp1, 5) ^ Integer.rotateRight(temp1, 14);
            temp7 = Integer.rotateRight(temp2, 5) ^ Integer.rotateRight(temp2, 14);

            state8 ^= temp4;
            state9 ^= temp5;
            state10 ^= temp6;
            state11 ^= temp7;

            temp0 = state3 ^ temp7 ^ XOODOO_C[r];
            temp1 = state0 ^ temp4;
            temp2 = state1 ^ temp5;
            temp3 = state2 ^ temp6;
            temp4 = Integer.rotateRight(state4 ^ temp4, 11);
            temp5 = Integer.rotateRight(state5 ^ temp5, 11);
            temp6 = Integer.rotateRight(state6 ^ temp6, 11);
            temp7 = Integer.rotateRight(state7 ^ temp7, 11);

            state0 = Integer.rotateRight(temp0 ^ (~temp4 & state8), 1);
            state1 = Integer.rotateRight(temp1 ^ (~temp5 & state9), 1);
            state2 = Integer.rotateRight(temp2 ^ (~temp6 & state10), 1);
            state3 = Integer.rotateRight(temp3 ^ (~temp7 & state11), 1);

            state4 = Integer.rotateRight(temp6 ^ (~state10 & temp2), 8);
            state5 = Integer.rotateRight(temp7 ^ (~state11 & temp3), 8);
            state6 = Integer.rotateRight(temp4 ^ (~state8 & temp0), 8);
            state7 = Integer.rotateRight(temp5 ^ (~state9 & temp1), 8);

            state8 ^= ~temp0 & temp4;
            state9 ^= ~temp1 & temp5;
            state10 ^= ~temp2 & temp6;
            state11 ^= ~temp3 & temp7;
        }

        state[0] = state0;
        state[1] = state1;
        state[2] = state2;
        state[3] = state3;
        state[4] = state4;
        state[5] = state5;
        state[6] = state6;
        state[7] = state7;
        state[8] = state8;
        state[9] = state9;
        state[10] = state10;
        state[11] = state11;
    }

    private Xoodoo() {
    }

}
