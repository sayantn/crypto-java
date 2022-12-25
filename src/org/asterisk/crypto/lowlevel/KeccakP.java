/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.lowlevel;

/**
 *
 * @author Sayantan Chakraborty
 */
public class KeccakP {

    private static final long[] RNDC_1600 = {
        0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
        0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
        0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
        0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
        0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
        0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
        0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
        0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    private static final int[] RNDC_800 = {
        0x00000001, 0x00008082, 0x0000808a,
        0x80008000, 0x0000808b, 0x80000001,
        0x80008081, 0x00008009, 0x0000008a,
        0x00000088, 0x80008009, 0x8000000a,
        0x8000808b, 0x0000008b, 0x00008089,
        0x00008003, 0x00008002, 0x00000080,
        0x0000800a, 0x8000000a, 0x80008081,
        0x00008080
    };

    /**
     * performs the 24-round Keccak-f[1600] permutation on the state
     *
     * @param state
     */
    public static void keccak_f1600(long[] state) {
        keccak_p1600(state, 24);
    }

    /**
     * performs {@code rounds} iterations of the Keccak-p[1600] permutation on
     * the state
     * <p>
     * the implementation is optimized for a high number of rounds. If only 1
     * round is required, use {@link #keccak_p1600_oneround(long[])}. In all
     * other cases, this method is faster
     *
     * @param state
     * @param rounds
     */
    public static void keccak_p1600(long[] state, int rounds) {
        long temp, bc0, bc1, bc2, bc3, bc4;

        long state0 = state[0];
        long state1 = state[1];
        long state2 = state[2];
        long state3 = state[3];
        long state4 = state[4];
        long state5 = state[5];
        long state6 = state[6];
        long state7 = state[7];
        long state8 = state[8];
        long state9 = state[9];
        long state10 = state[10];
        long state11 = state[11];
        long state12 = state[12];
        long state13 = state[13];
        long state14 = state[14];
        long state15 = state[15];
        long state16 = state[16];
        long state17 = state[17];
        long state18 = state[18];
        long state19 = state[19];
        long state20 = state[20];
        long state21 = state[21];
        long state22 = state[22];
        long state23 = state[23];
        long state24 = state[24];

        for (int r = 24 - rounds; r < 24; r++) {

            bc0 = state0 ^ state5 ^ state10 ^ state15 ^ state20;
            bc1 = state1 ^ state6 ^ state11 ^ state16 ^ state21;
            bc2 = state2 ^ state7 ^ state12 ^ state17 ^ state22;
            bc3 = state3 ^ state8 ^ state13 ^ state18 ^ state23;
            bc4 = state4 ^ state9 ^ state14 ^ state19 ^ state24;

            temp = bc4 ^ Long.rotateLeft(bc1, 1);
            state0 ^= temp;
            state5 ^= temp;
            state10 ^= temp;
            state15 ^= temp;
            state20 ^= temp;

            temp = bc0 ^ Long.rotateLeft(bc2, 1);
            state1 ^= temp;
            state6 ^= temp;
            state11 ^= temp;
            state16 ^= temp;
            state21 ^= temp;

            temp = bc1 ^ Long.rotateLeft(bc3, 1);
            state2 ^= temp;
            state7 ^= temp;
            state12 ^= temp;
            state17 ^= temp;
            state22 ^= temp;

            temp = bc2 ^ Long.rotateLeft(bc4, 1);
            state3 ^= temp;
            state8 ^= temp;
            state13 ^= temp;
            state18 ^= temp;
            state23 ^= temp;

            temp = bc3 ^ Long.rotateLeft(bc0, 1);
            state4 ^= temp;
            state9 ^= temp;
            state14 ^= temp;
            state19 ^= temp;
            state24 ^= temp;

            temp = state1;
            state1 = Long.rotateLeft(state6, 44);
            state6 = Long.rotateLeft(state9, 20);
            state9 = Long.rotateLeft(state22, 61);
            state22 = Long.rotateLeft(state14, 39);
            state14 = Long.rotateLeft(state20, 18);
            state20 = Long.rotateLeft(state2, 62);
            state2 = Long.rotateLeft(state12, 43);
            state12 = Long.rotateLeft(state13, 25);
            state13 = Long.rotateLeft(state19, 8);
            state19 = Long.rotateLeft(state23, 56);
            state23 = Long.rotateLeft(state15, 41);
            state15 = Long.rotateLeft(state4, 27);
            state4 = Long.rotateLeft(state24, 14);
            state24 = Long.rotateLeft(state21, 2);
            state21 = Long.rotateLeft(state8, 55);
            state8 = Long.rotateLeft(state16, 45);
            state16 = Long.rotateLeft(state5, 36);
            state5 = Long.rotateLeft(state3, 28);
            state3 = Long.rotateLeft(state18, 21);
            state18 = Long.rotateLeft(state17, 15);
            state17 = Long.rotateLeft(state11, 10);
            state11 = Long.rotateLeft(state7, 6);
            state7 = Long.rotateLeft(state10, 3);
            state10 = Long.rotateLeft(temp, 1);

            bc0 = state0;
            bc1 = state1;
            bc2 = state2;
            bc3 = state3;
            bc4 = state4;

            state0 ^= ~bc1 & bc2;
            state1 ^= ~bc2 & bc3;
            state2 ^= ~bc3 & bc4;
            state3 ^= ~bc4 & bc0;
            state4 ^= ~bc0 & bc1;

            bc0 = state5;
            bc1 = state6;
            bc2 = state7;
            bc3 = state8;
            bc4 = state9;

            state5 ^= ~bc1 & bc2;
            state6 ^= ~bc2 & bc3;
            state7 ^= ~bc3 & bc4;
            state8 ^= ~bc4 & bc0;
            state9 ^= ~bc0 & bc1;

            bc0 = state10;
            bc1 = state11;
            bc2 = state12;
            bc3 = state13;
            bc4 = state14;

            state10 ^= ~bc1 & bc2;
            state11 ^= ~bc2 & bc3;
            state12 ^= ~bc3 & bc4;
            state13 ^= ~bc4 & bc0;
            state14 ^= ~bc0 & bc1;

            bc0 = state15;
            bc1 = state16;
            bc2 = state17;
            bc3 = state18;
            bc4 = state19;

            state15 ^= ~bc1 & bc2;
            state16 ^= ~bc2 & bc3;
            state17 ^= ~bc3 & bc4;
            state18 ^= ~bc4 & bc0;
            state19 ^= ~bc0 & bc1;

            bc0 = state20;
            bc1 = state21;
            bc2 = state22;
            bc3 = state23;
            bc4 = state24;

            state20 ^= ~bc1 & bc2;
            state21 ^= ~bc2 & bc3;
            state22 ^= ~bc3 & bc4;
            state23 ^= ~bc4 & bc0;
            state24 ^= ~bc0 & bc1;

            state0 ^= RNDC_1600[r];

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
        state[12] = state12;
        state[13] = state13;
        state[14] = state14;
        state[15] = state15;
        state[16] = state16;
        state[17] = state17;
        state[18] = state18;
        state[19] = state19;
        state[20] = state20;
        state[21] = state21;
        state[22] = state22;
        state[23] = state23;
        state[24] = state24;

    }

    /**
     * performs a single round of the Keccak-p[1600] permutation. This is
     * equivalent to the last round of the Keccak-f[1600] permutation
     *
     * @param state
     */
    public static void keccak_p1600_oneround(long[] state) {
        long temp, temp0, temp1, temp2, temp3, temp4, bc0, bc1, bc2, bc3, bc4;

        long state0 = state[0];
        long state1 = state[1];
        long state2 = state[2];
        long state3 = state[3];
        long state4 = state[4];
        long state5 = state[5];
        long state6 = state[6];
        long state7 = state[7];
        long state8 = state[8];
        long state9 = state[9];
        long state10 = state[10];
        long state11 = state[11];
        long state12 = state[12];
        long state13 = state[13];
        long state14 = state[14];
        long state15 = state[15];
        long state16 = state[16];
        long state17 = state[17];
        long state18 = state[18];
        long state19 = state[19];
        long state20 = state[20];
        long state21 = state[21];
        long state22 = state[22];
        long state23 = state[23];
        long state24 = state[24];

        bc0 = state0 ^ state5 ^ state10 ^ state15 ^ state20;
        bc1 = state1 ^ state6 ^ state11 ^ state16 ^ state21;
        bc2 = state2 ^ state7 ^ state12 ^ state17 ^ state22;
        bc3 = state3 ^ state8 ^ state13 ^ state18 ^ state23;
        bc4 = state4 ^ state9 ^ state14 ^ state19 ^ state24;

        temp0 = bc4 ^ Long.rotateLeft(bc1, 1);
        temp1 = bc0 ^ Long.rotateLeft(bc2, 1);
        temp2 = bc1 ^ Long.rotateLeft(bc3, 1);
        temp3 = bc2 ^ Long.rotateLeft(bc4, 1);
        temp4 = bc3 ^ Long.rotateLeft(bc0, 1);

        temp = state1 ^ temp1;
        state1 = Long.rotateLeft(state6 ^ temp1, 44);
        state6 = Long.rotateLeft(state9 ^ temp4, 20);
        state9 = Long.rotateLeft(state22 ^ temp2, 61);
        state22 = Long.rotateLeft(state14 ^ temp4, 39);
        state14 = Long.rotateLeft(state20 ^ temp0, 18);
        state20 = Long.rotateLeft(state2 ^ temp2, 62);
        state2 = Long.rotateLeft(state12 ^ temp2, 43);
        state12 = Long.rotateLeft(state13 ^ temp3, 25);
        state13 = Long.rotateLeft(state19 ^ temp4, 8);
        state19 = Long.rotateLeft(state23 ^ temp3, 56);
        state23 = Long.rotateLeft(state15 ^ temp0, 41);
        state15 = Long.rotateLeft(state4 ^ temp4, 27);
        state4 = Long.rotateLeft(state24 ^ temp4, 14);
        state24 = Long.rotateLeft(state21 ^ temp1, 2);
        state21 = Long.rotateLeft(state8 ^ temp3, 55);
        state8 = Long.rotateLeft(state16 ^ temp1, 45);
        state16 = Long.rotateLeft(state5 ^ temp0, 36);
        state5 = Long.rotateLeft(state3 ^ temp3, 28);
        state3 = Long.rotateLeft(state18 ^ temp3, 21);
        state18 = Long.rotateLeft(state17 ^ temp2, 15);
        state17 = Long.rotateLeft(state11 ^ temp1, 10);
        state11 = Long.rotateLeft(state7 ^ temp2, 6);
        state7 = Long.rotateLeft(state10 ^ temp0, 3);
        state10 = Long.rotateLeft(temp, 1);

        state[0] = state0 ^ (~state1 & state2) ^ RNDC_1600[23];
        state[1] = state1 ^ (~state2 & state3);
        state[2] = state2 ^ (~state3 & state4);
        state[3] = state3 ^ (~state4 & state0);
        state[4] = state4 ^ (~state0 & state1);

        state[5] = state5 ^ (~state6 & state7);
        state[6] = state6 ^ (~state7 & state8);
        state[7] = state7 ^ (~state8 & state9);
        state[8] = state8 ^ (~state9 & state5);
        state[9] = state9 ^ (~state5 & state6);

        state[10] = state10 ^ (~state11 & state12);
        state[11] = state11 ^ (~state12 & state13);
        state[12] = state12 ^ (~state13 & state14);
        state[13] = state13 ^ (~state14 & state10);
        state[14] = state14 ^ (~state10 & state11);

        state[15] = state15 ^ (~state16 & state17);
        state[16] = state16 ^ (~state17 & state18);
        state[17] = state17 ^ (~state18 & state19);
        state[18] = state18 ^ (~state19 & state15);
        state[19] = state19 ^ (~state15 & state16);

        state[20] = state20 ^ (~state21 & state22);
        state[21] = state21 ^ (~state22 & state23);
        state[22] = state22 ^ (~state23 & state24);
        state[23] = state23 ^ (~state24 & state20);
        state[24] = state24 ^ (~state20 & state21);

    }

    /**
     * performs the 22-round Keccak-f[800] permutation on the state
     *
     * @param state
     */
    public static void keccak_f800(int[] state) {
        keccak_p800(state, 22);
    }

    /**
     * performs the last {@code rounds} rounds of the Keccak-f[800] permutation
     * on the state
     *
     * @param state
     * @param rounds
     */
    public static void keccak_p800(int[] state, int rounds) {
        int temp, bc0, bc1, bc2, bc3, bc4;

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
        int state12 = state[12];
        int state13 = state[13];
        int state14 = state[14];
        int state15 = state[15];
        int state16 = state[16];
        int state17 = state[17];
        int state18 = state[18];
        int state19 = state[19];
        int state20 = state[20];
        int state21 = state[21];
        int state22 = state[22];
        int state23 = state[23];
        int state24 = state[24];

        for (int r = 22 - rounds; r < 22; r++) {

            bc0 = state0 ^ state5 ^ state10 ^ state15 ^ state20;
            bc1 = state1 ^ state6 ^ state11 ^ state16 ^ state21;
            bc2 = state2 ^ state7 ^ state12 ^ state17 ^ state22;
            bc3 = state3 ^ state8 ^ state13 ^ state18 ^ state23;
            bc4 = state4 ^ state9 ^ state14 ^ state19 ^ state24;

            temp = bc4 ^ Integer.rotateLeft(bc1, 1);
            state0 ^= temp;
            state5 ^= temp;
            state10 ^= temp;
            state15 ^= temp;
            state20 ^= temp;

            temp = bc0 ^ Integer.rotateLeft(bc2, 1);
            state1 ^= temp;
            state6 ^= temp;
            state11 ^= temp;
            state16 ^= temp;
            state21 ^= temp;

            temp = bc1 ^ Integer.rotateLeft(bc3, 1);
            state2 ^= temp;
            state7 ^= temp;
            state12 ^= temp;
            state17 ^= temp;
            state22 ^= temp;

            temp = bc2 ^ Integer.rotateLeft(bc4, 1);
            state3 ^= temp;
            state8 ^= temp;
            state13 ^= temp;
            state18 ^= temp;
            state23 ^= temp;

            temp = bc3 ^ Integer.rotateLeft(bc0, 1);
            state4 ^= temp;
            state9 ^= temp;
            state14 ^= temp;
            state19 ^= temp;
            state24 ^= temp;

            temp = state1;
            state1 = Integer.rotateLeft(state6, 12);
            state6 = Integer.rotateLeft(state9, 20);
            state9 = Integer.rotateLeft(state22, 29);
            state22 = Integer.rotateLeft(state14, 7);
            state14 = Integer.rotateLeft(state20, 18);
            state20 = Integer.rotateLeft(state2, 30);
            state2 = Integer.rotateLeft(state12, 11);
            state12 = Integer.rotateLeft(state13, 25);
            state13 = Integer.rotateLeft(state19, 8);
            state19 = Integer.rotateLeft(state23, 24);
            state23 = Integer.rotateLeft(state15, 9);
            state15 = Integer.rotateLeft(state4, 27);
            state4 = Integer.rotateLeft(state24, 14);
            state24 = Integer.rotateLeft(state21, 2);
            state21 = Integer.rotateLeft(state8, 23);
            state8 = Integer.rotateLeft(state16, 13);
            state16 = Integer.rotateLeft(state5, 4);
            state5 = Integer.rotateLeft(state3, 28);
            state3 = Integer.rotateLeft(state18, 21);
            state18 = Integer.rotateLeft(state17, 15);
            state17 = Integer.rotateLeft(state11, 10);
            state11 = Integer.rotateLeft(state7, 6);
            state7 = Integer.rotateLeft(state10, 3);
            state10 = Integer.rotateLeft(temp, 1);

            bc0 = state0;
            bc1 = state1;
            bc2 = state2;
            bc3 = state3;
            bc4 = state4;

            state0 ^= ~bc1 & bc2;
            state1 ^= ~bc2 & bc3;
            state2 ^= ~bc3 & bc4;
            state3 ^= ~bc4 & bc0;
            state4 ^= ~bc0 & bc1;

            bc0 = state5;
            bc1 = state6;
            bc2 = state7;
            bc3 = state8;
            bc4 = state9;

            state5 ^= ~bc1 & bc2;
            state6 ^= ~bc2 & bc3;
            state7 ^= ~bc3 & bc4;
            state8 ^= ~bc4 & bc0;
            state9 ^= ~bc0 & bc1;

            bc0 = state10;
            bc1 = state11;
            bc2 = state12;
            bc3 = state13;
            bc4 = state14;

            state10 ^= ~bc1 & bc2;
            state11 ^= ~bc2 & bc3;
            state12 ^= ~bc3 & bc4;
            state13 ^= ~bc4 & bc0;
            state14 ^= ~bc0 & bc1;

            bc0 = state15;
            bc1 = state16;
            bc2 = state17;
            bc3 = state18;
            bc4 = state20;

            state15 ^= ~bc1 & bc2;
            state16 ^= ~bc2 & bc3;
            state17 ^= ~bc3 & bc4;
            state18 ^= ~bc4 & bc0;
            state19 ^= ~bc0 & bc1;

            bc0 = state20;
            bc1 = state21;
            bc2 = state22;
            bc3 = state23;
            bc4 = state24;

            state20 ^= ~bc1 & bc2;
            state21 ^= ~bc2 & bc3;
            state22 ^= ~bc3 & bc4;
            state23 ^= ~bc4 & bc0;
            state24 ^= ~bc0 & bc1;

            state0 ^= RNDC_800[r];

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
        state[12] = state12;
        state[13] = state13;
        state[14] = state14;
        state[15] = state15;
        state[16] = state16;
        state[17] = state17;
        state[18] = state18;
        state[19] = state19;
        state[20] = state20;
        state[21] = state21;
        state[22] = state22;
        state[23] = state23;
        state[24] = state24;

    }

    public static void keccak_p800_oneround(int[] state) {
        int temp, temp0, temp1, temp2, temp3, temp4, bc0, bc1, bc2, bc3, bc4;

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
        int state12 = state[12];
        int state13 = state[13];
        int state14 = state[14];
        int state15 = state[15];
        int state16 = state[16];
        int state17 = state[17];
        int state18 = state[18];
        int state19 = state[19];
        int state20 = state[20];
        int state21 = state[21];
        int state22 = state[22];
        int state23 = state[23];
        int state24 = state[24];

        bc0 = state0 ^ state5 ^ state10 ^ state15 ^ state20;
        bc1 = state1 ^ state6 ^ state11 ^ state16 ^ state21;
        bc2 = state2 ^ state7 ^ state12 ^ state17 ^ state22;
        bc3 = state3 ^ state8 ^ state13 ^ state18 ^ state23;
        bc4 = state4 ^ state9 ^ state14 ^ state19 ^ state24;

        temp0 = bc4 ^ Integer.rotateLeft(bc1, 1);
        temp1 = bc0 ^ Integer.rotateLeft(bc2, 1);
        temp2 = bc1 ^ Integer.rotateLeft(bc3, 1);
        temp3 = bc2 ^ Integer.rotateLeft(bc4, 1);
        temp4 = bc3 ^ Integer.rotateLeft(bc0, 1);

        temp = state1 ^ temp1;
        state1 = Integer.rotateLeft(state6 ^ temp1, 12);
        state6 = Integer.rotateLeft(state9 ^ temp4, 20);
        state9 = Integer.rotateLeft(state22 ^ temp2, 29);
        state22 = Integer.rotateLeft(state14 ^ temp4, 7);
        state14 = Integer.rotateLeft(state20 ^ temp0, 18);
        state20 = Integer.rotateLeft(state2 ^ temp2, 30);
        state2 = Integer.rotateLeft(state12 ^ temp2, 11);
        state12 = Integer.rotateLeft(state13 ^ temp3, 25);
        state13 = Integer.rotateLeft(state19 ^ temp4, 8);
        state19 = Integer.rotateLeft(state23 ^ temp3, 24);
        state23 = Integer.rotateLeft(state15 ^ temp0, 9);
        state15 = Integer.rotateLeft(state4 ^ temp4, 27);
        state4 = Integer.rotateLeft(state24 ^ temp4, 14);
        state24 = Integer.rotateLeft(state21 ^ temp1, 2);
        state21 = Integer.rotateLeft(state8 ^ temp3, 23);
        state8 = Integer.rotateLeft(state16 ^ temp1, 13);
        state16 = Integer.rotateLeft(state5 ^ temp0, 4);
        state5 = Integer.rotateLeft(state3 ^ temp3, 28);
        state3 = Integer.rotateLeft(state18 ^ temp3, 21);
        state18 = Integer.rotateLeft(state17 ^ temp2, 15);
        state17 = Integer.rotateLeft(state11 ^ temp1, 10);
        state11 = Integer.rotateLeft(state7 ^ temp2, 6);
        state7 = Integer.rotateLeft(state10 ^ temp0, 3);
        state10 = Integer.rotateLeft(temp, 1);

        state[0] = state0 ^ (~state1 & state2) ^ RNDC_800[21];
        state[1] = state1 ^ (~state2 & state3);
        state[2] = state2 ^ (~state3 & state4);
        state[3] = state3 ^ (~state4 & state0);
        state[4] = state4 ^ (~state0 & state1);

        state[5] = state5 ^ (~state6 & state7);
        state[6] = state6 ^ (~state7 & state8);
        state[7] = state7 ^ (~state8 & state9);
        state[8] = state8 ^ (~state9 & state5);
        state[9] = state9 ^ (~state5 & state6);

        state[10] = state10 ^ (~state11 & state12);
        state[11] = state11 ^ (~state12 & state13);
        state[12] = state12 ^ (~state13 & state14);
        state[13] = state13 ^ (~state14 & state10);
        state[14] = state14 ^ (~state10 & state11);

        state[15] = state15 ^ (~state16 & state17);
        state[16] = state16 ^ (~state17 & state18);
        state[17] = state17 ^ (~state18 & state19);
        state[18] = state18 ^ (~state19 & state15);
        state[19] = state19 ^ (~state15 & state16);

        state[20] = state20 ^ (~state21 & state22);
        state[21] = state21 ^ (~state22 & state23);
        state[22] = state22 ^ (~state23 & state24);
        state[23] = state23 ^ (~state24 & state20);
        state[24] = state24 ^ (~state20 & state21);

    }

}
