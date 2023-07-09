/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.mac;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import org.asterisk.crypto.helper.AbstractMacEngine;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.Mac;
import org.asterisk.crypto.lowlevel.KeccakP;

/**
 * 5.3 cpb
 *
 * @author Sayantan Chakraborty
 */
public enum Kravatte implements Mac {

    KRAVATTE;

    private static final ValueLayout.OfLong LAYOUT = Tools.LITTLE_ENDIAN_64_BIT;

    private static void permute(long[] state) {
        KeccakP.keccak_p1600(state, 6);
    }

    private static void rollc(long[] state) {
        long temp = Long.rotateLeft(state[20], 7) ^ state[21] ^ (state[21] >>> 3);
        state[20] = state[21];
        state[21] = state[22];
        state[22] = state[23];
        state[23] = state[24];
        state[24] = temp;
    }

    private static void rolle(long[] state) {
        long temp = Long.rotateLeft(state[20], 7) ^ Long.rotateLeft(state[21], 18) ^ (state[22] & (state[21] >>> 1));
        state[20] = state[21];
        state[21] = state[22];
        state[22] = state[23];
        state[23] = state[24];
        state[24] = state[15];
        state[15] = state[16];
        state[16] = state[17];
        state[17] = state[18];
        state[18] = state[19];
        state[19] = temp;
    }

    @Override
    public Engine start(byte[] key) {
        return new AbstractMacEngine(200) {

            private final long[] rolledKey = new long[25], buffer = new long[25], accumulator = new long[25];

            {
                rolledKey[0] = Tools.load64LE(key, 0);
                rolledKey[1] = Tools.load64LE(key, 8);
                rolledKey[2] = Tools.load64LE(key, 16);
                rolledKey[3] = Tools.load64LE(key, 24);
                rolledKey[4] = 0x01;

                permute(rolledKey);
            }

            @Override
            protected void ingestOneBlock(MemorySegment input, long offset) {
                for (int i = 0; i < 25; i++) {
                    buffer[i] = input.get(LAYOUT, offset + 8 * i) ^ rolledKey[i];
                }
                permute(buffer);
                for (int i = 0; i < 25; i++) {
                    accumulator[i] ^= buffer[i];
                }
                rollc(rolledKey);
            }

            @Override
            protected void ingestLastBlock(MemorySegment input, int length) {
                if (length == 200) {
                    ingestOneBlock(input, 0);
                    length = 0;
                }
                input.set(ValueLayout.JAVA_BYTE, length, (byte) 0x01);
                Tools.zeropad(input, length + 1);
                for (int i = 0; i < 25; i++) {
                    buffer[i] = input.get(LAYOUT, 8 * i) ^ rolledKey[i];
                }
                permute(buffer);
                for (int i = 0; i < 25; i++) {
                    accumulator[i] ^= buffer[i];
                }
                rollc(rolledKey);

                rollc(rolledKey);
            }

            @Override
            protected void getTag(byte[] dest, int offset) {
                System.arraycopy(accumulator, 0, buffer, 0, 25);

                permute(buffer);
                rolle(buffer);
                permute(buffer);

                Tools.store64LE(buffer[0] ^ rolledKey[0], dest, offset + 0);
                Tools.store64LE(buffer[1] ^ rolledKey[1], dest, offset + 8);
            }

            @Override
            public Mac getAlgorithm() {
                return KRAVATTE;
            }
        };
    }

    @Override
    public int tagLength() {
        return 16;
    }

    @Override
    public int keyLength() {
        return 32;
    }

}
