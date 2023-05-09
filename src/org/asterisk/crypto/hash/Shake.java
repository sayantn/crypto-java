/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.hash;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import org.asterisk.crypto.helper.AbstractXofEngine;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.interfaces.Xof;
import org.asterisk.crypto.lowlevel.KeccakP;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum Shake implements Xof {

    SHAKE_128 {
        @Override
        public Engine start() {
            return new AbstractXofEngine(168, 168) {

                private final long[] state = new long[25];

                @Override
                protected void ingestOneBlock(MemorySegment input, long offset) {
                    for (int i = 0; i < 21; i++) {
                        state[i] ^= input.get(Shake.LAYOUT, offset + 8 * i);
                    }
                    KeccakP.keccak_f1600(state);
                }

                @Override
                protected void ingestLastBlock(MemorySegment input, int length) {
                    if (length == 168) {
                        ingestOneBlock(input, 0);
                        length = 0;
                    }

                    if (length == 167) {
                        input.set(ValueLayout.JAVA_BYTE, length, (byte) 0x9f);
                    } else {
                        input.set(ValueLayout.JAVA_BYTE, length, (byte) 0x1f);
                        input.asSlice(length + 1, 166 - length).fill((byte) 0);
                        input.set(ValueLayout.JAVA_BYTE, 167, (byte) 0x80);
                    }

                    for (int i = 0; i < 21; i++) {
                        state[i] ^= input.get(Shake.LAYOUT, 8 * i);
                    }
                }

                @Override
                protected void digestOneBlock(byte[] dest, int offset) {
                    KeccakP.keccak_f1600(state);

                    for (int i = 0; i < 21; i++) {
                        Tools.store64LE(state[i], dest, offset + 8 * i);
                    }
                }

                @Override
                public Xof getAlgorithm() {
                    return Shake.SHAKE_128;
                }

            };
        }

        @Override
        public int digestSize() {
            return 32;
        }

        @Override
        public int blockSize() {
            return 168;
        }

    }, SHAKE_256 {
        @Override
        public Engine start() {
            return new AbstractXofEngine(136, 136) {

                private final long[] state = new long[25];

                @Override
                protected void ingestOneBlock(MemorySegment input, long offset) {
                    for (int i = 0; i < 17; i++) {
                        state[i] ^= input.get(Shake.LAYOUT, offset + 8 * i);
                    }
                    KeccakP.keccak_f1600(state);
                }

                @Override
                protected void ingestLastBlock(MemorySegment input, int length) {
                    if (length == 136) {
                        ingestOneBlock(input, 0);
                        length = 0;
                    }

                    if (length == 135) {
                        input.set(ValueLayout.JAVA_BYTE, length, (byte) 0x9f);
                    } else {
                        input.set(ValueLayout.JAVA_BYTE, length, (byte) 0x1f);
                        input.asSlice(length + 1, 134 - length).fill((byte) 0);
                        input.set(ValueLayout.JAVA_BYTE, 135, (byte) 0x80);
                    }

                    for (int i = 0; i < 17; i++) {
                        state[i] ^= input.get(Shake.LAYOUT, 8 * i);
                    }
                }

                @Override
                protected void digestOneBlock(byte[] dest, int offset) {
                    KeccakP.keccak_f1600(state);

                    for (int i = 0; i < 17; i++) {
                        Tools.store64LE(state[i], dest, offset + 8 * i);
                    }
                }

                @Override
                public Xof getAlgorithm() {
                    return Shake.SHAKE_256;
                }

            };
        }

        @Override
        public int digestSize() {
            return 64;
        }

        @Override
        public int blockSize() {
            return 136;
        }

    };

    private static final ValueLayout.OfLong LAYOUT = Tools.LITTLE_ENDIAN_64_BIT;

}
