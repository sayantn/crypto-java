/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.hash;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import org.asterisk.crypto.Tested;
import org.asterisk.crypto.helper.AbstractDigestEngine;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.Digest;
import org.asterisk.crypto.lowlevel.KeccakP;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum Sha3 implements Digest {

    @Tested
    SHA3_256 {
        @Override
        public Engine start() {
            return new AbstractDigestEngine(136) {

                private final long[] state = new long[25];

                @Override
                protected void ingestOneBlock(MemorySegment input, long offset) {
                    for (int i = 0; i < 17; i++) {
                        state[i] ^= input.get(Sha3.LAYOUT, offset + 8 * i);
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
                        input.set(ValueLayout.JAVA_BYTE, length, (byte) 0x86);
                    } else {
                        input.set(ValueLayout.JAVA_BYTE, length, (byte) 0x06);
                        input.asSlice(length + 1, 134 - length).fill((byte) 0);
                        input.set(ValueLayout.JAVA_BYTE, 135, (byte) 0x80);
                    }

                    ingestOneBlock(input, 0);

                }

                @Override
                protected void getDigest(byte[] dest, int offset) {
                    Tools.store64LE(state[0], dest, offset + 0);
                    Tools.store64LE(state[1], dest, offset + 8);
                    Tools.store64LE(state[2], dest, offset + 16);
                    Tools.store64LE(state[3], dest, offset + 24);
                }

                @Override
                public Digest getAlgorithm() {
                    return Sha3.SHA3_256;
                }

            };
        }

        @Override
        public int digestSize() {
            return 32;
        }

        @Override
        public int blockSize() {
            return 136;
        }

    }, @Tested
    SHA3_224 {
        @Override
        public Engine start() {
            return new AbstractDigestEngine(144) {

                private final long[] state = new long[25];

                @Override
                protected void ingestOneBlock(MemorySegment input, long offset) {
                    for (int i = 0; i < 18; i++) {
                        state[i] ^= input.get(Sha3.LAYOUT, offset + 8 * i);
                    }
                    KeccakP.keccak_f1600(state);
                }

                @Override
                protected void ingestLastBlock(MemorySegment input, int length) {
                    if (length == 144) {
                        ingestOneBlock(input, 0);
                        length = 0;
                    }

                    if (length == 143) {
                        input.set(ValueLayout.JAVA_BYTE, length, (byte) 0x86);
                    } else {
                        input.set(ValueLayout.JAVA_BYTE, length, (byte) 0x06);
                        input.asSlice(length + 1, 142 - length).fill((byte) 0);
                        input.set(ValueLayout.JAVA_BYTE, 143, (byte) 0x80);
                    }

                    ingestOneBlock(input, 0);

                }

                @Override
                protected void getDigest(byte[] dest, int offset) {
                    Tools.store64LE(state[0], dest, offset + 0);
                    Tools.store64LE(state[1], dest, offset + 8);
                    Tools.store64LE(state[2], dest, offset + 16);
                    Tools.store32LE((int) state[3], dest, offset + 24);
                }

                @Override
                public Digest getAlgorithm() {
                    return Sha3.SHA3_224;
                }

            };
        }

        @Override
        public int digestSize() {
            return 28;
        }

        @Override
        public int blockSize() {
            return 144;
        }

    }, @Tested
    SHA3_512 {
        @Override
        public Engine start() {
            return new AbstractDigestEngine(72) {

                private final long[] state = new long[25];

                @Override
                protected void ingestOneBlock(MemorySegment input, long offset) {
                    for (int i = 0; i < 9; i++) {
                        state[i] ^= input.get(Sha3.LAYOUT, offset + 8 * i);
                    }
                    KeccakP.keccak_f1600(state);
                }

                @Override
                protected void ingestLastBlock(MemorySegment input, int length) {
                    if (length == 72) {
                        ingestOneBlock(input, 0);
                        length = 0;
                    }

                    if (length == 71) {
                        input.set(ValueLayout.JAVA_BYTE, length, (byte) 0x86);
                    } else {
                        input.set(ValueLayout.JAVA_BYTE, length, (byte) 0x06);
                        input.asSlice(length + 1, 70 - length).fill((byte) 0);
                        input.set(ValueLayout.JAVA_BYTE, 71, (byte) 0x80);
                    }

                    ingestOneBlock(input, 0);

                }

                @Override
                protected void getDigest(byte[] dest, int offset) {
                    Tools.store64LE(state[0], dest, offset + 0);
                    Tools.store64LE(state[1], dest, offset + 8);
                    Tools.store64LE(state[2], dest, offset + 16);
                    Tools.store64LE(state[3], dest, offset + 24);
                    Tools.store64LE(state[4], dest, offset + 32);
                    Tools.store64LE(state[5], dest, offset + 40);
                    Tools.store64LE(state[6], dest, offset + 48);
                    Tools.store64LE(state[7], dest, offset + 56);
                }

                @Override
                public Digest getAlgorithm() {
                    return Sha3.SHA3_256;
                }

            };
        }

        @Override
        public int digestSize() {
            return 64;
        }

        @Override
        public int blockSize() {
            return 72;
        }

    }, @Tested
    SHA3_384 {
        @Override
        public Engine start() {
            return new AbstractDigestEngine(104) {

                private final long[] state = new long[25];

                @Override
                protected void ingestOneBlock(MemorySegment input, long offset) {
                    for (int i = 0; i < 13; i++) {
                        state[i] ^= input.get(Sha3.LAYOUT, offset + 8 * i);
                    }
                    KeccakP.keccak_f1600(state);
                }

                @Override
                protected void ingestLastBlock(MemorySegment input, int length) {
                    if (length == 104) {
                        ingestOneBlock(input, 0);
                        length = 0;
                    }

                    if (length == 103) {
                        input.set(ValueLayout.JAVA_BYTE, length, (byte) 0x86);
                    } else {
                        input.set(ValueLayout.JAVA_BYTE, length, (byte) 0x06);
                        input.asSlice(length + 1, 102 - length).fill((byte) 0);
                        input.set(ValueLayout.JAVA_BYTE, 103, (byte) 0x80);
                    }

                    ingestOneBlock(input, 0);

                }

                @Override
                protected void getDigest(byte[] dest, int offset) {
                    Tools.store64LE(state[0], dest, offset + 0);
                    Tools.store64LE(state[1], dest, offset + 8);
                    Tools.store64LE(state[2], dest, offset + 16);
                    Tools.store64LE(state[3], dest, offset + 24);
                    Tools.store64LE(state[4], dest, offset + 32);
                    Tools.store64LE(state[5], dest, offset + 40);
                }

                @Override
                public Digest getAlgorithm() {
                    return Sha3.SHA3_256;
                }

            };
        }

        @Override
        public int digestSize() {
            return 48;
        }

        @Override
        public int blockSize() {
            return 104;
        }

    };

    private static final ValueLayout.OfLong LAYOUT = Tools.LITTLE_ENDIAN_64_BIT;

}
