/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.hash;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.MemorySession;
import java.lang.foreign.ValueLayout;
import java.util.Arrays;
import java.util.Objects;
import org.asterisk.crypto.Tested;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.interfaces.Xof;

import static org.asterisk.crypto.helper.Tools.store64LE;
import static org.asterisk.crypto.lowlevel.KeccakP.keccak_p1600;

/**
 *
 * @author Sayantan Chakraborty
 */
public class KangarooTwelve implements Xof {

    private static final int BLOCK_SIZE = 168, CHUNK_SIZE = 8192;

    @Tested
    public static final KangarooTwelve DEFAULT = new KangarooTwelve(new byte[0]);

    public static byte[] lengthEncode(long length) {
        byte[] ret = new byte[Math.ceilDiv(64 - Long.numberOfLeadingZeros(length), 8) + 1];
        for (int i = ret.length - 2; length != 0; i--, length >>>= 8) {
            ret[i] = (byte) (length & 0xff);
        }
        ret[ret.length - 1] = (byte) (ret.length - 1);
        return ret;
    }

    @Tested
    public static KangarooTwelve customized(String customization) {
        return new KangarooTwelve(customization.getBytes());
    }

    private final byte[] customization, lengthEncoded;

    private KangarooTwelve(byte[] customization) {
        this.customization = customization;
        lengthEncoded = lengthEncode(customization.length);
    }

    @Override
    public Engine start() {
        return new Xof.Engine() {

            private final Node root = new Node();
            private Node current = root;

            private final long[] output = new long[4];

            private final byte[] digestBuffer = new byte[BLOCK_SIZE];
            private long chunkCtr = 0;

            private int chunkPos = 0;

            @Override
            public void ingest(MemorySegment input) {
                long length = input.byteSize(), offset = 0;
                if (chunkPos > 0) {
                    int take = (int) Math.min(length, CHUNK_SIZE - chunkPos);
                    current.ingest(input, offset, take);
                    offset += take;
                    length -= take;
                    chunkPos += take;
                    if (chunkPos == CHUNK_SIZE && length > 0) {
                        if (chunkCtr++ == 0) {
                            current = new Node();
                            root.star();
                        } else {
                            current.chain(0x0b, output);
                            root.chain(output);
                            current.reset();
                        }
                        chunkPos = 0;
                    }
                }
                while (length > CHUNK_SIZE) {

                    current.ingestWholeChunk(input, offset, 0x0b, output);
                    root.chain(output);
                    current.reset();

                    chunkCtr++;

                    offset += CHUNK_SIZE;
                    length -= CHUNK_SIZE;
                }

                if (length > 0) {
                    current.ingest(input, offset, length);
                    chunkPos = (int) length;
                }
            }

            @Override
            public void startDigesting() {
                ingest(customization);
                ingest(lengthEncoded);
                if (chunkCtr == 0) {
                    root.startDigesting((byte) 0x07);
                } else {
                    current.chainLast((byte) 0x0b, output);
                    root.chain(output);

                    root.ingest(lengthEncode(chunkCtr));
                    root.ingest((byte) 0xff, (byte) 0xff);

                    root.startDigesting((byte) 0x06);
                }
                chunkPos = 0;
            }

            @Override
            public void continueDigesting(byte[] dest, int offset, int length) {
                Objects.checkFromIndexSize(offset, length, dest.length);
                if (chunkPos > 0) {
                    int give = Math.min(BLOCK_SIZE - chunkPos, length);
                    System.arraycopy(digestBuffer, chunkPos, dest, offset, give);
                    chunkPos += give;
                    offset += give;
                    length -= give;
                    if (chunkPos == BLOCK_SIZE) {
                        chunkPos = 0;
                    }
                }
                while (length >= BLOCK_SIZE) {
                    root.digestOneBlock(dest, offset);
                    offset += BLOCK_SIZE;
                    length -= BLOCK_SIZE;
                }
                if (length > 0) {
                    root.digestOneBlock(digestBuffer, 0);
                    System.arraycopy(digestBuffer, 0, dest, offset, length);
                    chunkPos = length;
                }
            }

            @Override
            public Xof getAlgorithm() {
                return KangarooTwelve.this;
            }
        };
    }

    @Override
    public int digestSize() {
        return 32;
    }

    @Override
    public int blockSize() {
        return BLOCK_SIZE;
    }

    private static class Node {

        private static final ValueLayout.OfLong LAYOUT = Tools.LITTLE_ENDIAN_64_BIT;

        private final long[] state = new long[25];
        private final MemorySegment buffer = MemorySegment.allocateNative(BLOCK_SIZE, MemorySession.global());
        private int position = 0;

        private void round(MemorySegment input, long offset) {
            for (int i = 0; i < 21; i++) {
                state[i] ^= input.get(LAYOUT, offset + 8 * i);
            }
            keccak_p1600(state, 12);
        }

        public void ingestWholeChunk(MemorySegment input, long offset, int delimitedSuffix, long[] output) {
            assert position == 0;

            for (int i = 0; i < 48; i++) {
                round(input, offset);
                offset += BLOCK_SIZE;
            }

            for (int i = 0; i < 16; i++) {
                state[i] ^= input.get(LAYOUT, offset + 8 * i);
            }

            state[16] ^= delimitedSuffix;
            state[20] ^= 0x8000000000000000L;

            keccak_p1600(state, 12);

            output[0] = state[0];
            output[1] = state[1];
            output[2] = state[2];
            output[3] = state[3];

        }

        public void ingest(byte... input) {
            ingest(MemorySegment.ofArray(input), 0, input.length);
        }

        public void ingest(MemorySegment input, long offset, long length) {
            if (position > 0) {
                int take = (int) Math.min(length, BLOCK_SIZE - position);
                MemorySegment.copy(input, offset, buffer, position, take);
                offset += take;
                length -= take;
                position += take;
                if (position == BLOCK_SIZE) {
                    round(buffer, 0);
                    position = 0;
                }
            }
            while (length >= BLOCK_SIZE) {
                round(input, offset);
                offset += BLOCK_SIZE;
                length -= BLOCK_SIZE;
            }
            if (length > 0) {
                MemorySegment.copy(input, offset, buffer, 0, length);
                position = (int) length;
            }
        }

        public void chain(long[] output) {
            assert (position & 7) == 0;

            int x = position >>> 3;

            switch (x) {
                case 17 -> {
                    state[17] ^= output[0];
                    state[18] ^= output[1];
                    state[19] ^= output[2];
                    state[20] ^= output[3];
                    keccak_p1600(state, 12);
                    position = 0;
                }
                case 18 -> {
                    state[18] ^= output[0];
                    state[19] ^= output[1];
                    state[20] ^= output[2];
                    keccak_p1600(state, 12);
                    state[0] ^= output[3];
                    position = 8;
                }
                case 19 -> {
                    state[19] ^= output[0];
                    state[20] ^= output[1];
                    keccak_p1600(state, 12);
                    state[0] ^= output[2];
                    state[1] ^= output[3];
                    position = 16;
                }
                case 20 -> {
                    state[20] ^= output[0];
                    keccak_p1600(state, 12);
                    state[0] ^= output[1];
                    state[1] ^= output[2];
                    state[2] ^= output[3];
                    position = 24;
                }
                default -> {
                    state[x + 0] ^= output[0];
                    state[x + 1] ^= output[1];
                    state[x + 2] ^= output[2];
                    state[x + 3] ^= output[3];
                    position += 32;
                }
            }
        }

        public void chainLast(byte delimitedSuffix, long[] output) {
            buffer.set(ValueLayout.JAVA_BYTE, position++, delimitedSuffix);
            if (position == BLOCK_SIZE) {
                round(buffer, 0);
                position = 0;
            }
            buffer.asSlice(position).fill((byte) 0);
            buffer.set(ValueLayout.JAVA_BYTE, BLOCK_SIZE - 1, (byte) 0x80);

            round(buffer, 0);

            output[0] = state[0];
            output[1] = state[1];
            output[2] = state[2];
            output[3] = state[3];
        }

        private void chain(int delimitedSuffix, long[] output) {
            assert position == 128;

            for (int i = 0; i < 16; i++) {
                state[i] ^= buffer.get(LAYOUT, 8 * i);
            }

            state[16] ^= delimitedSuffix;
            state[20] ^= 0x8000000000000000L;

            keccak_p1600(state, 12);

            output[0] = state[0];
            output[1] = state[1];
            output[2] = state[2];
            output[3] = state[3];
        }

        private void star() {
            assert position == 128;

            for (int i = 0; i < 16; i++) {
                state[i] ^= buffer.get(LAYOUT, 8 * i);
            }

            state[16] ^= 0x03;

            buffer.fill((byte) 0);

            position = 136;
        }

        public void startDigesting(byte delimitedSuffix) {
            buffer.set(ValueLayout.JAVA_BYTE, position++, delimitedSuffix);
            if (position == BLOCK_SIZE) {
                round(buffer, 0);
                position = 0;
            }
            buffer.asSlice(position).fill((byte) 0);
            buffer.set(ValueLayout.JAVA_BYTE, BLOCK_SIZE - 1, (byte) 0x80);

            for (int i = 0; i < 21; i++) {
                state[i] ^= buffer.get(LAYOUT, 8 * i);
            }
        }

        public void digestOneBlock(byte[] output, int offset) {
            keccak_p1600(state, 12);

            for (int i = 0; i < 21; i++) {
                store64LE(state[i], output, offset + 8 * i);
            }
        }

        public void reset() {
            Arrays.fill(state, 0);
            position = 0;
        }

    }

}
