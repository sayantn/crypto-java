/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.hash;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.MemorySession;
import java.lang.foreign.ValueLayout;
import java.util.Arrays;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.interfaces.Digest;
import org.asterisk.crypto.lowlevel.KeccakP;

import static org.asterisk.crypto.lowlevel.KeccakP.keccak_f1600;

/**
 *
 * @author Sayantan Chakraborty
 */
public class ParallelHash128 implements Digest {

    private static final int BLOCK_SIZE = 168, DIGEST_LEN = 32;

    private static final ValueLayout.OfLong LAYOUT = Tools.LITTLE_ENDIAN_64_BIT;

    private static final long PREFIX_0 = 0x01a8010c50617261L, PREFIX_1 = 0x6c6c656c48617368L;

    private static long[] precomputeState(byte[] customization) {
        if (customization.length > 150) {
            throw new UnsupportedOperationException("Customization strings of over 150 bytes are not supported yet!");
        }

        long[] state = new long[25];

        state[0] = PREFIX_0;
        state[1] = PREFIX_1;

        byte[] buffer = new byte[BLOCK_SIZE - 16];

        buffer[0] = 0x01;
        buffer[1] = (byte) customization.length;
        System.arraycopy(customization, 0, buffer, 2, customization.length);

        for (int i = 0; i < 19; i++) {
            state[i + 2] = Tools.load64BE(buffer, 8 * i);
        }

        KeccakP.keccak_f1600(state);

        return state;

    }

    private final long[] precomputedState;
    private final long chunkSize;

    public ParallelHash128(String customization, long chunkSize) {
        this.precomputedState = precomputeState(customization.getBytes());
        this.chunkSize = chunkSize;
    }

    @Override
    public Engine start() {
        return new Engine() {

            private final Chunk current = new Chunk();
            private final Root root = new Root(precomputedState);
            private long chunkPos = 0;

            private final long[] chaining = new long[4];

            private int nChunks = 0;

            @Override
            public void ingest(MemorySegment input) {
                long length = input.byteSize(), offset = 0;
                while (length + chunkPos >= chunkSize) {
                    long take = chunkSize - chunkPos;

                    current.ingest(input, offset, take);
                    current.finish(chaining);
                    root.chain(chaining);
                    current.reset();

                    nChunks++;

                    chunkPos = 0;
                    offset += take;
                    length -= take;
                }
                if (length > 0) {
                    current.ingest(input, offset, length);
                    chunkPos = length;
                }
            }

            @Override
            public void digestTo(byte[] dest, int offset) {
                if (chunkPos > 0) {
                    current.finish(chaining);
                    root.chain(chaining);

                    nChunks++;
                }
                root.finish(nChunks, dest, offset);
            }

            @Override
            public Digest getAlgorithm() {
                return ParallelHash128.this;
            }
        };
    }

    @Override
    public int digestSize() {
        return DIGEST_LEN;
    }

    @Override
    public int blockSize() {
        return BLOCK_SIZE;
    }

    private static final class Chunk {

        private final long[] state = new long[25];
        private final MemorySegment buffer = MemorySegment.allocateNative(BLOCK_SIZE, MemorySession.global());
        private int position = 0;

        private void ingestOneBlock(MemorySegment input, long offset) {
            for (int i = 0; i < 21; i++) {
                state[i] ^= input.get(LAYOUT, offset + 8 * i);
            }
            KeccakP.keccak_f1600(state);
        }

        public void finish(long[] output) {
            if (position == BLOCK_SIZE - 1) {
                buffer.set(ValueLayout.JAVA_BYTE, position, (byte) 0x9f);
            } else {
                buffer.set(ValueLayout.JAVA_BYTE, position, (byte) 0x1f);
                buffer.asSlice(position + 1, BLOCK_SIZE - 2 - position).fill((byte) 0);
                buffer.set(ValueLayout.JAVA_BYTE, BLOCK_SIZE - 1, (byte) 0x80);
            }

            ingestOneBlock(buffer, 0);

            output[0] = state[0];
            output[1] = state[1];
            output[2] = state[2];
            output[3] = state[3];
        }

        public void ingest(MemorySegment input, long offset, long length) {
            if (position > 0) {
                int take = (int) Math.min(length, BLOCK_SIZE - position);
                MemorySegment.copy(input, offset, buffer, position, take);
                offset += take;
                length -= take;
                position += take;
                if (position == BLOCK_SIZE) {
                    ingestOneBlock(buffer, 0);
                    position = 0;
                }
            }
            while (length >= BLOCK_SIZE) {
                ingestOneBlock(input, offset);
                offset += BLOCK_SIZE;
                length -= BLOCK_SIZE;
            }
            if (length > 0) {
                MemorySegment.copy(input, offset, buffer, 0, length);
                position = (int) length;
            }
        }

        public void reset() {
            Arrays.fill(state, 0);
        }
    }

    private static final class Root {

        private final long[] state;
        private int position = 0;

        private Root(long[] precomputed) {
            this.state = precomputed.clone();
        }

        public void chain(long[] output) {
            int x = position;
            switch (x) {
                case 17 -> {
                    state[17] ^= output[0];
                    state[18] ^= output[1];
                    state[19] ^= output[2];
                    state[20] ^= output[3];
                    keccak_f1600(state);
                    position = 0;
                }
                case 18 -> {
                    state[18] ^= output[0];
                    state[19] ^= output[1];
                    state[20] ^= output[2];
                    keccak_f1600(state);
                    state[0] ^= output[3];
                    position = 1;
                }
                case 19 -> {
                    state[19] ^= output[0];
                    state[20] ^= output[1];
                    keccak_f1600(state);
                    state[0] ^= output[2];
                    state[1] ^= output[3];
                    position = 2;
                }
                case 20 -> {
                    state[20] ^= output[0];
                    keccak_f1600(state);
                    state[0] ^= output[1];
                    state[1] ^= output[2];
                    state[2] ^= output[3];
                    position = 3;
                }
                default -> {
                    state[x + 0] ^= output[0];
                    state[x + 1] ^= output[1];
                    state[x + 2] ^= output[2];
                    state[x + 3] ^= output[3];
                    position += 4;
                }
            }
        }

        public void finish(int length, byte[] output, int offset) {
            int n = length == 0 ? 1 : Math.ceilDiv(32 - Integer.numberOfLeadingZeros(length), 8);

            byte[] buf = new byte[8];
            for (int i = n - 1; length != 0; i--, length >>>= 8) {
                buf[i] = (byte) (length & 0xff);
            }
            buf[n] = (byte) n;
            buf[n + 1] = (byte) DIGEST_LEN;
            buf[n + 2] = 0x01;

            buf[n + 3] = 0x04;

            state[position] ^= Tools.load64LE(buf, 0);
            state[20] ^= 0x8000000000000000L;

            keccak_f1600(state);

            Tools.store64LE(state[0], output, offset + 0);
            Tools.store64LE(state[1], output, offset + 8);
            Tools.store64LE(state[2], output, offset + 16);
            Tools.store64LE(state[3], output, offset + 24);

        }

    }

}
