/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.hash;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.Arena;
import java.lang.foreign.ValueLayout;
import java.util.Arrays;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.Digest;
import org.asterisk.crypto.lowlevel.KeccakP;

import static org.asterisk.crypto.lowlevel.KeccakP.keccak_f1600;

/**
 *
 * @author Sayantan Chakraborty
 */
public class ParallelHash256 implements Digest {

    private static final int BLOCK_SIZE = 136, DIGEST_LEN = 64;

    private static final ValueLayout.OfLong LAYOUT = Tools.LITTLE_ENDIAN_64_BIT;

    private static final long PREFIX_0 = 0x01a8010c50617261L, PREFIX_1 = 0x6c6c656c48617368L;

    private static long[] precomputeState(byte[] customization) {
        if (customization.length > 118) {
            throw new UnsupportedOperationException("Customization strings of over 118 bytes are not supported yet!");
        }

        long[] state = new long[25];

        state[0] = PREFIX_0;
        state[1] = PREFIX_1;

        byte[] buffer = new byte[BLOCK_SIZE - 16];

        buffer[0] = 0x01;
        buffer[0] = (byte) customization.length;
        System.arraycopy(customization, 0, buffer, 2, customization.length);

        for (int i = 0; i < 15; i++) {
            state[i + 2] = Tools.load64BE(buffer, 8 * i);
        }

        KeccakP.keccak_f1600(state);

        return state;

    }

    private final long[] precomputedState;
    private final long chunkSize;

    public ParallelHash256(String customization, long chunkSize) {
        this.precomputedState = precomputeState(customization.getBytes());
        this.chunkSize = chunkSize;
    }

    @Override
    public Digest.Engine start() {
        return new Digest.Engine() {

            private final Chunk current = new Chunk();
            private final Root root = new Root(precomputedState);
            private long chunkPos = 0;

            private final long[] chaining = new long[8];

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
                return ParallelHash256.this;
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
        private final MemorySegment buffer = Arena.ofAuto().allocate(BLOCK_SIZE);
        private int position = 0;

        private void ingestOneBlock(MemorySegment input, long offset) {
            for (int i = 0; i < 17; i++) {
                state[i] ^= input.get(LAYOUT, offset + 8 * i);
            }
            KeccakP.keccak_f1600(state);
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

        public void finish(long[] output) {
            if (position == BLOCK_SIZE - 1) {
                buffer.set(ValueLayout.JAVA_BYTE, position, (byte) 0x9f);
            } else {
                buffer.set(ValueLayout.JAVA_BYTE, position, (byte) 0x1f);
                buffer.asSlice(position + 1, BLOCK_SIZE - 2 - position).fill((byte) 0);
                buffer.set(ValueLayout.JAVA_BYTE, BLOCK_SIZE - 1, (byte) 0x80);
            }

            ingestOneBlock(buffer, 0);

            System.arraycopy(state, 0, output, 0, 8);
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
            if (position < 9) {
                for (int i = 0; i < 8; i++) {
                    state[position++] ^= output[i];
                }
            } else {
                int i;
                for (i = 0; position < 17; i++) {
                    state[position++] ^= output[i];
                }
                keccak_f1600(state);
                position = 0;
                for (; i < 8; i++) {
                    state[position++] ^= output[i];
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
            state[16] ^= 0x8000000000000000L;

            keccak_f1600(state);

            for (int i = 0; i < 8; i++) {
                Tools.store64LE(state[i], output, offset + 8 * i);
            }

        }

    }

}
