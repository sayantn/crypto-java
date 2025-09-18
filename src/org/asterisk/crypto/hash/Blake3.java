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
package org.asterisk.crypto.hash;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.Arena;
import java.lang.foreign.ValueLayout;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.Mac;
import org.asterisk.crypto.Xof;

import static org.asterisk.crypto.helper.Tools.load32LE;
import static org.asterisk.crypto.helper.Tools.store32LE;

/**
 *
 * @author Sayantan Chakraborty
 */
/**
 * 12.7 cpb
 *
 * @author Sayantan Chakraborty
 */
public enum Blake3 implements Xof, Mac {

    BLAKE3;

    private static final int DEFAULT_HASH_LEN = 32;

    private static final int BLOCK_LEN = 64;
    private static final int CHUNK_LEN = 1024;

    //flags
    private static final int CHUNK_START = 1;
    private static final int CHUNK_END = 2;
    private static final int PARENT = 4;
    private static final int ROOT = 8;
    private static final int KEYED_HASH = 16;

    private static final int[] DEFAULT_IV = {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    };

    private static final ValueLayout.OfInt LAYOUT = Tools.LITTLE_ENDIAN_32_BIT;

    private static void g(int[] state, int a, int b, int c, int d, int mx, int my) {
        state[a] += state[b] + mx;
        state[d] = Integer.rotateRight(state[d] ^ state[a], 16);
        state[c] += state[d];
        state[b] = Integer.rotateRight(state[b] ^ state[c], 12);
        state[a] += state[b] + my;
        state[d] = Integer.rotateRight(state[d] ^ state[a], 8);
        state[c] += state[d];
        state[b] = Integer.rotateRight(state[b] ^ state[c], 7);
    }

    private static void roundFn(int[] state, int m0, int m1, int m2, int m3, int m4, int m5, int m6, int m7, int m8, int m9, int m10, int m11, int m12, int m13, int m14, int m15) {
        //Mix columns
        g(state, 0, 4, 8, 12, m0, m1);
        g(state, 1, 5, 9, 13, m2, m3);
        g(state, 2, 6, 10, 14, m4, m5);
        g(state, 3, 7, 11, 15, m6, m7);

        //mix diagonals
        g(state, 0, 5, 10, 15, m8, m9);
        g(state, 1, 6, 11, 12, m10, m11);
        g(state, 2, 7, 8, 13, m12, m13);
        g(state, 3, 4, 9, 14, m14, m15);
    }

    public static int[] compress(int[] chainingValue, MemorySegment input, long offset, long counter, int blockLen, int flags) {
        return compress(chainingValue, counter, blockLen, flags,
                input.get(LAYOUT, offset + 0), input.get(LAYOUT, offset + 4), input.get(LAYOUT, offset + 8), input.get(LAYOUT, offset + 12),
                input.get(LAYOUT, offset + 16), input.get(LAYOUT, offset + 20), input.get(LAYOUT, offset + 24), input.get(LAYOUT, offset + 28),
                input.get(LAYOUT, offset + 32), input.get(LAYOUT, offset + 36), input.get(LAYOUT, offset + 40), input.get(LAYOUT, offset + 44),
                input.get(LAYOUT, offset + 48), input.get(LAYOUT, offset + 52), input.get(LAYOUT, offset + 56), input.get(LAYOUT, offset + 60));
    }

    public static int[] compress(int[] chainingValue, int[] blockWords, long counter, int blockLen, int flags) {
        return compress(chainingValue, counter, blockLen, flags,
                blockWords[0], blockWords[1], blockWords[2], blockWords[3], blockWords[4], blockWords[5], blockWords[6], blockWords[7],
                blockWords[8], blockWords[9], blockWords[10], blockWords[11], blockWords[12], blockWords[13], blockWords[14], blockWords[15]);
    }

    private static int[] compress(int[] chainingValue, long counter, int blockLen, int flags, int m0, int m1, int m2, int m3, int m4, int m5, int m6, int m7, int m8, int m9, int m10, int m11, int m12, int m13, int m14, int m15) {
        int[] state = new int[16];
        System.arraycopy(chainingValue, 0, state, 0, 8);
        System.arraycopy(DEFAULT_IV, 0, state, 8, 4);
        state[12] = (int) counter;
        state[13] = (int) (counter >> 32);
        state[14] = blockLen;
        state[15] = flags;

        roundFn(state,
                m0, m1, m2, m3,
                m4, m5, m6, m7,
                m8, m9, m10, m11,
                m12, m13, m14, m15);
        roundFn(state,
                m2, m6, m3, m10,
                m7, m0, m4, m13,
                m1, m11, m12, m5,
                m9, m14, m15, m8);
        roundFn(state,
                m3, m4, m10, m12,
                m13, m2, m7, m14,
                m6, m5, m9, m0,
                m11, m15, m8, m1);
        roundFn(state,
                m10, m7, m12, m9,
                m14, m3, m13, m15,
                m4, m0, m11, m2,
                m5, m8, m1, m6);
        roundFn(state,
                m12, m13, m9, m11,
                m15, m10, m14, m8,
                m7, m2, m5, m3,
                m0, m1, m6, m4);
        roundFn(state,
                m9, m14, m11, m5,
                m8, m12, m15, m1,
                m13, m3, m0, m10,
                m2, m6, m4, m7);
        roundFn(state,
                m11, m15, m5, m0,
                m1, m9, m8, m6,
                m14, m10, m2, m12,
                m3, m4, m7, m13);

        state[0] ^= state[8];
        state[8] ^= chainingValue[0];
        state[1] ^= state[9];
        state[9] ^= chainingValue[1];
        state[2] ^= state[10];
        state[10] ^= chainingValue[2];
        state[3] ^= state[11];
        state[11] ^= chainingValue[3];
        state[4] ^= state[12];
        state[12] ^= chainingValue[4];
        state[5] ^= state[13];
        state[13] ^= chainingValue[5];
        state[6] ^= state[14];
        state[14] ^= chainingValue[6];
        state[7] ^= state[15];
        state[15] ^= chainingValue[7];
        return state;
    }

    private static Node parentOutput(int[] leftChild, int[] rightChild, int[] keyWords, int flags) {
        System.arraycopy(rightChild, 0, leftChild, 8, 8);
        return new Node(keyWords, leftChild, 0, BLOCK_LEN, flags | PARENT);
    }

    private static int[] parent(int[] leftChild, int[] rightChild, int[] keyWords, int flags) {
        System.arraycopy(rightChild, 0, leftChild, 8, 8);
        return compress(keyWords, leftChild, 0, BLOCK_LEN, flags | PARENT);
    }

    @Override
    public Xof.Engine start() {
        return new Blake3Engine(DEFAULT_IV, 0);
    }

    @Override
    public int digestSize() {
        return DEFAULT_HASH_LEN;
    }

    @Override
    public int blockSize() {
        return BLOCK_LEN;
    }

    @Override
    public Mac.Engine start(byte[] key) {
        var internal = new Blake3Engine(new int[]{
            load32LE(key, 0), load32LE(key, 4), load32LE(key, 8), load32LE(key, 12),
            load32LE(key, 16), load32LE(key, 20), load32LE(key, 24), load32LE(key, 28)
        }, KEYED_HASH);

        return new Mac.Engine() {
            @Override
            public void ingest(MemorySegment input) {
                internal.ingest(input);
            }

            @Override
            public void authenticateTo(byte[] tag, int offset, int length) {
                internal.startDigesting();
                internal.continueDigesting(tag, offset, length);
            }

            @Override
            public Mac getAlgorithm() {
                return BLAKE3;
            }
        };
    }

    @Override
    public int tagLength() {
        return DEFAULT_HASH_LEN;
    }

    @Override
    public int keyLength() {
        return 32;
    }

    private static class Node {

        private final int[] inputCV, blockWords;
        private final long counter;
        private final int blockLen, flags;
        private int outputCounter = 0;
        private final byte[] outputBuffer = new byte[64];
        private int outputPosition = 0;

        private Node(int[] inputCV, int[] blockWords, long counter, int blockLen, int flags) {
            this.inputCV = inputCV;
            this.blockWords = blockWords;
            this.counter = counter;
            this.blockLen = blockLen;
            this.flags = flags;
        }

        private int[] chain() {
            return compress(inputCV, blockWords, counter, blockLen, flags);
        }

        private void outputOneBlock(byte[] output, int offset) {
            int[] words = compress(inputCV, blockWords, outputCounter++, blockLen, flags | ROOT);

            store32LE(words[0], output, offset + 0);
            store32LE(words[1], output, offset + 4);
            store32LE(words[2], output, offset + 8);
            store32LE(words[3], output, offset + 12);
            store32LE(words[4], output, offset + 16);
            store32LE(words[5], output, offset + 20);
            store32LE(words[6], output, offset + 24);
            store32LE(words[7], output, offset + 28);
            store32LE(words[8], output, offset + 32);
            store32LE(words[9], output, offset + 36);
            store32LE(words[10], output, offset + 40);
            store32LE(words[11], output, offset + 44);
            store32LE(words[12], output, offset + 48);
            store32LE(words[13], output, offset + 52);
            store32LE(words[14], output, offset + 56);
            store32LE(words[15], output, offset + 60);
        }

        private void rootOutputBytes(byte[] output, int offset, int length) {
            if (outputPosition > 0) {
                int take = Math.min(length, 64 - outputPosition);
                System.arraycopy(outputBuffer, outputPosition, output, offset, take);
                offset += take;
                length -= take;
                outputPosition = (outputPosition + take) & 0x3f;
            }
            while (length >= 64) {
                outputOneBlock(output, offset);

                offset += 64;
                length -= 64;
            }
            if (length > 0) {
                outputOneBlock(outputBuffer, 0);
                System.arraycopy(outputBuffer, 0, output, offset, length);
                outputPosition = length;
            }
        }

    }

    private static class ChunkState {

        private final MemorySegment buffer = Arena.ofAuto().allocate(BLOCK_LEN);
        private int position = 0;
        private int startFlag = CHUNK_START;

        private int[] chainingValue;
        private long chunkCtr;
        private final int flags;

        private ChunkState(int[] chainingValue, long chunkCtr, int flags) {
            this.chainingValue = chainingValue;
            this.chunkCtr = chunkCtr;
            this.flags = flags;
        }

        public int[] ingestFullChunk(MemorySegment input, long offset) {
            chainingValue = compress(chainingValue, input, offset, chunkCtr, BLOCK_LEN, flags | CHUNK_START);
            offset += 64;

            for (int i = 64; i < 960; i += 64) {
                chainingValue = compress(chainingValue, input, offset, chunkCtr, BLOCK_LEN, flags);
                offset += 64;
            }

            return compress(chainingValue, input, offset, chunkCtr, BLOCK_LEN, flags | CHUNK_END);
        }

        public void ingest(MemorySegment input, long offset, long length) {
            if (position > 0) {
                int take = (int) Math.min(BLOCK_LEN - position, length);
                MemorySegment.copy(input, offset, buffer, position, take);
                offset += take;
                length -= take;
                position += take;
                if (position == BLOCK_LEN && length > 0) {
                    chainingValue = compress(chainingValue, buffer, 0, chunkCtr, BLOCK_LEN, flags | startFlag);
                    startFlag = 0;
                    position = 0;
                }
            }
            if (length > BLOCK_LEN && startFlag != 0) {
                chainingValue = compress(chainingValue, input, offset, chunkCtr, BLOCK_LEN, flags | CHUNK_START);
                startFlag = 0;
                offset += BLOCK_LEN;
                length -= BLOCK_LEN;
            }
            while (length > BLOCK_LEN) {
                chainingValue = compress(chainingValue, input, offset, chunkCtr, BLOCK_LEN, flags);
                offset += BLOCK_LEN;
                length -= BLOCK_LEN;
            }
            if (length > 0) {
                MemorySegment.copy(input, offset, buffer, 0, length);
                position = (int) length;
            }
        }

        private int[] chain() {
            Tools.zeropad(buffer, position);
            return compress(chainingValue, buffer, 0, chunkCtr, position, flags | startFlag | CHUNK_END);
        }

        private Node output() {
            Tools.zeropad(buffer, position);
            var blockWords = new int[16];
            for (int i = 0; i < 16; i++) {
                blockWords[i] = buffer.get(LAYOUT, 4 * i);
            }
            return new Node(chainingValue, blockWords, chunkCtr, position, flags | startFlag | CHUNK_END);
        }

        private void reset(int[] keyWords) {
            chainingValue = keyWords;
            chunkCtr++;
            position = 0;
            startFlag = CHUNK_START;
        }

    }

    public static class Blake3Engine implements Xof.Engine {

        private final int[][] cvStack = new int[54][];
        private int cvStackLen = 0;
        private final int[] keyWords;
        private final int flags;
        private final ChunkState state;
        private int position = 0;

        private Node out = null;

        private Blake3Engine(int[] keyWords, int flags) {
            this.keyWords = keyWords;
            this.flags = flags;
            this.state = new ChunkState(this.keyWords, 0, flags);
        }

        private void addChunkCV(int[] newCV, long totalChunks) {
            while ((totalChunks & 1) == 0) {
                newCV = parent(popStack(), newCV, keyWords, flags);
                totalChunks >>>= 1;
            }
            pushStack(newCV);
        }

        private int[] popStack() {
            var ret = cvStack[--cvStackLen];
            cvStack[cvStackLen] = null;
            return ret;
        }

        private void pushStack(int[] cv) {
            cvStack[cvStackLen++] = cv;
        }

        @Override
        public void ingest(MemorySegment input) {
            if (out != null) {
                throw new IllegalStateException("Cannot ingest after starting to digest!");
            }
            long offset = 0, length = input.byteSize();
            if (position > 0) {
                int take = (int) Math.min(CHUNK_LEN - position, length);
                state.ingest(input, offset, take);
                offset += take;
                length -= take;
                position += take;
                if (position == CHUNK_LEN && length > 0) {
                    addChunkCV(state.chain(), state.chunkCtr + 1);
                    state.reset(keyWords);
                    position = 0;
                }
            }
            while (length > CHUNK_LEN) {
                addChunkCV(state.ingestFullChunk(input, offset), state.chunkCtr + 1);
                state.reset(keyWords);

                offset += CHUNK_LEN;
                length -= CHUNK_LEN;
            }
            state.ingest(input, offset, length);
            position = (int) length;
        }

        @Override
        public void startDigesting() {
            if (out != null) {
                throw new IllegalStateException("Cannot start to digest twice!!!!");
            }
            out = state.output();
            while (cvStackLen > 0) {
                out = parentOutput(popStack(), out.chain(), keyWords, flags);
            }
        }

        @Override
        public void continueDigesting(byte[] output, int offset, int length) {
            out.rootOutputBytes(output, offset, length);
        }

        @Override
        public Xof getAlgorithm() {
            return BLAKE3;
        }
    }

}
