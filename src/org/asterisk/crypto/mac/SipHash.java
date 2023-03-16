/*
 * Copyright (C) 2022 Sayantan Chakraborty
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
package org.asterisk.crypto.mac;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.MemorySession;
import java.lang.foreign.ValueLayout;
import java.util.Objects;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.interfaces.Mac;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum SipHash implements Mac {

    SIPHASH_2_4 {
        @Override
        public Engine start(byte[] key) {
            return new SipHashEngine(Tools.load64LE(key, 0), Tools.load64LE(key, 8)) {

                @Override
                protected void ingestBlocks(MemorySegment input, long offset, long length) {
                    long v0 = state[0], v1 = state[1], v2 = state[2], v3 = state[3];

                    while (length >= 8) {
                        long m = input.get(Tools.LITTLE_ENDIAN_64_BIT, offset);

                        v3 ^= m;

                        v0 += v1;
                        v2 += v3;
                        v1 = v0 ^ Long.rotateLeft(v1, 13);
                        v3 = v2 ^ Long.rotateLeft(v3, 16);
                        v2 += v1;
                        v0 = v3 + Long.rotateLeft(v0, 32);
                        v1 = v2 ^ Long.rotateLeft(v1, 17);
                        v3 = v0 ^ Long.rotateLeft(v3, 21);
                        v2 = Long.rotateLeft(v2, 32);
                        v0 += v1;
                        v2 += v3;
                        v1 = v0 ^ Long.rotateLeft(v1, 13);
                        v3 = v2 ^ Long.rotateLeft(v3, 16);
                        v2 += v1;
                        v0 = v3 + Long.rotateLeft(v0, 32);
                        v1 = v2 ^ Long.rotateLeft(v1, 17);
                        v3 = v0 ^ Long.rotateLeft(v3, 21);
                        v2 = Long.rotateLeft(v2, 32);

                        v0 ^= m;

                        offset += 8;
                        length -= 8;
                    }

                    state[0] = v0;
                    state[1] = v1;
                    state[2] = v2;
                    state[3] = v3;
                }

                @Override
                protected void ingestOneBlock(MemorySegment input, long offset) {
                    long m = input.get(Tools.LITTLE_ENDIAN_64_BIT, offset);
                    state[3] ^= m;
                    sipround(state);
                    sipround(state);
                    state[0] ^= m;
                }

                @Override
                protected void getTag(byte[] buffer) {
                    state[2] ^= 0xff;

                    sipround(state);
                    sipround(state);
                    sipround(state);
                    sipround(state);

                    Tools.store64LE(state[0] ^ state[1] ^ state[2] ^ state[3], buffer, 0);
                }

                @Override
                public Mac getAlgorithm() {
                    return SipHash.SIPHASH_2_4;
                }

            };
        }

    }, SIPHASH_4_8 {
        @Override
        public Engine start(byte[] key) {
            return new SipHashEngine(Tools.load64LE(key, 0), Tools.load64LE(key, 8)) {

                @Override
                protected void ingestBlocks(MemorySegment input, long offset, long length) {
                    long v0 = state[0], v1 = state[1], v2 = state[2], v3 = state[3];

                    while (length >= 8) {
                        long m = input.get(Tools.LITTLE_ENDIAN_64_BIT, offset);

                        v3 ^= m;

                        v0 += v1;
                        v2 += v3;
                        v1 = v0 ^ Long.rotateLeft(v1, 13);
                        v3 = v2 ^ Long.rotateLeft(v3, 16);
                        v2 += v1;
                        v0 = v3 + Long.rotateLeft(v0, 32);
                        v1 = v2 ^ Long.rotateLeft(v1, 17);
                        v3 = v0 ^ Long.rotateLeft(v3, 21);
                        v2 = Long.rotateLeft(v2, 32);
                        v0 += v1;
                        v2 += v3;
                        v1 = v0 ^ Long.rotateLeft(v1, 13);
                        v3 = v2 ^ Long.rotateLeft(v3, 16);
                        v2 += v1;
                        v0 = v3 + Long.rotateLeft(v0, 32);
                        v1 = v2 ^ Long.rotateLeft(v1, 17);
                        v3 = v0 ^ Long.rotateLeft(v3, 21);
                        v2 = Long.rotateLeft(v2, 32);
                        v0 += v1;
                        v2 += v3;
                        v1 = v0 ^ Long.rotateLeft(v1, 13);
                        v3 = v2 ^ Long.rotateLeft(v3, 16);
                        v2 += v1;
                        v0 = v3 + Long.rotateLeft(v0, 32);
                        v1 = v2 ^ Long.rotateLeft(v1, 17);
                        v3 = v0 ^ Long.rotateLeft(v3, 21);
                        v2 = Long.rotateLeft(v2, 32);
                        v0 += v1;
                        v2 += v3;
                        v1 = v0 ^ Long.rotateLeft(v1, 13);
                        v3 = v2 ^ Long.rotateLeft(v3, 16);
                        v2 += v1;
                        v0 = v3 + Long.rotateLeft(v0, 32);
                        v1 = v2 ^ Long.rotateLeft(v1, 17);
                        v3 = v0 ^ Long.rotateLeft(v3, 21);
                        v2 = Long.rotateLeft(v2, 32);

                        v0 ^= m;

                        offset += 8;
                        length -= 8;
                    }

                    state[0] = v0;
                    state[1] = v1;
                    state[2] = v2;
                    state[3] = v3;
                }

                @Override
                protected void ingestOneBlock(MemorySegment input, long offset) {
                    long m = input.get(Tools.LITTLE_ENDIAN_64_BIT, offset);
                    state[3] ^= m;
                    sipround(state);
                    sipround(state);
                    sipround(state);
                    sipround(state);
                    state[0] ^= m;
                }

                @Override
                protected void getTag(byte[] buffer) {
                    state[2] ^= 0xff;

                    sipround(state);
                    sipround(state);
                    sipround(state);
                    sipround(state);
                    sipround(state);
                    sipround(state);
                    sipround(state);
                    sipround(state);

                    Tools.store64LE(state[0] ^ state[1] ^ state[2] ^ state[3], buffer, 0);
                }

                @Override
                public Mac getAlgorithm() {
                    return SipHash.SIPHASH_4_8;
                }
            };
        }
    };

    private static final long CONST_0 = 0x736f6d6570736575L;
    private static final long CONST_1 = 0x646f72616e646f6dL;
    private static final long CONST_2 = 0x6c7967656e657261L;
    private static final long CONST_3 = 0x7465646279746573L;

    private static void sipround(long[] state) {
        state[0] += state[1];
        state[2] += state[3];
        state[1] = state[0] ^ Long.rotateLeft(state[1], 13);
        state[3] = state[2] ^ Long.rotateLeft(state[3], 16);
        state[2] += state[1];
        state[0] = state[3] + Long.rotateLeft(state[0], 32);
        state[1] = state[2] ^ Long.rotateLeft(state[1], 17);
        state[3] = state[0] ^ Long.rotateLeft(state[3], 21);
        state[2] = Long.rotateLeft(state[2], 32);
    }

    @Override
    public int tagLength() {
        return 8;
    }

    @Override
    public int keyLength() {
        return 16;
    }

    private abstract static class SipHashEngine implements Engine {

        protected final long[] state;

        private int counter = 0;

        private final MemorySegment buffer = MemorySegment.allocateNative(8, MemorySession.global());
        private int position = 0;

        private SipHashEngine(long k0, long k1) {
            state = new long[]{
                k0 ^ CONST_0, k1 ^ CONST_1, k0 ^ CONST_2, k1 ^ CONST_3
            };
        }

        protected abstract void ingestOneBlock(MemorySegment input, long offset);

        protected abstract void ingestBlocks(MemorySegment input, long offset, long length);

        protected abstract void getTag(byte[] dest);

        @Override
        public final void ingest(MemorySegment input) {
            long offset = 0, length = input.byteSize();
            counter += length;
            if (position > 0) {
                int take = (int) Math.min(length, 8 - position);
                MemorySegment.copy(input, offset, buffer, position, take);
                offset += take;
                length -= take;
                position += take;
                if (position == 8) {
                    ingestOneBlock(buffer, 0);
                    position = 0;
                }
            }
            if (length >= 8) {
                ingestBlocks(input, offset, length);
                offset += length & ~7;
                length &= 7;
            }
            if (length > 0) {
                MemorySegment.copy(input, offset, buffer, 0, length);
                position = (int) length;
            }
        }

        @Override
        public void authenticateTo(byte[] tag, int offset, int length) {
            Objects.checkFromIndexSize(offset, 8, tag.length);

            buffer.asSlice(position, 7 - position).fill((byte) 0);
            buffer.set(ValueLayout.JAVA_BYTE, 7, (byte) counter);
            ingestOneBlock(buffer, 0);

            byte[] dest = new byte[8];
            getTag(dest);
            System.arraycopy(dest, 0, tag, offset, length);
        }

    }

}
