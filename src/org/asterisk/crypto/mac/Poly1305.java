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
import java.lang.foreign.Arena;
import java.lang.foreign.ValueLayout;
import java.util.Objects;
import org.asterisk.crypto.Tested;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.Mac;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum Poly1305 implements Mac {

    @Tested
    POLY1305;

    private static final ValueLayout.OfInt LAYOUT = Tools.LITTLE_ENDIAN_32_BIT;

    private static final int MASK = 0x3ffffff;
    private static final int HIGH = 0x1000000;

    @Override
    public Poly1305Engine start(byte[] key) {
        return new Poly1305Engine(key);
    }

    @Override
    public int tagLength() {
        return 16;
    }

    @Override
    public int keyLength() {
        return 32;
    }

    public static final class Poly1305Engine implements Engine {

        private static long addFull(int a, int b) {
            return Integer.toUnsignedLong(a) + Integer.toUnsignedLong(b);
        }

        private final MemorySegment buffer = Arena.ofAuto().allocate(16);
        private int position = 0;

        private final int[] r, s, pad, h = new int[5];

        public Poly1305Engine(byte[] key) {
            r = new int[]{
                Tools.load32LE(key, 0) & MASK,
                (Tools.load32LE(key, 3) >>> 2) & 0x3ffff03,
                (Tools.load32LE(key, 6) >>> 4) & 0x3ffc0ff,
                (Tools.load32LE(key, 9) >>> 6) & 0x3f03fff,
                (Tools.load32LE(key, 12) >>> 8) & 0x00fffff
            };
            s = new int[]{
                r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5
            };
            pad = new int[]{
                Tools.load32LE(key, 16),
                Tools.load32LE(key, 20),
                Tools.load32LE(key, 24),
                Tools.load32LE(key, 28)
            };
        }

        public Poly1305Engine(int[] key) {
            r = new int[]{
                key[0] & MASK,
                ((key[0] >>> 26) | ((key[1] << 8) >>> 2)) & 0x3ffff03,
                ((key[1] >>> 28) | ((key[2] << 8) >>> 4)) & 0x3ffc0ff,
                ((key[2] >>> 30) | ((key[3] << 8) >>> 6)) & 0x3f03fff,
                key[4] & 0x00fffff
            };
            s = new int[]{
                r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5
            };
            pad = new int[]{
                key[4], key[5], key[6], key[7]
            };
        }

        @Override
        public void ingest(MemorySegment input) {
            long offset = 0, length = input.byteSize();
            if (position > 0) {
                int take = (int) Math.min(length, 16 - position);
                MemorySegment.copy(input, offset, buffer, position, take);
                offset += take;
                length -= take;
                position += take;
                if (position == 16) {
                    processBlock(buffer, 0, HIGH);
                    position = 0;
                }
            }
            if (length >= 16) {
                var x = processBlocks(input, offset, length);
                length -= x;
                offset += x;
            }
            if (length > 0) {
                MemorySegment.copy(input, offset, buffer, 0, length);
                position = (int) length;
            }
        }

        @Override
        public void authenticateTo(byte[] tag, int offset, int length) {
            Objects.checkFromIndexSize(offset, 16, tag.length);
            if (position > 0) {
                buffer.set(ValueLayout.JAVA_BYTE, position, (byte) 1);
                Tools.zeropad(buffer, position + 1);
                processBlock(buffer, 0, 0);
            }
            byte[] dest = new byte[16];
            getTag(dest);
            System.arraycopy(dest, 0, tag, offset, length);
        }

        private long processBlocks(MemorySegment input, long offset, long length) {
            long initial = offset;

            int h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];

            int r0 = r[0], r1 = r[1], r2 = r[2], r3 = r[3], r4 = r[4];

            int s1 = s[0], s2 = s[1], s3 = s[2], s4 = s[3];

            long d0, d1, d2, d3, d4;

            while (length >= 16) {

                h0 += (input.get(LAYOUT, offset + 0)) & MASK;
                h1 += (input.get(LAYOUT, offset + 3) >>> 2) & MASK;
                h2 += (input.get(LAYOUT, offset + 6) >>> 4) & MASK;
                h3 += (input.get(LAYOUT, offset + 9) >>> 6) & MASK;
                h4 += (input.get(LAYOUT, offset + 12) >>> 8) | HIGH;

                d0 = ((long) h0 * r0) + ((long) h1 * s4) + ((long) h2 * s3) + ((long) h3 * s2) + ((long) h4 * s1);
                d1 = ((long) h0 * r1) + ((long) h1 * r0) + ((long) h2 * s4) + ((long) h3 * s3) + ((long) h4 * s2);
                d2 = ((long) h0 * r2) + ((long) h1 * r1) + ((long) h2 * r0) + ((long) h3 * s4) + ((long) h4 * s3);
                d3 = ((long) h0 * r3) + ((long) h1 * r2) + ((long) h2 * r1) + ((long) h3 * r0) + ((long) h4 * s4);
                d4 = ((long) h0 * r4) + ((long) h1 * r3) + ((long) h2 * r2) + ((long) h3 * r1) + ((long) h4 * r0);

                d1 += (int) (d0 >>> 26);
                h0 = (int) (d0 & MASK);
                d2 += (int) (d1 >>> 26);
                h1 = (int) (d1 & MASK);
                d3 += (int) (d2 >>> 26);
                h2 = (int) (d2 & MASK);
                d4 += (int) (d3 >>> 26);
                h3 = (int) (d3 & MASK);
                h0 += 5 * (int) (d4 >>> 26);
                h4 = (int) (d4 & MASK);
                h1 += h0 >>> 26;
                h0 &= MASK;

                offset += 16;
                length -= 16;
            }

            h[0] = h0;
            h[1] = h1;
            h[2] = h2;
            h[3] = h3;
            h[4] = h4;

            return offset - initial;
        }

        private void processBlock(MemorySegment input, long offset, int hibit) {
            h[0] += (input.get(LAYOUT, offset + 0)) & MASK;
            h[1] += (input.get(LAYOUT, offset + 3) >>> 2) & MASK;
            h[2] += (input.get(LAYOUT, offset + 6) >>> 4) & MASK;
            h[3] += (input.get(LAYOUT, offset + 9) >>> 6) & MASK;
            h[0] += (input.get(LAYOUT, offset + 12) >>> 8) | hibit;

            long d0 = ((long) h[0] * r[0]) + ((long) h[1] * s[3]) + ((long) h[2] * s[2]) + ((long) h[3] * s[1]) + ((long) h[4] * s[0]);
            long d1 = ((long) h[0] * r[1]) + ((long) h[1] * r[0]) + ((long) h[2] * s[3]) + ((long) h[3] * s[2]) + ((long) h[4] * s[1]);
            long d2 = ((long) h[0] * r[2]) + ((long) h[1] * r[1]) + ((long) h[2] * r[0]) + ((long) h[3] * s[3]) + ((long) h[4] * s[2]);
            long d3 = ((long) h[0] * r[3]) + ((long) h[1] * r[2]) + ((long) h[2] * r[1]) + ((long) h[3] * r[0]) + ((long) h[4] * s[3]);
            long d4 = ((long) h[0] * r[4]) + ((long) h[1] * r[3]) + ((long) h[2] * r[2]) + ((long) h[3] * r[1]) + ((long) h[4] * r[0]);

            d1 += (int) (d0 >>> 26);
            h[0] = (int) (d0 & MASK);
            d2 += (int) (d1 >>> 26);
            h[1] = (int) (d1 & MASK);
            d3 += (int) (d2 >>> 26);
            h[2] = (int) (d2 & MASK);
            d4 += (int) (d3 >>> 26);
            h[3] = (int) (d3 & MASK);
            h[0] += 5 * (int) (d4 >>> 26);
            h[4] = (int) (d4 & MASK);
            h[1] += h[0] >>> 26;
            h[0] &= MASK;
        }

        private void getTag(byte[] buffer) {
            int h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];

            h2 += h1 >>> 26;
            h1 &= MASK;
            h3 += h2 >>> 26;
            h2 &= MASK;
            h4 += h3 >>> 26;
            h3 &= MASK;
            h0 += 5 * (h4 >>> 26);
            h4 &= MASK;
            h1 += h0 >>> 26;
            h0 &= MASK;

            int g0 = h0 + 5;
            int g1 = h1 + (g0 >>> 26);
            g0 &= MASK;
            int g2 = h2 + (g1 >>> 26);
            g1 &= MASK;
            int g3 = h3 + (g2 >>> 26);
            g2 &= MASK;
            int g4 = h4 + (g3 >>> 26) - 0x4000000;
            g3 &= MASK;

            int b = (g4 >>> 31) - 1;
            int nb = ~b;

            h0 = (h0 & nb) | (g0 & b);
            h1 = (h1 & nb) | (g1 & b);
            h2 = (h2 & nb) | (g2 & b);
            h3 = (h3 & nb) | (g3 & b);
            h4 = (h4 & nb) | (g4 & b);

            long f;

            f = addFull(h0 | (h1 << 26), pad[0]);
            Tools.store32LE((int) f, buffer, 0);

            f = addFull((h1 >>> 6) | (h2 << 20), pad[1]) + (f >>> 32);
            Tools.store32LE((int) f, buffer, 4);

            f = addFull((h2 >>> 12) | (h3 << 14), pad[2]) + (f >>> 32);
            Tools.store32LE((int) f, buffer, 8);

            f = addFull((h2 >>> 18) | (h4 << 8), pad[3]) + (f >>> 32);
            Tools.store32LE((int) f, buffer, 12);

        }

        @Override
        public Mac getAlgorithm() {
            return POLY1305;
        }
    }

}
