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
package org.asterisk.crypto.aead;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Arrays;
import java.util.List;
import org.asterisk.crypto.hash.Blake2b;
import org.asterisk.crypto.helper.Tools;

import static org.asterisk.crypto.lowlevel.AesPermutation.aesRound;

/**
 *
 * @author Sayantan Chakraborty
 */
public class Aez {

    private static void aes4(int[] plaintext, int[] key, int[] ciphertext, int[] temp) {
        aesRound(plaintext, 0, temp, 0, key, 4);
        aesRound(temp, 0, ciphertext, 0, key, 0);
        aesRound(ciphertext, 0, temp, 0, key, 8);
        aesRound(temp, 0, ciphertext, 0, 0, 0, 0, 0);
    }

    private static void aes10(int[] plaintext, int[] key, int[] ciphertext, int[] temp) {
        aesRound(plaintext, 0, temp, 0, key, 0);
        aesRound(temp, 0, ciphertext, 0, key, 4);
        aesRound(ciphertext, 0, temp, 0, key, 8);
        aesRound(temp, 0, ciphertext, 0, key, 0);
        aesRound(ciphertext, 0, temp, 0, key, 4);
        aesRound(temp, 0, ciphertext, 0, key, 8);
        aesRound(ciphertext, 0, temp, 0, key, 0);
        aesRound(temp, 0, ciphertext, 0, key, 4);
        aesRound(ciphertext, 0, temp, 0, key, 8);
        aesRound(temp, 0, ciphertext, 0, key, 0);
    }

    private static void x2(int[] src) {
        int x = src[0] >> 31;
        src[0] = (src[0] << 1) | (src[1] >>> 31);
        src[1] = (src[1] << 1) | (src[2] >>> 31);
        src[2] = (src[2] << 1) | (src[3] >>> 31);
        src[3] = (src[3] << 1) ^ (0x87 & x);
    }

    private static int[] mul(int[] src, int off, int exp) {
        int[] ret = new int[4];
        for (int mask = Integer.highestOneBit(exp); mask != 0; mask >>>= 1) {
            x2(ret);
            if ((mask & exp) != 0) {
                ret[0] ^= src[off + 0];
                ret[1] ^= src[off + 1];
                ret[2] ^= src[off + 2];
                ret[3] ^= src[off + 3];
            }
        }
        return ret;
    }

    private static int[] extract(byte[] key) {
        if (key.length == 48) {
            return loadBytes(key);
        }
        var engine = Blake2b.DEFAULT.start();
        engine.ingest(key);
        var temp = engine.digest();
        return loadBytes(temp);
    }

    private static int[] loadBytes(byte[] key) {
        return new int[]{
            Tools.load32BE(key, 0), Tools.load32BE(key, 4), Tools.load32BE(key, 8), Tools.load32BE(key, 12),
            Tools.load32BE(key, 16), Tools.load32BE(key, 20), Tools.load32BE(key, 24), Tools.load32BE(key, 28),
            Tools.load32BE(key, 32), Tools.load32BE(key, 36), Tools.load32BE(key, 40), Tools.load32BE(key, 44)
        };
    }

    private static int[] join(int[] key, int[][] offsets, List<AezHasher> hashers) {
        int[] ret = {0, 0, 0, 0x80};

        new Encipher(key, offsets, 3).encryptBlock(ret, ret);

        for (var hasher : hashers) {
            var sum = hasher.checksum;
            ret[0] ^= sum[0];
            ret[1] ^= sum[1];
            ret[2] ^= sum[2];
            ret[3] ^= sum[3];
        }
        return ret;
    }

    private static final class Encipher {

        private final int[] key, delta, ladder;
        private final int[] temp = new int[4];

        private final int[][] offsets;

        private int index = 1;

        private Encipher(int[] key, int[][] offsets, int tweak) {
            this.key = key;
            delta = mul(key, 4, tweak);
            ladder = Arrays.copyOf(key, 4);
            x2(ladder);
            this.offsets = offsets;
        }

        public void encryptBlock(int[] plaintext, int[] ciphertext) {
            int[] offset = offsets[index];

            aesRound(plaintext[0] ^ delta[0] ^ ladder[0] ^ offset[0],
                    plaintext[1] ^ delta[1] ^ ladder[1] ^ offset[1],
                    plaintext[2] ^ delta[2] ^ ladder[2] ^ offset[2],
                    plaintext[3] ^ delta[3] ^ ladder[3] ^ offset[3], temp, 0, key, 4);
            aesRound(temp, 0, ciphertext, 0, key, 0);
            aesRound(ciphertext, 0, temp, 0, key, 8);
            aesRound(temp, 0, ciphertext, 0, 0, 0, 0, 0);

            if ((index++ & 7) == 0) {
                x2(ladder);
            }
        }

        public void encryptBlock0(int[] plaintext, int[] ciphertext) {
            int[] offset = offsets[0];

            aesRound(plaintext[0] ^ delta[0] ^ key[0] ^ offset[0],
                    plaintext[1] ^ delta[1] ^ key[1] ^ offset[1],
                    plaintext[2] ^ delta[2] ^ key[2] ^ offset[2],
                    plaintext[3] ^ delta[3] ^ key[3] ^ offset[3], temp, 0, key, 4);
            aesRound(temp, 0, ciphertext, 0, key, 0);
            aesRound(ciphertext, 0, temp, 0, key, 8);
            aesRound(temp, 0, ciphertext, 0, 0, 0, 0, 0);
        }

    }

    public static final class AezHasher {

        private static final ValueLayout.OfInt LAYOUT = Tools.BIG_ENDIAN_32_BIT;

        private final Encipher cipher;
        private final int[] checksum = new int[4], data = new int[4];

        private AezHasher(int[] key, int[][] offsets, int counter) {
            cipher = new Encipher(key, offsets, counter + 2);
        }

        private void ingestOneBlock(MemorySegment aad, long offset) {
            data[0] = aad.get(LAYOUT, offset + 0);
            data[1] = aad.get(LAYOUT, offset + 4);
            data[2] = aad.get(LAYOUT, offset + 8);
            data[3] = aad.get(LAYOUT, offset + 12);

            cipher.encryptBlock(data, data);

            checksum[0] ^= data[0];
            checksum[1] ^= data[1];
            checksum[2] ^= data[2];
            checksum[3] ^= data[3];
        }

        private void ingestLastBlock(MemorySegment buffer, int length) {
            if (length > 0 || cipher.index == 1) {
                Tools.ozpad(buffer, length);
                data[0] = buffer.get(LAYOUT, 0);
                data[1] = buffer.get(LAYOUT, 4);
                data[2] = buffer.get(LAYOUT, 8);
                data[3] = buffer.get(LAYOUT, 12);

                cipher.encryptBlock0(data, data);

                checksum[0] ^= data[0];
                checksum[1] ^= data[1];
                checksum[2] ^= data[2];
                checksum[3] ^= data[3];
            }
        }
    }

}
