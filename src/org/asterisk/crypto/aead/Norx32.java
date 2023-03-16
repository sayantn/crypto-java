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
import java.util.Objects;
import org.asterisk.crypto.Tested;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.interfaces.AuthenticatedCipher;

import static java.lang.foreign.MemorySession.global;

/**
 *
 * @author Sayantan Chakraborty
 */
public final class Norx32 implements AuthenticatedCipher {

    private static final int RATE = 48;

    private static final int HEADER = 0x01, PAYLOAD = 0x02, TRAILER = 0x04, TAG = 0x08, BRANCH = 0x10, MERGE = 0x20;

    private static final ValueLayout.OfInt LAYOUT = Tools.LITTLE_ENDIAN_32_BIT;

    private static final int[] CONST = {
        0xa3d8d930, 0x3fa8b72c, 0xed84eb49, 0xedca4787, 0x335463eb, 0xf994220b, 0xbe0bf5c9, 0xd7c49104
    };

    public static void permute(int[] state, int rounds) {
        permute(state, state, rounds);
    }

    public static void permute(int[] srcState, int[] destState, int rounds) {
        int x0 = srcState[0];
        int x1 = srcState[1];
        int x2 = srcState[2];
        int x3 = srcState[3];
        int x4 = srcState[4];
        int x5 = srcState[5];
        int x6 = srcState[6];
        int x7 = srcState[7];
        int x8 = srcState[8];
        int x9 = srcState[9];
        int x10 = srcState[10];
        int x11 = srcState[11];
        int x12 = srcState[12];
        int x13 = srcState[13];
        int x14 = srcState[14];
        int x15 = srcState[15];

        for (int i = 0; i < rounds; i++) {
            x0 = x0 ^ x4 ^ ((x0 & x4) << 1);
            x12 = Integer.rotateRight(x0 ^ x12, 8);
            x8 = x8 ^ x12 ^ ((x8 & x12) << 1);
            x4 = Integer.rotateRight(x4 ^ x8, 11);
            x0 = x0 ^ x4 ^ ((x0 & x4) << 1);
            x12 = Integer.rotateRight(x0 ^ x12, RATE);
            x8 = x8 ^ x12 ^ ((x8 & x12) << 1);
            x4 = Integer.rotateRight(x4 ^ x8, 31);

            x1 = x1 ^ x5 ^ ((x1 & x5) << 1);
            x13 = Integer.rotateRight(x1 ^ x13, 8);
            x9 = x9 ^ x13 ^ ((x9 & x13) << 1);
            x5 = Integer.rotateRight(x5 ^ x9, 11);
            x1 = x1 ^ x5 ^ ((x1 & x5) << 1);
            x13 = Integer.rotateRight(x1 ^ x13, RATE);
            x9 = x9 ^ x13 ^ ((x9 & x13) << 1);
            x5 = Integer.rotateRight(x5 ^ x9, 31);

            x2 = x2 ^ x6 ^ ((x2 & x6) << 1);
            x14 = Integer.rotateRight(x2 ^ x14, 8);
            x10 = x10 ^ x14 ^ ((x10 & x14) << 1);
            x6 = Integer.rotateRight(x6 ^ x10, 11);
            x2 = x2 ^ x6 ^ ((x2 & x6) << 1);
            x14 = Integer.rotateRight(x2 ^ x14, RATE);
            x10 = x10 ^ x14 ^ ((x10 & x14) << 1);
            x6 = Integer.rotateRight(x6 ^ x10, 31);

            x3 = x3 ^ x7 ^ ((x3 & x7) << 1);
            x15 = Integer.rotateRight(x3 ^ x15, 8);
            x11 = x11 ^ x15 ^ ((x11 & x15) << 1);
            x7 = Integer.rotateRight(x7 ^ x11, 11);
            x3 = x3 ^ x7 ^ ((x3 & x7) << 1);
            x15 = Integer.rotateRight(x3 ^ x15, RATE);
            x11 = x11 ^ x15 ^ ((x11 & x15) << 1);
            x7 = Integer.rotateRight(x7 ^ x11, 31);

            x0 = x0 ^ x5 ^ ((x0 & x5) << 1);
            x15 = Integer.rotateRight(x0 ^ x15, 8);
            x10 = x10 ^ x15 ^ ((x10 & x15) << 1);
            x5 = Integer.rotateRight(x5 ^ x10, 11);
            x0 = x0 ^ x5 ^ ((x0 & x5) << 1);
            x15 = Integer.rotateRight(x0 ^ x15, RATE);
            x10 = x10 ^ x15 ^ ((x10 & x15) << 1);
            x5 = Integer.rotateRight(x5 ^ x10, 31);

            x1 = x1 ^ x6 ^ ((x1 & x6) << 1);
            x12 = Integer.rotateRight(x1 ^ x12, 8);
            x11 = x11 ^ x12 ^ ((x11 & x12) << 1);
            x6 = Integer.rotateRight(x6 ^ x11, 11);
            x1 = x1 ^ x6 ^ ((x1 & x6) << 1);
            x12 = Integer.rotateRight(x1 ^ x12, RATE);
            x11 = x11 ^ x12 ^ ((x11 & x12) << 1);
            x6 = Integer.rotateRight(x6 ^ x11, 31);

            x2 = x2 ^ x7 ^ ((x2 & x7) << 1);
            x13 = Integer.rotateRight(x2 ^ x13, 8);
            x8 = x8 ^ x13 ^ ((x8 & x13) << 1);
            x7 = Integer.rotateRight(x7 ^ x8, 11);
            x2 = x2 ^ x7 ^ ((x2 & x7) << 1);
            x13 = Integer.rotateRight(x2 ^ x13, RATE);
            x8 = x8 ^ x13 ^ ((x8 & x13) << 1);
            x7 = Integer.rotateRight(x7 ^ x8, 31);

            x3 = x3 ^ x4 ^ ((x3 & x4) << 1);
            x14 = Integer.rotateRight(x3 ^ x14, 8);
            x9 = x9 ^ x14 ^ ((x9 & x14) << 1);
            x4 = Integer.rotateRight(x4 ^ x9, 11);
            x3 = x3 ^ x4 ^ ((x3 & x4) << 1);
            x14 = Integer.rotateRight(x3 ^ x14, RATE);
            x9 = x9 ^ x14 ^ ((x9 & x14) << 1);
            x4 = Integer.rotateRight(x4 ^ x9, 31);
        }

        destState[0] = x0;
        destState[1] = x1;
        destState[2] = x2;
        destState[3] = x3;
        destState[4] = x4;
        destState[5] = x5;
        destState[6] = x6;
        destState[7] = x7;
        destState[8] = x8;
        destState[9] = x9;
        destState[10] = x10;
        destState[11] = x11;
        destState[12] = x12;
        destState[13] = x13;
        destState[14] = x14;
        destState[15] = x15;
    }

    private static void pad(MemorySegment buffer, int position) {
        if (position == RATE - 1) {
            buffer.set(ValueLayout.JAVA_BYTE, RATE - 1, (byte) 0x81);
        } else {
            buffer.set(ValueLayout.JAVA_BYTE, position, (byte) 0x01);
            buffer.asSlice(position + 1, RATE - position - 2).fill((byte) 0);
            buffer.set(ValueLayout.JAVA_BYTE, RATE - 1, (byte) 0x80);
        }
    }

    private static int[] load(byte[] key) {
        if (key.length < 16) {
            throw new IllegalArgumentException("Norx32 requires a 16 byte key, " + key.length + " bytes provided");
        }
        return new int[]{
            Tools.load32LE(key, 0), Tools.load32LE(key, 4), Tools.load32LE(key, 8), Tools.load32LE(key, 12)
        };
    }

    private final int rounds, parallelism;

    @Tested
    public Norx32(int rounds, int parallelism) {
        if (rounds <= 0) {
            throw new IllegalArgumentException("Rounds <= 0 : " + rounds);
        }
        if (parallelism < 0) {
            throw new IllegalArgumentException("Parallelism < 0 :" + parallelism);
        }
        this.rounds = rounds;
        this.parallelism = parallelism;
    }

    @Override
    public EncryptEngine startEncryption(byte[] key, byte[] iv) {
        return switch (parallelism) {
            case 1 ->
                new SerialNorx32Encrypter(key, iv);
            case 0 ->
                new BushNorx32Encrypter(key, iv);
            default ->
                new ParallelNorx32Encrypter(key, iv);
        };
    }

    @Override
    public DecryptEngine startDecryption(byte[] key, byte[] iv) {
        return switch (parallelism) {
            case 1 ->
                new SerialNorx32Decrypter(key, iv);
            case 0 ->
                new BushNorx32Decrypter(key, iv);
            default ->
                new ParallelNorx32Decrypter(key, iv);
        };
    }

    @Override
    public int keyLength() {
        return 16;
    }

    @Override
    public int ivLength() {
        return 16;
    }

    @Override
    public int tagLength() {
        return 16;
    }



    private int[] initialise(int[] k, byte[] iv) {
        if (iv.length < 16) {
            throw new IllegalArgumentException("Norx32 needs a 16 byte iv, " + iv.length + " bytes provided!");
        }

        int[] state = {
            Tools.load32LE(iv, 0), Tools.load32LE(iv, 4), Tools.load32LE(iv, 8), Tools.load32LE(iv, 12),
            k[0], k[1], k[2], k[3],
            CONST[0], CONST[1], CONST[2], CONST[3],
            CONST[4] ^ 32, CONST[5] ^ rounds, CONST[6] ^ parallelism, CONST[7] ^ 128
        };

        permute(state, rounds);

        state[12] ^= k[0];
        state[13] ^= k[1];
        state[14] ^= k[2];
        state[15] ^= k[3];

        return state;

    }

    private void absorbBlock(int[] state, MemorySegment input, long offset, int stage) {
        assert stage == HEADER || stage == TRAILER;

        state[15] ^= stage;

        permute(state, rounds);

        state[0] ^= input.get(LAYOUT, offset + 0);
        state[1] ^= input.get(LAYOUT, offset + 4);
        state[2] ^= input.get(LAYOUT, offset + 8);
        state[3] ^= input.get(LAYOUT, offset + 12);
        state[4] ^= input.get(LAYOUT, offset + 16);
        state[5] ^= input.get(LAYOUT, offset + 20);
        state[6] ^= input.get(LAYOUT, offset + 24);
        state[7] ^= input.get(LAYOUT, offset + 28);
        state[8] ^= input.get(LAYOUT, offset + 32);
        state[9] ^= input.get(LAYOUT, offset + 36);
        state[10] ^= input.get(LAYOUT, offset + 40);
        state[11] ^= input.get(LAYOUT, offset + 44);
    }

    private byte[] finalise(int[] state, int[] k) {
        state[15] ^= TAG;

        permute(state, rounds);

        state[12] ^= k[0];
        state[13] ^= k[1];
        state[14] ^= k[2];
        state[15] ^= k[3];

        permute(state, rounds);

        state[12] ^= k[0];
        state[13] ^= k[1];
        state[14] ^= k[2];
        state[15] ^= k[3];

        byte[] buf = new byte[16];
        Tools.store32LE(state[12], buf, 0);
        Tools.store32LE(state[13], buf, 4);
        Tools.store32LE(state[14], buf, 8);
        Tools.store32LE(state[15], buf, 12);

        return buf;
    }

    private void branch(int[] state, int[][] branches) {
        int[] first = branches[0];

        System.arraycopy(state, 0, first, 0, 16);

        first[15] ^= BRANCH;

        permute(first, rounds);

        for (int i = 1; i < parallelism; i++) {
            var branch = branches[i];

            branch[0] = first[0] ^ i;
            branch[1] = first[1] ^ i;
            branch[2] = first[2] ^ i;
            branch[3] = first[3] ^ i;
            branch[4] = first[4] ^ i;
            branch[5] = first[5] ^ i;
            branch[6] = first[6] ^ i;
            branch[7] = first[7] ^ i;
            branch[8] = first[8] ^ i;
            branch[9] = first[9] ^ i;
            branch[10] = first[10] ^ i;
            branch[11] = first[11] ^ i;
            branch[12] = first[12];
            branch[13] = first[13];
            branch[14] = first[14];
            branch[15] = first[15];
        }

    }

    private void merge(int[][] branches, int[] state) {
        Arrays.fill(state, 0);

        for (var branch : branches) {

            branch[15] ^= MERGE;

            permute(branch, rounds);

            state[0] ^= branch[0];
            state[1] ^= branch[1];
            state[2] ^= branch[2];
            state[3] ^= branch[3];
            state[4] ^= branch[4];
            state[5] ^= branch[5];
            state[6] ^= branch[6];
            state[7] ^= branch[7];
            state[8] ^= branch[8];
            state[9] ^= branch[9];
            state[10] ^= branch[10];
            state[11] ^= branch[11];
            state[12] ^= branch[12];
            state[13] ^= branch[13];
            state[14] ^= branch[14];
            state[15] ^= branch[15];
        }
    }

    private void encryptBlock(int[] state, MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
        state[15] ^= PAYLOAD;

        permute(state, rounds);

        state[0] ^= plaintext.get(LAYOUT, pOffset + 0);
        ciphertext.set(LAYOUT, cOffset + 0, state[0]);
        state[1] ^= plaintext.get(LAYOUT, pOffset + 4);
        ciphertext.set(LAYOUT, cOffset + 4, state[1]);
        state[2] ^= plaintext.get(LAYOUT, pOffset + 8);
        ciphertext.set(LAYOUT, cOffset + 8, state[2]);
        state[3] ^= plaintext.get(LAYOUT, pOffset + 12);
        ciphertext.set(LAYOUT, cOffset + 12, state[3]);
        state[4] ^= plaintext.get(LAYOUT, pOffset + 16);
        ciphertext.set(LAYOUT, cOffset + 16, state[4]);
        state[5] ^= plaintext.get(LAYOUT, pOffset + 20);
        ciphertext.set(LAYOUT, cOffset + 20, state[5]);
        state[6] ^= plaintext.get(LAYOUT, pOffset + 24);
        ciphertext.set(LAYOUT, cOffset + 24, state[6]);
        state[7] ^= plaintext.get(LAYOUT, pOffset + 28);
        ciphertext.set(LAYOUT, cOffset + 28, state[7]);
        state[8] ^= plaintext.get(LAYOUT, pOffset + 32);
        ciphertext.set(LAYOUT, cOffset + 32, state[8]);
        state[9] ^= plaintext.get(LAYOUT, pOffset + 36);
        ciphertext.set(LAYOUT, cOffset + 36, state[9]);
        state[10] ^= plaintext.get(LAYOUT, pOffset + 40);
        ciphertext.set(LAYOUT, cOffset + 40, state[10]);
        state[11] ^= plaintext.get(LAYOUT, pOffset + 44);
        ciphertext.set(LAYOUT, cOffset + 44, state[11]);

    }

    private void decryptBlock(int[] state, MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset) {
        state[15] ^= PAYLOAD;

        permute(state, rounds);

        int c;

        c = ciphertext.get(LAYOUT, cOffset + 0);
        plaintext.set(LAYOUT, pOffset + 0, c ^ state[0]);
        state[0] = c;
        c = ciphertext.get(LAYOUT, cOffset + 4);
        plaintext.set(LAYOUT, pOffset + 4, c ^ state[1]);
        state[1] = c;
        c = ciphertext.get(LAYOUT, cOffset + 8);
        plaintext.set(LAYOUT, pOffset + 8, c ^ state[2]);
        state[2] = c;
        c = ciphertext.get(LAYOUT, cOffset + 12);
        plaintext.set(LAYOUT, pOffset + 12, c ^ state[3]);
        state[3] = c;
        c = ciphertext.get(LAYOUT, cOffset + 16);
        plaintext.set(LAYOUT, pOffset + 16, c ^ state[4]);
        state[4] = c;
        c = ciphertext.get(LAYOUT, cOffset + 20);
        plaintext.set(LAYOUT, pOffset + 20, c ^ state[5]);
        state[5] = c;
        c = ciphertext.get(LAYOUT, cOffset + 24);
        plaintext.set(LAYOUT, pOffset + 24, c ^ state[6]);
        state[6] = c;
        c = ciphertext.get(LAYOUT, cOffset + 28);
        plaintext.set(LAYOUT, pOffset + 28, c ^ state[7]);
        state[7] = c;
        c = ciphertext.get(LAYOUT, cOffset + 32);
        plaintext.set(LAYOUT, pOffset + 32, c ^ state[8]);
        state[8] = c;
        c = ciphertext.get(LAYOUT, cOffset + 36);
        plaintext.set(LAYOUT, pOffset + 36, c ^ state[9]);
        state[9] = c;
        c = ciphertext.get(LAYOUT, cOffset + 40);
        plaintext.set(LAYOUT, pOffset + 40, c ^ state[10]);
        state[10] = c;
        c = ciphertext.get(LAYOUT, cOffset + 44);
        plaintext.set(LAYOUT, pOffset + 44, c ^ state[11]);
        state[11] = c;
    }

    private void decryptLast(int[] state, MemorySegment buffer, int position, MemorySegment plaintext) {
        state[15] ^= PAYLOAD;

        permute(state, rounds);

        buffer.set(LAYOUT, 0, buffer.get(LAYOUT, 0) ^ state[0]);
        buffer.set(LAYOUT, 4, buffer.get(LAYOUT, 4) ^ state[1]);
        buffer.set(LAYOUT, 8, buffer.get(LAYOUT, 8) ^ state[2]);
        buffer.set(LAYOUT, 12, buffer.get(LAYOUT, 12) ^ state[3]);
        buffer.set(LAYOUT, 16, buffer.get(LAYOUT, 16) ^ state[4]);
        buffer.set(LAYOUT, 20, buffer.get(LAYOUT, 20) ^ state[5]);
        buffer.set(LAYOUT, 24, buffer.get(LAYOUT, 24) ^ state[6]);
        buffer.set(LAYOUT, 28, buffer.get(LAYOUT, 28) ^ state[7]);
        buffer.set(LAYOUT, 32, buffer.get(LAYOUT, 32) ^ state[8]);
        buffer.set(LAYOUT, 36, buffer.get(LAYOUT, 36) ^ state[9]);
        buffer.set(LAYOUT, 40, buffer.get(LAYOUT, 40) ^ state[10]);
        buffer.set(LAYOUT, 44, buffer.get(LAYOUT, 44) ^ state[11]);

        pad(buffer, position);

        state[0] ^= buffer.get(LAYOUT, 0);
        state[1] ^= buffer.get(LAYOUT, 4);
        state[2] ^= buffer.get(LAYOUT, 8);
        state[3] ^= buffer.get(LAYOUT, 12);
        state[4] ^= buffer.get(LAYOUT, 16);
        state[5] ^= buffer.get(LAYOUT, 20);
        state[6] ^= buffer.get(LAYOUT, 24);
        state[7] ^= buffer.get(LAYOUT, 28);
        state[8] ^= buffer.get(LAYOUT, 32);
        state[9] ^= buffer.get(LAYOUT, 36);
        state[10] ^= buffer.get(LAYOUT, 40);
        state[11] ^= buffer.get(LAYOUT, 44);

        MemorySegment.copy(buffer, 0, plaintext, 0, position);

    }

    private final class SerialNorx32Encrypter extends AbstractNorx32Encrypter {

        private SerialNorx32Encrypter(byte[] key, byte[] iv) {
            super(key, iv, RATE);
        }

        @Override
        void prepareForCrypting() {
        }

        @Override
        void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
            encryptBlock(state, plaintext, pOffset, ciphertext, cOffset);
        }

        @Override
        void encryptLastBlock(MemorySegment buffer, int position, MemorySegment ciphertext) {
            pad(buffer, position);
            encryptBlock(state, buffer, 0, buffer, 0);
            MemorySegment.copy(buffer, 0, ciphertext, 0, position);
        }

    }

    private final class ParallelNorx32Encrypter extends AbstractNorx32Encrypter {

        private final int[][] branches = new int[parallelism][16];

        private ParallelNorx32Encrypter(byte[] key, byte[] iv) {
            super(key, iv, parallelism * RATE);
        }

        @Override
        void prepareForCrypting() {
            branch(state, branches);
        }

        @Override
        void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
            for (int i = 0; i < parallelism; i++, pOffset += RATE, cOffset += RATE) {
                encryptBlock(branches[i], plaintext, pOffset, ciphertext, cOffset);
            }
        }

        @Override
        void encryptLastBlock(MemorySegment buffer, int position, MemorySegment ciphertext) {
            int i = 0, offset = 0;
            while (position >= RATE) {
                encryptBlock(branches[i++], buffer, offset, ciphertext, offset);
                offset += RATE;
                position -= RATE;
            }
            pad(buffer.asSlice(offset, RATE), position);
            encryptBlock(branches[i], buffer, offset, buffer, offset);
            MemorySegment.copy(buffer, offset, ciphertext, offset, position);

            merge(branches, state);
        }

    }

    private final class BushNorx32Encrypter extends AbstractNorx32Encrypter {

        private final int[] copy = new int[16], temp = new int[16], checksum = new int[16];

        private int counter = 0;

        private BushNorx32Encrypter(byte[] key, byte[] iv) {
            super(key, iv, RATE);
        }

        @Override
        void prepareForCrypting() {
            System.arraycopy(state, 0, copy, 0, 16);

            copy[15] ^= BRANCH;

            permute(copy, rounds);
        }

        @Override
        void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
            temp[0] = copy[0] ^ counter;
            temp[1] = copy[1] ^ counter;
            temp[2] = copy[2] ^ counter;
            temp[3] = copy[3] ^ counter;
            temp[4] = copy[4] ^ counter;
            temp[5] = copy[5] ^ counter;
            temp[6] = copy[6] ^ counter;
            temp[7] = copy[7] ^ counter;
            temp[8] = copy[8] ^ counter;
            temp[9] = copy[9] ^ counter;
            temp[10] = copy[10] ^ counter;
            temp[11] = copy[11] ^ counter;
            temp[12] = copy[12];
            temp[13] = copy[13];
            temp[14] = copy[14];
            temp[15] = copy[15];

            encryptBlock(temp, plaintext, pOffset, ciphertext, cOffset);

            temp[15] ^= MERGE;

            permute(temp, rounds);

            checksum[0] ^= temp[0];
            checksum[1] ^= temp[1];
            checksum[2] ^= temp[2];
            checksum[3] ^= temp[3];
            checksum[4] ^= temp[4];
            checksum[5] ^= temp[5];
            checksum[6] ^= temp[6];
            checksum[7] ^= temp[7];
            checksum[8] ^= temp[8];
            checksum[9] ^= temp[9];
            checksum[10] ^= temp[10];
            checksum[11] ^= temp[11];
            checksum[12] ^= temp[12];
            checksum[13] ^= temp[13];
            checksum[14] ^= temp[14];
            checksum[15] ^= temp[15];

            counter++;

        }

        @Override
        void encryptLastBlock(MemorySegment buffer, int position, MemorySegment ciphertext) {
            pad(buffer, position);
            encryptOneBlock(buffer, 0, buffer, 0);
            MemorySegment.copy(buffer, 0, ciphertext, 0, position);
        }

    }

    private abstract class AbstractNorx32Encrypter implements EncryptEngine {

        final int[] state;

        private final int[] k;

        private final MemorySegment buffer;
        private int position = 0;

        private int stage = HEADER;

        private boolean inputAny = false;

        private final int rate;

        private AbstractNorx32Encrypter(byte[] key, byte[] iv, int rate) {
            k = load(key);
            state = initialise(k, iv);
            this.rate = rate;
            buffer = MemorySegment.allocateNative(rate, global());
        }

        @Override
        public void ingestAAD(MemorySegment aad) {
            switch (stage) {
                case PAYLOAD ->
                    throw new IllegalStateException("finish() must be called before ending crypting");
                case TAG ->
                    throw new IllegalStateException("Already extracted tag");
            }
            long offset = 0, length = aad.byteSize();

            inputAny |= length != 0;

            if (position > 0) {
                int take = (int) Math.min(length, RATE - position);
                MemorySegment.copy(aad, offset, buffer, position, take);
                offset += take;
                length -= take;
                position += take;
                if (position == RATE) {
                    absorbBlock(state, buffer, 0, stage);
                    position = 0;
                }
            }
            while (length >= RATE) {
                absorbBlock(state, aad, offset, stage);
                offset += RATE;
                length -= RATE;
            }
            if (length > 0) {
                MemorySegment.copy(aad, offset, buffer, 0, length);
                position = (int) length;
            }
        }

        abstract void prepareForCrypting();

        abstract void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset);

        abstract void encryptLastBlock(MemorySegment buffer, int position, MemorySegment ciphertext);

        @Override
        public long encrypt(MemorySegment plaintext, MemorySegment ciphertext) {
            switch (stage) {
                case HEADER -> {
                    if (inputAny) {
                        pad(buffer, position);
                        absorbBlock(state, buffer, 0, HEADER);
                        position = 0;
                        inputAny = false;
                    }
                    prepareForCrypting();
                    stage = PAYLOAD;
                }
                case TRAILER ->
                    throw new IllegalStateException("Cannot crypt after finish() call!");
                case TAG ->
                    throw new IllegalStateException("Tag already extracted!");
            }
            long pOffset = 0, length = plaintext.byteSize(), cOffset = 0;

            inputAny |= length != 0;

            if (position > 0) {
                int take = (int) Math.min(length, rate - position);
                MemorySegment.copy(plaintext, pOffset, buffer, position, take);
                pOffset += take;
                length -= take;
                position += take;
                if (position == rate) {
                    encryptOneBlock(buffer, 0, ciphertext, cOffset);
                    cOffset += rate;
                    position = 0;
                }
            }
            while (length >= rate) {
                encryptOneBlock(plaintext, pOffset, ciphertext, cOffset);
                pOffset += rate;
                length -= rate;
                cOffset += rate;
            }
            if (length > 0) {
                MemorySegment.copy(plaintext, pOffset, buffer, 0, length);
                position = (int) length;
            }
            return cOffset;
        }

        @Override
        public int finish(MemorySegment ciphertext) {
            return switch (stage) {
                case HEADER -> {
                    if (inputAny) {
                        pad(buffer, position);
                        absorbBlock(state, buffer, 0, HEADER);
                        inputAny = false;
                    }
                    position = 0;
                    stage = TRAILER;
                    yield 0;
                }
                case PAYLOAD -> {
                    if (inputAny) {
                        encryptLastBlock(buffer, position, ciphertext);
                        inputAny = false;
                    }
                    var ret = position;
                    position = 0;
                    stage = TRAILER;
                    yield ret;
                }
                case TRAILER ->
                    throw new IllegalStateException("Cannot call finish() twice!");
                case TAG ->
                    throw new IllegalStateException("Tag already extracted!");
                default ->
                    throw new AssertionError();
            };
        }

        @Override
        public void authenticate(byte[] tag, int offset, int length) {
            Objects.checkFromIndexSize(offset, length, tag.length);
            if (length > 16) {
                throw new IllegalArgumentException("Norx32 can produce tags of up to 16 bytes, requested " + length + " bytes");
            }

            switch (stage) {
                case HEADER, TRAILER -> {
                    if (inputAny) {
                        pad(buffer, position);
                        absorbBlock(state, buffer, 0, stage);
                        position = 0;
                    }
                }
                case PAYLOAD ->
                    throw new IllegalStateException("finish() must be called after crypting!");
                case TAG ->
                    throw new IllegalStateException("Tag already extracted!");
            }

            stage = TAG;

            var temp = finalise(state, k);
            System.arraycopy(temp, 16 - length, tag, offset, length);

        }

        @Override
        public AuthenticatedCipher getAlgorithm() {
            return Norx32.this;
        }

    }

    private final class SerialNorx32Decrypter extends AbstractNorx32Decrypter {

        private SerialNorx32Decrypter(byte[] key, byte[] iv) {
            super(key, iv, RATE);
        }

        @Override
        void prepareForCrypting() {
        }

        @Override
        void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset) {
            decryptBlock(state, ciphertext, cOffset, plaintext, pOffset);
        }

        @Override
        void decryptLastBlock(MemorySegment buffer, int position, MemorySegment plaintext) {
            decryptLast(state, buffer, position, plaintext);
        }

    }

    private final class ParallelNorx32Decrypter extends AbstractNorx32Decrypter {

        private final int[][] branches = new int[parallelism][16];

        private ParallelNorx32Decrypter(byte[] key, byte[] iv) {
            super(key, iv, parallelism * RATE);
        }

        @Override
        void prepareForCrypting() {
            branch(state, branches);
        }

        @Override
        void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset) {
            for (int i = 0; i < parallelism; i++, cOffset += RATE, pOffset += RATE) {
                decryptBlock(branches[i], ciphertext, cOffset, plaintext, pOffset);
            }
        }

        @Override
        void decryptLastBlock(MemorySegment buffer, int position, MemorySegment plaintext) {
            int i = 0, offset = 0;
            while (position >= RATE) {
                decryptBlock(branches[i++], buffer, offset, plaintext, offset);
                offset += RATE;
                position -= RATE;
            }
            decryptLast(branches[i], buffer.asSlice(offset, RATE), position, plaintext.asSlice(offset));

            merge(branches, state);

        }

    }

    private final class BushNorx32Decrypter extends AbstractNorx32Decrypter {

        private final int[] copy = new int[16], temp = new int[16], checksum = new int[16];

        private int counter = 0;

        private BushNorx32Decrypter(byte[] key, byte[] iv) {
            super(key, iv, RATE);
        }

        @Override
        void prepareForCrypting() {
            System.arraycopy(state, 0, copy, 0, 16);

            copy[15] ^= BRANCH;

            permute(copy, rounds);
        }

        @Override
        void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset) {
            temp[0] = copy[0] ^ counter;
            temp[1] = copy[1] ^ counter;
            temp[2] = copy[2] ^ counter;
            temp[3] = copy[3] ^ counter;
            temp[4] = copy[4] ^ counter;
            temp[5] = copy[5] ^ counter;
            temp[6] = copy[6] ^ counter;
            temp[7] = copy[7] ^ counter;
            temp[8] = copy[8] ^ counter;
            temp[9] = copy[9] ^ counter;
            temp[10] = copy[10] ^ counter;
            temp[11] = copy[11] ^ counter;
            temp[12] = copy[12];
            temp[13] = copy[13];
            temp[14] = copy[14];
            temp[15] = copy[15];

            decryptBlock(temp, ciphertext, cOffset, plaintext, pOffset);

            temp[15] ^= MERGE;

            permute(temp, rounds);

            checksum[0] ^= temp[0];
            checksum[1] ^= temp[1];
            checksum[2] ^= temp[2];
            checksum[3] ^= temp[3];
            checksum[4] ^= temp[4];
            checksum[5] ^= temp[5];
            checksum[6] ^= temp[6];
            checksum[7] ^= temp[7];
            checksum[8] ^= temp[8];
            checksum[9] ^= temp[9];
            checksum[10] ^= temp[10];
            checksum[11] ^= temp[11];
            checksum[12] ^= temp[12];
            checksum[13] ^= temp[13];
            checksum[14] ^= temp[14];
            checksum[15] ^= temp[15];

            counter++;

        }

        @Override
        void decryptLastBlock(MemorySegment buffer, int position, MemorySegment plaintext) {
            temp[0] = copy[0] ^ counter;
            temp[1] = copy[1] ^ counter;
            temp[2] = copy[2] ^ counter;
            temp[3] = copy[3] ^ counter;
            temp[4] = copy[4] ^ counter;
            temp[5] = copy[5] ^ counter;
            temp[6] = copy[6] ^ counter;
            temp[7] = copy[7] ^ counter;
            temp[8] = copy[8] ^ counter;
            temp[9] = copy[9] ^ counter;
            temp[10] = copy[10] ^ counter;
            temp[11] = copy[11] ^ counter;
            temp[12] = copy[12];
            temp[13] = copy[13];
            temp[14] = copy[14];
            temp[15] = copy[15];

            decryptLast(temp, buffer, position, plaintext);

            temp[15] ^= MERGE;

            permute(temp, rounds);

            checksum[0] ^= temp[0];
            checksum[1] ^= temp[1];
            checksum[2] ^= temp[2];
            checksum[3] ^= temp[3];
            checksum[4] ^= temp[4];
            checksum[5] ^= temp[5];
            checksum[6] ^= temp[6];
            checksum[7] ^= temp[7];
            checksum[8] ^= temp[8];
            checksum[9] ^= temp[9];
            checksum[10] ^= temp[10];
            checksum[11] ^= temp[11];
            checksum[12] ^= temp[12];
            checksum[13] ^= temp[13];
            checksum[14] ^= temp[14];
            checksum[15] ^= temp[15];
        }
    }

    private abstract class AbstractNorx32Decrypter implements DecryptEngine {

        final int[] state;

        private final int[] k;

        private final MemorySegment buffer;
        private int position = 0;

        private int stage = HEADER;

        private boolean inputAny = false;

        private final int rate;

        private AbstractNorx32Decrypter(byte[] key, byte[] iv, int rate) {
            k = load(key);
            state = initialise(k, iv);
            this.rate = rate;
            buffer = MemorySegment.allocateNative(rate, global());
        }

        @Override
        public void ingestAAD(MemorySegment aad) {
            switch (stage) {
                case PAYLOAD ->
                    throw new IllegalStateException("finish() must be called before ending crypting");
                case TAG ->
                    throw new IllegalStateException("Already extracted tag");
            }
            long offset = 0, length = aad.byteSize();

            inputAny |= length != 0;

            if (position > 0) {
                int take = (int) Math.min(length, RATE - position);
                MemorySegment.copy(aad, offset, buffer, position, take);
                offset += take;
                length -= take;
                position += take;
                if (position == RATE) {
                    absorbBlock(state, buffer, 0, stage);
                    position = 0;
                }
            }
            while (length >= RATE) {
                absorbBlock(state, aad, offset, stage);
                offset += RATE;
                length -= RATE;
            }
            if (length > 0) {
                MemorySegment.copy(aad, offset, buffer, 0, length);
                position = (int) length;
            }
        }

        abstract void prepareForCrypting();

        abstract void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset);

        abstract void decryptLastBlock(MemorySegment buffer, int position, MemorySegment plaintext);

        @Override
        public long decrypt(MemorySegment ciphertext, MemorySegment plaintext) {
            switch (stage) {
                case HEADER -> {
                    if (inputAny) {
                        pad(buffer, position);
                        absorbBlock(state, buffer, 0, HEADER);
                        position = 0;
                        inputAny = false;
                    }
                    prepareForCrypting();
                    stage = PAYLOAD;
                }
                case TRAILER ->
                    throw new IllegalStateException("Cannot crypt after finish() call!");
                case TAG ->
                    throw new IllegalStateException("Tag already extracted!");
            }
            long cOffset = 0, length = ciphertext.byteSize(), pOffset = 0;

            inputAny |= length != 0;

            if (position > 0) {
                int take = (int) Math.min(length, rate - position);
                MemorySegment.copy(ciphertext, cOffset, buffer, position, take);
                cOffset += take;
                length -= take;
                position += take;
                if (position == rate) {
                    decryptOneBlock(buffer, 0, plaintext, pOffset);
                    pOffset += rate;
                    position = 0;
                }
            }
            while (length >= rate) {
                decryptOneBlock(ciphertext, cOffset, plaintext, pOffset);
                cOffset += rate;
                length -= rate;
                pOffset += rate;
            }
            if (length > 0) {
                MemorySegment.copy(ciphertext, cOffset, buffer, 0, length);
                position = (int) length;
            }
            return cOffset;
        }

        @Override
        public int finish(MemorySegment plaintext) {
            return switch (stage) {
                case HEADER -> {
                    if (inputAny) {
                        pad(buffer, position);
                        absorbBlock(state, buffer, 0, HEADER);
                        inputAny = false;
                    }
                    position = 0;
                    stage = TRAILER;
                    yield 0;
                }
                case PAYLOAD -> {
                    if (inputAny) {
                        decryptLastBlock(buffer, position, plaintext);
                        inputAny = false;
                    }
                    var ret = position;
                    position = 0;
                    stage = TRAILER;
                    yield ret;
                }
                case TRAILER ->
                    throw new IllegalStateException("Cannot call finish() twice!");
                case TAG ->
                    throw new IllegalStateException("Tag already extracted!");
                default ->
                    throw new AssertionError();
            };
        }

        @Override
        public boolean verify(byte[] tag, int offset, int length) {
            Objects.checkFromIndexSize(offset, length, tag.length);
            if (length > 16) {
                throw new IllegalArgumentException("Norx32 can produce tags of up to 16 bytes, requested " + length + " bytes");
            }

            switch (stage) {
                case HEADER, TRAILER -> {
                    if (inputAny) {
                        pad(buffer, position);
                        absorbBlock(state, buffer, 0, stage);
                        position = 0;
                    }
                }
                case PAYLOAD ->
                    throw new IllegalStateException("finish() must be called after crypting!");
                case TAG ->
                    throw new IllegalStateException("Tag already extracted!");
            }

            stage = TAG;

            var temp = finalise(state, k);
            return Tools.equals(temp, 16 - length, tag, offset, length);
        }

        @Override
        public AuthenticatedCipher getAlgorithm() {
            return Norx32.this;
        }

    }

}
