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
public final class Norx64 implements AuthenticatedCipher {

    private static final int RATE = 96;

    private static final int HEADER = 0x01, PAYLOAD = 0x02, TRAILER = 0x04, TAG = 0x08, BRANCH = 0x10, MERGE = 0x20;

    private static final ValueLayout.OfLong LAYOUT = Tools.LITTLE_ENDIAN_64_BIT;

    private static final long[] CONST = {
        0xb15e641748de5e6bL, 0xaa95e955e10f8410L, 0x28d1034441a9dd40L, 0x7f31bbf964e93bf5L,
        0xb5e9e22493dffb96L, 0xb980c852479fafbdL, 0xda24516bf55eafd4L, 0x86026ae8536f1501L
    };

    public static void permute(long[] state, int rounds) {
        permute(state, state, rounds);
    }

    public static void permute(long[] srcState, long[] destState, int rounds) {
        long x0 = srcState[0];
        long x1 = srcState[1];
        long x2 = srcState[2];
        long x3 = srcState[3];
        long x4 = srcState[4];
        long x5 = srcState[5];
        long x6 = srcState[6];
        long x7 = srcState[7];
        long x8 = srcState[8];
        long x9 = srcState[9];
        long x10 = srcState[10];
        long x11 = srcState[11];
        long x12 = srcState[12];
        long x13 = srcState[13];
        long x14 = srcState[14];
        long x15 = srcState[15];

        for (int i = 0; i < rounds; i++) {
            x0 = x0 ^ x4 ^ ((x0 & x4) << 1);
            x12 = Long.rotateRight(x0 ^ x12, 8);
            x8 = x8 ^ x12 ^ ((x8 & x12) << 1);
            x4 = Long.rotateRight(x4 ^ x8, 19);
            x0 = x0 ^ x4 ^ ((x0 & x4) << 1);
            x12 = Long.rotateRight(x0 ^ x12, 40);
            x8 = x8 ^ x12 ^ ((x8 & x12) << 1);
            x4 = Long.rotateRight(x4 ^ x8, 63);

            x1 = x1 ^ x5 ^ ((x1 & x5) << 1);
            x13 = Long.rotateRight(x1 ^ x13, 8);
            x9 = x9 ^ x13 ^ ((x9 & x13) << 1);
            x5 = Long.rotateRight(x5 ^ x9, 19);
            x1 = x1 ^ x5 ^ ((x1 & x5) << 1);
            x13 = Long.rotateRight(x1 ^ x13, 40);
            x9 = x9 ^ x13 ^ ((x9 & x13) << 1);
            x5 = Long.rotateRight(x5 ^ x9, 63);

            x2 = x2 ^ x6 ^ ((x2 & x6) << 1);
            x14 = Long.rotateRight(x2 ^ x14, 8);
            x10 = x10 ^ x14 ^ ((x10 & x14) << 1);
            x6 = Long.rotateRight(x6 ^ x10, 19);
            x2 = x2 ^ x6 ^ ((x2 & x6) << 1);
            x14 = Long.rotateRight(x2 ^ x14, 40);
            x10 = x10 ^ x14 ^ ((x10 & x14) << 1);
            x6 = Long.rotateRight(x6 ^ x10, 63);

            x3 = x3 ^ x7 ^ ((x3 & x7) << 1);
            x15 = Long.rotateRight(x3 ^ x15, 8);
            x11 = x11 ^ x15 ^ ((x11 & x15) << 1);
            x7 = Long.rotateRight(x7 ^ x11, 19);
            x3 = x3 ^ x7 ^ ((x3 & x7) << 1);
            x15 = Long.rotateRight(x3 ^ x15, 40);
            x11 = x11 ^ x15 ^ ((x11 & x15) << 1);
            x7 = Long.rotateRight(x7 ^ x11, 63);

            x0 = x0 ^ x5 ^ ((x0 & x5) << 1);
            x15 = Long.rotateRight(x0 ^ x15, 8);
            x10 = x10 ^ x15 ^ ((x10 & x15) << 1);
            x5 = Long.rotateRight(x5 ^ x10, 19);
            x0 = x0 ^ x5 ^ ((x0 & x5) << 1);
            x15 = Long.rotateRight(x0 ^ x15, 40);
            x10 = x10 ^ x15 ^ ((x10 & x15) << 1);
            x5 = Long.rotateRight(x5 ^ x10, 63);

            x1 = x1 ^ x6 ^ ((x1 & x6) << 1);
            x12 = Long.rotateRight(x1 ^ x12, 8);
            x11 = x11 ^ x12 ^ ((x11 & x12) << 1);
            x6 = Long.rotateRight(x6 ^ x11, 19);
            x1 = x1 ^ x6 ^ ((x1 & x6) << 1);
            x12 = Long.rotateRight(x1 ^ x12, 40);
            x11 = x11 ^ x12 ^ ((x11 & x12) << 1);
            x6 = Long.rotateRight(x6 ^ x11, 63);

            x2 = x2 ^ x7 ^ ((x2 & x7) << 1);
            x13 = Long.rotateRight(x2 ^ x13, 8);
            x8 = x8 ^ x13 ^ ((x8 & x13) << 1);
            x7 = Long.rotateRight(x7 ^ x8, 19);
            x2 = x2 ^ x7 ^ ((x2 & x7) << 1);
            x13 = Long.rotateRight(x2 ^ x13, 40);
            x8 = x8 ^ x13 ^ ((x8 & x13) << 1);
            x7 = Long.rotateRight(x7 ^ x8, 63);

            x3 = x3 ^ x4 ^ ((x3 & x4) << 1);
            x14 = Long.rotateRight(x3 ^ x14, 8);
            x9 = x9 ^ x14 ^ ((x9 & x14) << 1);
            x4 = Long.rotateRight(x4 ^ x9, 19);
            x3 = x3 ^ x4 ^ ((x3 & x4) << 1);
            x14 = Long.rotateRight(x3 ^ x14, 40);
            x9 = x9 ^ x14 ^ ((x9 & x14) << 1);
            x4 = Long.rotateRight(x4 ^ x9, 63);
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

    private static long[] load(byte[] key) {
        if (key.length < 32) {
            throw new IllegalArgumentException("Norx64 requires a 32 byte key, " + key.length + " bytes provided");
        }
        return new long[]{
            Tools.load64LE(key, 0), Tools.load64LE(key, 8), Tools.load64LE(key, 16), Tools.load64LE(key, 24)
        };
    }

    private final int rounds, parallelism;

    @Tested
    public Norx64(int rounds, int parallelism) {
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
                new SerialNorx64Encrypter(key, iv);
            case 0 ->
                new BushNorx64Encrypter(key, iv);
            default ->
                new ParallelNorx64Encrypter(key, iv);
        };
    }

    @Override
    public DecryptEngine startDecryption(byte[] key, byte[] iv) {
        return switch (parallelism) {
            case 1 ->
                new SerialNorx64Decrypter(key, iv);
            case 0 ->
                new BushNorx64Decrypter(key, iv);
            default ->
                new ParallelNorx64Decrypter(key, iv);
        };
    }

    @Override
    public int keyLength() {
        return 32;
    }

    @Override
    public int ivLength() {
        return 32;
    }

    @Override
    public int tagLength() {
        return 32;
    }



    private long[] initialise(long[] k, byte[] iv) {
        if (iv.length < 32) {
            throw new IllegalArgumentException("Norx64 needs a 32 byte iv, " + iv.length + " bytes provided!");
        }

        long[] state = {
            Tools.load64LE(iv, 0), Tools.load64LE(iv, 8), Tools.load64LE(iv, 16), Tools.load64LE(iv, 24),
            k[0], k[1], k[2], k[3],
            CONST[0], CONST[1], CONST[2], CONST[3],
            CONST[4] ^ 64, CONST[5] ^ rounds, CONST[6] ^ parallelism, CONST[7] ^ 256
        };

        permute(state, rounds);

        state[12] ^= k[0];
        state[13] ^= k[1];
        state[14] ^= k[2];
        state[15] ^= k[3];

        return state;
    }

    private void absorbBlock(long[] state, MemorySegment input, long offset, int stage) {
        assert stage == HEADER || stage == TRAILER;

        state[15] ^= stage;

        permute(state, rounds);

        state[0] ^= input.get(LAYOUT, offset + 0);
        state[1] ^= input.get(LAYOUT, offset + 8);
        state[2] ^= input.get(LAYOUT, offset + 16);
        state[3] ^= input.get(LAYOUT, offset + 24);
        state[4] ^= input.get(LAYOUT, offset + 32);
        state[5] ^= input.get(LAYOUT, offset + 40);
        state[6] ^= input.get(LAYOUT, offset + 48);
        state[7] ^= input.get(LAYOUT, offset + 56);
        state[8] ^= input.get(LAYOUT, offset + 64);
        state[9] ^= input.get(LAYOUT, offset + 72);
        state[10] ^= input.get(LAYOUT, offset + 80);
        state[11] ^= input.get(LAYOUT, offset + 88);
    }

    private byte[] finalise(long[] state, long[] k) {
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

        byte[] buf = new byte[32];
        Tools.store64LE(state[12], buf, 0);
        Tools.store64LE(state[13], buf, 8);
        Tools.store64LE(state[14], buf, 16);
        Tools.store64LE(state[15], buf, 24);

        return buf;
    }

    private void branch(long[] state, long[][] branches) {
        long[] first = branches[0];

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

    private void merge(long[][] branches, long[] state) {
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

    private void encryptBlock(long[] state, MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
        state[15] ^= PAYLOAD;

        permute(state, rounds);

        state[0] ^= plaintext.get(LAYOUT, pOffset + 0);
        ciphertext.set(LAYOUT, cOffset + 0, state[0]);
        state[1] ^= plaintext.get(LAYOUT, pOffset + 8);
        ciphertext.set(LAYOUT, cOffset + 8, state[1]);
        state[2] ^= plaintext.get(LAYOUT, pOffset + 16);
        ciphertext.set(LAYOUT, cOffset + 16, state[2]);
        state[3] ^= plaintext.get(LAYOUT, pOffset + 24);
        ciphertext.set(LAYOUT, cOffset + 24, state[3]);
        state[4] ^= plaintext.get(LAYOUT, pOffset + 32);
        ciphertext.set(LAYOUT, cOffset + 32, state[4]);
        state[5] ^= plaintext.get(LAYOUT, pOffset + 40);
        ciphertext.set(LAYOUT, cOffset + 40, state[5]);
        state[6] ^= plaintext.get(LAYOUT, pOffset + 48);
        ciphertext.set(LAYOUT, cOffset + 48, state[6]);
        state[7] ^= plaintext.get(LAYOUT, pOffset + 56);
        ciphertext.set(LAYOUT, cOffset + 56, state[7]);
        state[8] ^= plaintext.get(LAYOUT, pOffset + 64);
        ciphertext.set(LAYOUT, cOffset + 64, state[8]);
        state[9] ^= plaintext.get(LAYOUT, pOffset + 72);
        ciphertext.set(LAYOUT, cOffset + 72, state[9]);
        state[10] ^= plaintext.get(LAYOUT, pOffset + 80);
        ciphertext.set(LAYOUT, cOffset + 80, state[10]);
        state[11] ^= plaintext.get(LAYOUT, pOffset + 88);
        ciphertext.set(LAYOUT, cOffset + 88, state[11]);

    }

    private void decryptBlock(long[] state, MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset) {
        state[15] ^= PAYLOAD;

        permute(state, rounds);

        long c;

        c = ciphertext.get(LAYOUT, cOffset + 0);
        plaintext.set(LAYOUT, pOffset + 0, c ^ state[0]);
        state[0] = c;
        c = ciphertext.get(LAYOUT, cOffset + 8);
        plaintext.set(LAYOUT, pOffset + 8, c ^ state[1]);
        state[1] = c;
        c = ciphertext.get(LAYOUT, cOffset + 16);
        plaintext.set(LAYOUT, pOffset + 16, c ^ state[2]);
        state[2] = c;
        c = ciphertext.get(LAYOUT, cOffset + 24);
        plaintext.set(LAYOUT, pOffset + 24, c ^ state[3]);
        state[3] = c;
        c = ciphertext.get(LAYOUT, cOffset + 32);
        plaintext.set(LAYOUT, pOffset + 32, c ^ state[4]);
        state[4] = c;
        c = ciphertext.get(LAYOUT, cOffset + 40);
        plaintext.set(LAYOUT, pOffset + 40, c ^ state[5]);
        state[5] = c;
        c = ciphertext.get(LAYOUT, cOffset + 48);
        plaintext.set(LAYOUT, pOffset + 48, c ^ state[6]);
        state[6] = c;
        c = ciphertext.get(LAYOUT, cOffset + 56);
        plaintext.set(LAYOUT, pOffset + 56, c ^ state[7]);
        state[7] = c;
        c = ciphertext.get(LAYOUT, cOffset + 64);
        plaintext.set(LAYOUT, pOffset + 64, c ^ state[8]);
        state[8] = c;
        c = ciphertext.get(LAYOUT, cOffset + 72);
        plaintext.set(LAYOUT, pOffset + 72, c ^ state[9]);
        state[9] = c;
        c = ciphertext.get(LAYOUT, cOffset + 80);
        plaintext.set(LAYOUT, pOffset + 80, c ^ state[10]);
        state[10] = c;
        c = ciphertext.get(LAYOUT, cOffset + 88);
        plaintext.set(LAYOUT, pOffset + 88, c ^ state[11]);
        state[11] = c;
    }

    private void decryptLast(long[] state, MemorySegment buffer, int position, MemorySegment plaintext) {
        state[15] ^= PAYLOAD;

        permute(state, rounds);

        buffer.set(LAYOUT, 0, buffer.get(LAYOUT, 0) ^ state[0]);
        buffer.set(LAYOUT, 8, buffer.get(LAYOUT, 8) ^ state[1]);
        buffer.set(LAYOUT, 16, buffer.get(LAYOUT, 16) ^ state[2]);
        buffer.set(LAYOUT, 24, buffer.get(LAYOUT, 24) ^ state[3]);
        buffer.set(LAYOUT, 32, buffer.get(LAYOUT, 32) ^ state[4]);
        buffer.set(LAYOUT, 40, buffer.get(LAYOUT, 40) ^ state[5]);
        buffer.set(LAYOUT, 48, buffer.get(LAYOUT, 48) ^ state[6]);
        buffer.set(LAYOUT, 56, buffer.get(LAYOUT, 56) ^ state[7]);
        buffer.set(LAYOUT, 64, buffer.get(LAYOUT, 64) ^ state[8]);
        buffer.set(LAYOUT, 72, buffer.get(LAYOUT, 72) ^ state[9]);
        buffer.set(LAYOUT, 80, buffer.get(LAYOUT, 80) ^ state[10]);
        buffer.set(LAYOUT, 88, buffer.get(LAYOUT, 88) ^ state[11]);

        pad(buffer, position);

        state[0] ^= buffer.get(LAYOUT, 0);
        state[1] ^= buffer.get(LAYOUT, 8);
        state[2] ^= buffer.get(LAYOUT, 16);
        state[3] ^= buffer.get(LAYOUT, 24);
        state[4] ^= buffer.get(LAYOUT, 32);
        state[5] ^= buffer.get(LAYOUT, 40);
        state[6] ^= buffer.get(LAYOUT, 48);
        state[7] ^= buffer.get(LAYOUT, 56);
        state[8] ^= buffer.get(LAYOUT, 64);
        state[9] ^= buffer.get(LAYOUT, 72);
        state[10] ^= buffer.get(LAYOUT, 80);
        state[11] ^= buffer.get(LAYOUT, 88);

        MemorySegment.copy(buffer, 0, plaintext, 0, position);

    }

    private final class SerialNorx64Encrypter extends AbstractNorx64Encrypter {

        private SerialNorx64Encrypter(byte[] key, byte[] iv) {
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

    private final class ParallelNorx64Encrypter extends AbstractNorx64Encrypter {

        private final long[][] branches = new long[parallelism][16];

        private ParallelNorx64Encrypter(byte[] key, byte[] iv) {
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

    private final class BushNorx64Encrypter extends AbstractNorx64Encrypter {

        private final long[] copy = new long[16], temp = new long[16], checksum = new long[16];

        private int counter = 0;

        private BushNorx64Encrypter(byte[] key, byte[] iv) {
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

    private abstract class AbstractNorx64Encrypter implements EncryptEngine {

        final long[] state;

        private final long[] k;

        private final MemorySegment buffer;
        private int position = 0;

        private int stage = HEADER;

        private boolean inputAny = false;

        private final int rate;

        private AbstractNorx64Encrypter(byte[] key, byte[] iv, int rate) {
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
            if (length > 32) {
                throw new IllegalArgumentException("Norx64 can produce tags of up to 32 bytes, requested " + length + " bytes");
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
            System.arraycopy(temp, 32 - length, tag, offset, length);

        }

        @Override
        public AuthenticatedCipher getAlgorithm() {
            return Norx64.this;
        }

    }

    private final class SerialNorx64Decrypter extends AbstractNorx64Decrypter {

        private SerialNorx64Decrypter(byte[] key, byte[] iv) {
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

    private final class ParallelNorx64Decrypter extends AbstractNorx64Decrypter {

        private final long[][] branches = new long[parallelism][16];

        private ParallelNorx64Decrypter(byte[] key, byte[] iv) {
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

    private final class BushNorx64Decrypter extends AbstractNorx64Decrypter {

        private final long[] copy = new long[16], temp = new long[16], checksum = new long[16];

        private long counter = 0;

        private BushNorx64Decrypter(byte[] key, byte[] iv) {
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

    private abstract class AbstractNorx64Decrypter implements DecryptEngine {

        final long[] state;

        private final long[] k;

        private final MemorySegment buffer;
        private int position = 0;

        private int stage = HEADER;

        private boolean inputAny = false;

        private final int rate;

        private AbstractNorx64Decrypter(byte[] key, byte[] iv, int rate) {
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
            if (length > 32) {
                throw new IllegalArgumentException("Norx64 can produce tags of up to 32 bytes, requested " + length + " bytes");
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
            return Tools.equals(temp, 32 - length, tag, offset, length);
        }

        @Override
        public AuthenticatedCipher getAlgorithm() {
            return Norx64.this;
        }

    }

}
