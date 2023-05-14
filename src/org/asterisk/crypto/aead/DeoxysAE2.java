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
import java.lang.foreign.SegmentScope;
import javax.crypto.AEADBadTagException;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.interfaces.SimpleAead;
import org.asterisk.crypto.lowlevel.DeoxysTBC;

import static org.asterisk.crypto.helper.Tools.BIG_ENDIAN_32_BIT;
import static org.asterisk.crypto.helper.Tools.load32BE;
import static org.asterisk.crypto.helper.Tools.ozpad;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum DeoxysAE2 implements SimpleAead {

    DEOXYS_AE2;

    private static final int BLOCK = 0x02000000, LAST = 0x04000000, TAG = 0x01000000;

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

    @Override
    public long encrypt(byte[] key, byte[] iv, MemorySegment aad, MemorySegment plaintext, MemorySegment ciphertext, byte[] tag, int tOffset, int tLength) {
        if (tLength != 16) {
            throw new IllegalArgumentException("Deoxys-AE2 always exports a 16 byte tag");
        }
        var encrypter = startEncryption(key, iv);
        encrypter.ingestAAD(aad);
        encrypter.firstPass(plaintext);
        encrypter.authenticate(tag, tOffset);
        var offset = encrypter.secondPass(plaintext, ciphertext);
        offset += encrypter.finishSecondPass(ciphertext.asSlice(offset));
        return offset;
    }

    @Override
    public long decrypt(byte[] key, byte[] iv, MemorySegment aad, MemorySegment ciphertext, MemorySegment plaintext, byte[] tag, int tOffset, int tLength) throws AEADBadTagException {
        if (tLength != 16) {
            throw new IllegalArgumentException("Deoxys-AE2 always exports a 16 byte tag");
        }
        var decrypter = startDecryption(key, iv);
        decrypter.ingestAAD(aad);
        decrypter.setTag(tag, tOffset);
        var offset = decrypter.decrypt(ciphertext, plaintext);
        offset += decrypter.finish(plaintext.asSlice(offset));
        if (!decrypter.verify()) {
            plaintext.asSlice(0, offset).fill((byte) 0);
            throw new AEADBadTagException();
        }
        return offset;
    }

    public Encrypter startEncryption(byte[] key, byte[] iv) {
        if (key.length < keyLength()) {
            throw new IllegalArgumentException(this + " requires a key of " + keyLength() + " bytes, passed only " + key.length + " bytes");
        }
        if (iv.length < 16) {
            throw new IllegalArgumentException(this + " requires an iv of 16 bytes, passed only " + iv.length + " bytes");
        }
        return new Encrypter(key, iv);
    }

    public Decrypter startDecryption(byte[] key, byte[] iv) {
        if (key.length < keyLength()) {
            throw new IllegalArgumentException(this + " requires a key of " + keyLength() + " bytes, passed only " + key.length + " bytes");
        }
        if (iv.length < 16) {
            throw new IllegalArgumentException(this + " requires an iv of 16 bytes, passed only " + iv.length + " bytes");
        }
        return new Decrypter(key, iv);
    }

    private enum State {
        INGESTING, FIRST_PASS, SECOND_PASS, CLOSED
    }

    public static class Encrypter {

        private final MemorySegment buffer = MemorySegment.allocateNative(32, SegmentScope.auto());
        private int position = 0;

        private final int[] auth = new int[4], tweak = new int[8], data = new int[4], savednonce, savedtag = new int[4];

        private final DeoxysTBC.DeoxysTBC_128_256 blockCipher;

        private long counter = 0;

        private State state = State.INGESTING;

        private Encrypter(byte[] key, byte[] iv) {
            blockCipher = new DeoxysTBC.DeoxysTBC_128_256(key);
            savednonce = new int[]{
                load32BE(iv, 0),
                load32BE(iv, 4),
                load32BE(iv, 8),
                load32BE(iv, 12)
            };
            tweak[4] = BLOCK;
        }

        private void ingestOneBlock(MemorySegment aad, long offset) {
            tweak[6] = (int) (counter >>> 32);
            tweak[7] = (int) counter;

            tweak[0] = aad.get(BIG_ENDIAN_32_BIT, offset + 0);
            tweak[1] = aad.get(BIG_ENDIAN_32_BIT, offset + 4);
            tweak[2] = aad.get(BIG_ENDIAN_32_BIT, offset + 8);
            tweak[3] = aad.get(BIG_ENDIAN_32_BIT, offset + 12);

            data[0] = aad.get(BIG_ENDIAN_32_BIT, offset + 16);
            data[1] = aad.get(BIG_ENDIAN_32_BIT, offset + 20);
            data[2] = aad.get(BIG_ENDIAN_32_BIT, offset + 24);
            data[3] = aad.get(BIG_ENDIAN_32_BIT, offset + 28);

            blockCipher.setTweak(tweak);
            blockCipher.encryptBlock(data, 0, data, 0);

            auth[0] ^= data[0];
            auth[1] ^= data[1];
            auth[2] ^= data[2];
            auth[3] ^= data[3];

            counter++;

        }

        private void ingestLastBlock() {
            if (position > 0) {
                tweak[4] |= LAST;
                ozpad(buffer, position);
                ingestOneBlock(buffer, 0);
                position = 0;
            }
            tweak[4] = 0;
            counter = 0;
        }

        public void ingestAAD(MemorySegment input) {
            if (state != State.INGESTING) {
                throw new IllegalStateException("Cannot ingest AAD after starting encrypting!");
            }
            long offset = 0, length = input.byteSize();
            if (position > 0) {
                int take = (int) Math.min(length, 32 - position);
                MemorySegment.copy(input, offset, buffer, position, take);
                offset += take;
                length -= take;
                position += take;
                if (position == 32) {
                    ingestOneBlock(buffer, 0);
                    position = 0;
                }
            }
            while (length >= 32) {
                ingestOneBlock(input, offset);
                offset += 32;
                length -= 32;
            }
            if (length > 0) {
                MemorySegment.copy(input, offset, buffer, 0, length);
                position = (int) length;
            }
        }

        public void ingestAAD(byte[] aad, int offset, int length) {
            ingestAAD(MemorySegment.ofArray(aad).asSlice(offset, length));
        }

        public void ingestAAD(byte[] aad) {
            ingestAAD(MemorySegment.ofArray(aad));
        }

        private void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
            tweak[2] = (int) (counter >>> 32);
            tweak[3] = (int) counter;

            blockCipher.setTweak1(tweak);
            blockCipher.encryptBlock(savednonce, 0, data, 0);

            ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 0, plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 0) ^ data[0]);
            ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 4, plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 4) ^ data[1]);
            ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 8, plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 8) ^ data[2]);
            ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 12, plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 12) ^ data[3]);

            counter++;
        }

        private void generateTag() {
            tweak[0] = TAG;
            tweak[1] = 0;
            tweak[2] = 0;
            tweak[3] = 0;

            blockCipher.setTweak0(savednonce);
            blockCipher.setTweak1(tweak);
            blockCipher.encryptBlock(auth, 0, savedtag, 0);

            blockCipher.setTweak0(savedtag);
            tweak[0] |= BLOCK;
            tweak[1] = 0;
        }

        public void firstPass(MemorySegment plaintext) {
            switch (state) {
                case INGESTING -> {
                    ingestLastBlock();
                    state = State.FIRST_PASS;
                }
                case SECOND_PASS ->
                    throw new IllegalStateException("First pass can be done only once");
                case CLOSED ->
                    throw new IllegalStateException("Cannot encrypt more than once");
            }
            long offset = 0, length = plaintext.byteSize();
            if (position > 0) {
                int take = (int) Math.min(length, 32 - position);
                MemorySegment.copy(plaintext, offset, buffer, position, take);
                offset += take;
                length -= take;
                position += take;
                if (position == 32) {
                    ingestOneBlock(buffer, 0);
                    position = 0;
                }
            }

            while (length >= 32) {
                ingestOneBlock(plaintext, offset);

                offset += 32;
                length -= 32;
            }
            if (length > 0) {
                MemorySegment.copy(plaintext, offset, buffer, 0, length);
                position = (int) length;
            }
        }

        public void authenticate(byte[] tag, int offset) {
            if (tag.length - offset < 16) {
                throw new IllegalArgumentException("Deoxys-AE2 always exports a 16 byte tag, but buffer provided has size " + (tag.length - offset));
            }
            if (state == State.INGESTING || state == State.FIRST_PASS) {
                ingestLastBlock();
                state = State.SECOND_PASS;
                generateTag();
            }
            Tools.store32BE(savedtag[0], tag, offset + 0);
            Tools.store32BE(savedtag[1], tag, offset + 4);
            Tools.store32BE(savedtag[2], tag, offset + 8);
            Tools.store32BE(savedtag[3], tag, offset + 12);
        }

        public long secondPass(MemorySegment plaintext, MemorySegment ciphertext) {
            switch (state) {
                case INGESTING, FIRST_PASS -> {
                    ingestLastBlock();
                    state = State.SECOND_PASS;
                    generateTag();
                }
                case CLOSED ->
                    throw new IllegalStateException("Cannot encrypt more than once");
            }
            long pOffset = 0, cOffset = 0, length = plaintext.byteSize();
            if (position > 0) {
                int take = (int) Math.min(length, 16 - position);
                MemorySegment.copy(plaintext, pOffset, buffer, position, take);
                pOffset += take;
                length -= take;
                position += take;
                if (position == 16) {
                    encryptOneBlock(buffer, 0, ciphertext, cOffset);
                    cOffset += 16;
                    position = 0;
                }
            }

            while (length >= 16) {
                encryptOneBlock(plaintext, pOffset, ciphertext, cOffset);

                pOffset += 16;
                cOffset += 16;
                length -= 16;
            }
            if (length > 0) {
                MemorySegment.copy(plaintext, pOffset, buffer, 0, length);
                position = (int) length;
            }
            return pOffset;
        }

        public int finishSecondPass(MemorySegment ciphertext) {
            return switch (state) {
                case INGESTING, FIRST_PASS -> {
                    ingestLastBlock();
                    state = State.CLOSED;
                    generateTag();
                    yield 0;
                }
                case SECOND_PASS -> {
                    tweak[0] |= LAST;
                    encryptOneBlock(buffer, 0, buffer, 0);
                    MemorySegment.copy(buffer, 0, ciphertext, 0, position);
                    state = State.CLOSED;
                    yield position;
                }
                case CLOSED ->
                    throw new IllegalStateException("Already closed!");
            };
        }

    }

    public static class Decrypter {

        private final MemorySegment buffer = MemorySegment.allocateNative(32, SegmentScope.auto());
        private int position = 0;

        private final DeoxysTBC.DeoxysTBC_128_256 authCipher, cryptCipher;

        private final int[] authTweak = new int[8], cryptTweak = new int[4], data = new int[4], savednonce, savedtag = new int[4], auth = new int[4];

        private long authCtr = 0, cryptCtr = 0;

        private boolean ingestingAAD = true, tagSet = false;

        private Decrypter(byte[] key, byte[] iv) {
            authCipher = new DeoxysTBC.DeoxysTBC_128_256(key);
            cryptCipher = new DeoxysTBC.DeoxysTBC_128_256(authCipher);

            savednonce = new int[]{
                load32BE(iv, 0),
                load32BE(iv, 4),
                load32BE(iv, 8),
                load32BE(iv, 12)
            };

            authTweak[4] = BLOCK;
        }

        private void ingestOneBlock(MemorySegment aad, long offset) {
            authTweak[0] = aad.get(BIG_ENDIAN_32_BIT, offset + 0);
            authTweak[1] = aad.get(BIG_ENDIAN_32_BIT, offset + 4);
            authTweak[2] = aad.get(BIG_ENDIAN_32_BIT, offset + 8);
            authTweak[3] = aad.get(BIG_ENDIAN_32_BIT, offset + 12);

            authTweak[6] = (int) (authCtr >>> 32);
            authTweak[7] = (int) authCtr;

            data[0] = aad.get(BIG_ENDIAN_32_BIT, offset + 16);
            data[1] = aad.get(BIG_ENDIAN_32_BIT, offset + 20);
            data[2] = aad.get(BIG_ENDIAN_32_BIT, offset + 24);
            data[3] = aad.get(BIG_ENDIAN_32_BIT, offset + 28);

            authCipher.setTweak(authTweak);
            authCipher.encryptBlock(data, 0, data, 0);

            auth[0] ^= data[0];
            auth[1] ^= data[1];
            auth[2] ^= data[2];
            auth[3] ^= data[3];

            authCtr++;
        }

        private void ingestLastBlock() {
            if (position > 0) {
                ozpad(buffer, position);
                authTweak[4] |= LAST;
                ingestOneBlock(buffer, 0);
            }
            authCtr = 0;
            authTweak[4] = 0;
        }

        public void ingestAAD(MemorySegment input) {
            if (!ingestingAAD) {
                throw new IllegalStateException("Cannot ingest aad after starting to encrypt!");
            }
            long offset = 0, length = input.byteSize();
            if (position > 0) {
                int take = (int) Math.min(length, 32 - position);
                MemorySegment.copy(input, offset, buffer, position, take);
                offset += take;
                length -= take;
                position += take;
                if (position == 32) {
                    ingestOneBlock(buffer, 0);
                    position = 0;
                }
            }
            while (length >= 32) {
                ingestOneBlock(input, offset);
                offset += 32;
                length -= 32;
            }
            if (length > 0) {
                MemorySegment.copy(input, offset, buffer, 0, length);
                position = (int) length;
            }
        }

        public void setTag(byte[] tag, int offset) {
            if (tagSet) {
                throw new IllegalStateException("Tag already set!");
            }
            savedtag[0] = load32BE(tag, offset + 0);
            savedtag[1] = load32BE(tag, offset + 4);
            savedtag[2] = load32BE(tag, offset + 8);
            savedtag[3] = load32BE(tag, offset + 12);

            cryptCipher.setTweak0(savedtag);

            cryptTweak[0] = TAG | BLOCK;

            tagSet = true;
        }

        private void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset) {
            cryptTweak[2] = (int) (cryptCtr >>> 32);
            cryptTweak[3] = (int) cryptCtr;

            cryptCipher.setTweak1(cryptTweak);
            cryptCipher.encryptBlock(savednonce, 0, authTweak, 0);

            authTweak[0] ^= ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 0);
            authTweak[1] ^= ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 4);
            authTweak[2] ^= ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 8);
            authTweak[3] ^= ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 12);

            plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 0, authTweak[0]);
            plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 4, authTweak[1]);
            plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 8, authTweak[2]);
            plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 12, authTweak[3]);

            cryptCtr++;

            cryptTweak[2] = (int) (cryptCtr >>> 32);
            cryptTweak[3] = (int) cryptCtr;

            cryptCipher.setTweak1(cryptTweak);
            cryptCipher.encryptBlock(savednonce, 0, data, 0);

            data[0] ^= ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 16);
            data[1] ^= ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 20);
            data[2] ^= ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 24);
            data[3] ^= ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 28);

            plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 16, data[0]);
            plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 20, data[1]);
            plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 24, data[2]);
            plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 28, data[3]);

            cryptCtr++;

            authTweak[6] = (int) (authCtr >>> 32);
            authTweak[7] = (int) authCtr;

            authCipher.setTweak(authTweak);
            authCipher.encryptBlock(data, 0, data, 0);

            auth[0] ^= data[0];
            auth[1] ^= data[1];
            auth[2] ^= data[2];
            auth[3] ^= data[3];

            authCtr++;

        }

        private void decryptLastBlock(MemorySegment plaintext) {
            if (position > 0) {
                authTweak[4] |= LAST;
                cryptTweak[0] |= LAST;

                cryptTweak[2] = (int) (cryptCtr >>> 32);
                cryptTweak[3] = (int) cryptCtr;

                cryptCipher.setTweak1(cryptTweak);
                cryptCipher.encryptBlock(savednonce, 0, authTweak, 0);

                authTweak[0] ^= buffer.get(BIG_ENDIAN_32_BIT, 0);
                authTweak[1] ^= buffer.get(BIG_ENDIAN_32_BIT, 4);
                authTweak[2] ^= buffer.get(BIG_ENDIAN_32_BIT, 8);
                authTweak[3] ^= buffer.get(BIG_ENDIAN_32_BIT, 12);

                cryptCtr++;

                if (position > 16) {
                    plaintext.set(BIG_ENDIAN_32_BIT, 0, authTweak[0]);
                    plaintext.set(BIG_ENDIAN_32_BIT, 4, authTweak[1]);
                    plaintext.set(BIG_ENDIAN_32_BIT, 8, authTweak[2]);
                    plaintext.set(BIG_ENDIAN_32_BIT, 12, authTweak[3]);

                    cryptTweak[2] = (int) (cryptCtr >>> 32);
                    cryptTweak[3] = (int) cryptCtr;

                    cryptCipher.setTweak1(cryptTweak);
                    cryptCipher.encryptBlock(savednonce, 0, data, 0);

                    data[0] ^= buffer.get(BIG_ENDIAN_32_BIT, 16);
                    data[1] ^= buffer.get(BIG_ENDIAN_32_BIT, 20);
                    data[2] ^= buffer.get(BIG_ENDIAN_32_BIT, 24);
                    data[3] ^= buffer.get(BIG_ENDIAN_32_BIT, 28);

                    buffer.set(BIG_ENDIAN_32_BIT, 16, data[0]);
                    buffer.set(BIG_ENDIAN_32_BIT, 20, data[1]);
                    buffer.set(BIG_ENDIAN_32_BIT, 24, data[2]);
                    buffer.set(BIG_ENDIAN_32_BIT, 28, data[3]);

                    MemorySegment.copy(buffer, 16, plaintext, 0, position - 16);

                    ozpad(buffer, position);

                    data[0] = buffer.get(BIG_ENDIAN_32_BIT, 16);
                    data[1] = buffer.get(BIG_ENDIAN_32_BIT, 20);
                    data[2] = buffer.get(BIG_ENDIAN_32_BIT, 24);
                    data[3] = buffer.get(BIG_ENDIAN_32_BIT, 28);
                } else {
                    buffer.set(BIG_ENDIAN_32_BIT, 0, authTweak[0]);
                    buffer.set(BIG_ENDIAN_32_BIT, 4, authTweak[1]);
                    buffer.set(BIG_ENDIAN_32_BIT, 8, authTweak[2]);
                    buffer.set(BIG_ENDIAN_32_BIT, 12, authTweak[3]);

                    MemorySegment.copy(buffer, 0, plaintext, 0, position);

                    ozpad(buffer, position);

                    authTweak[0] = buffer.get(BIG_ENDIAN_32_BIT, 0);
                    authTweak[1] = buffer.get(BIG_ENDIAN_32_BIT, 4);
                    authTweak[2] = buffer.get(BIG_ENDIAN_32_BIT, 8);
                    authTweak[3] = buffer.get(BIG_ENDIAN_32_BIT, 12);

                    data[0] = 0;
                    data[1] = 0;
                    data[2] = 0;
                    data[3] = 0;

                }

                authTweak[6] = (int) (authCtr >>> 32);
                authTweak[7] = (int) authCtr;

                authCipher.setTweak(authTweak);
                authCipher.encryptBlock(data, 0, data, 0);

                auth[0] ^= data[0];
                auth[1] ^= data[1];
                auth[2] ^= data[2];
                auth[3] ^= data[3];
            }
        }

        public long decrypt(MemorySegment ciphertext, MemorySegment plaintext) {
            if (!tagSet) {
                throw new IllegalStateException("Tag must be received before decrypting!");
            }
            if (ingestingAAD) {
                ingestLastBlock();
                position = 0;
                ingestingAAD = false;
            }
            long pOffset = 0, length = ciphertext.byteSize(), cOffset = 0;
            if (position > 0) {
                int take = (int) Math.min(length, 32 - position);
                MemorySegment.copy(ciphertext, cOffset, buffer, position, take);
                cOffset += take;
                length -= take;
                position += take;
                if (position == 32) {
                    decryptOneBlock(buffer, 0, plaintext, pOffset);
                    pOffset += 32;
                    position = 0;
                }
            }
            while (length >= 32) {
                decryptOneBlock(ciphertext, cOffset, plaintext, pOffset);
                cOffset += 32;
                length -= 32;
                pOffset += 32;
            }
            if (length > 0) {
                MemorySegment.copy(ciphertext, cOffset, buffer, 0, length);
                position = (int) length;
            }
            return cOffset;
        }

        public int finish(MemorySegment plaintext) {
            if (ingestingAAD) {
                ingestLastBlock();
                position = 0;
                ingestingAAD = false;
            }
            decryptLastBlock(plaintext);
            return position;
        }

        public boolean verify() {
            authCipher.setTweak0(savednonce);
            authTweak[0] = TAG;
            authTweak[1] = 0;
            authTweak[2] = 0;
            authTweak[3] = 0;
            authCipher.setTweak1(authTweak);

            authCipher.encryptBlock(auth, 0, auth, 0);

            return ((savedtag[0] ^ auth[0]) | (savedtag[1] ^ auth[1]) | (savedtag[2] ^ auth[2]) | (savedtag[3] ^ auth[3])) == 0;

        }

    }

}
