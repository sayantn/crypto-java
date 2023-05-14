/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.aead;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.SegmentScope;
import java.util.function.Function;
import javax.crypto.AEADBadTagException;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.interfaces.SimpleAead;
import org.asterisk.crypto.lowlevel.DeoxysTBC;

import static org.asterisk.crypto.helper.Tools.BIG_ENDIAN_32_BIT;
import static org.asterisk.crypto.helper.Tools.load32BE;
import static org.asterisk.crypto.helper.Tools.ozpad;

/**
 * the winner of the CAESAR competition for authenticated ciphers in use case 3
 * - defense in depth
 * <p>
 * the encryption is not streamable, though AAD can be ingested streamingly.
 * only one call to encrypt can be done.
 * <p>
 * the decryption is fully streamable, though one must supply the tag before
 * decrypting anything
 * <p>
 * Deoxys-II also has the limitation that its tags cannot be truncated at all.
 * If the tag is truncated, the cryptogram cannot be decrypted (this is not an
 * implementation error, this is fundamentally true)
 * <p>
 * Deoxys-II makes up for all of this is security. In the nonce-respecting
 * scenario, it is not bound to birthday-based attacks. In the nonce-misuse
 * scenario, it still retains 64bit security against authenticity and integrity,
 * and full security against key recovery.
 *
 * @author Sayantan Chakraborty
 */
public enum DeoxysII implements SimpleAead {

    DEOXYS_II_128(DeoxysTBC.DeoxysTBC_256::new) {
        @Override
        public int keyLength() {
            return 16;
        }
    }, DEOXYS_II_256(DeoxysTBC.DeoxysTBC_256_128::new) {
        @Override
        public int keyLength() {
            return 32;
        }
    };

    private static final int AAD_BLOCK = 0x20000000, LAST = 0x40000000, FINAL = 0x10000000, TAG = 0x80000000;

    private final Function<byte[], DeoxysTBC> constructor;

    private DeoxysII(Function<byte[], DeoxysTBC> constructor) {
        this.constructor = constructor;
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
            throw new IllegalArgumentException("Deoxys-II always exports a 16 byte tag");
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
        if (iv.length < 15) {
            throw new IllegalArgumentException(this + " requires an iv of 15 bytes, passed only " + iv.length + " bytes");
        }
        return new Encrypter(constructor.apply(key), iv);
    }

    public Decrypter startDecryption(byte[] key, byte[] iv) {
        if (key.length < keyLength()) {
            throw new IllegalArgumentException(this + " requires a key of " + keyLength() + " bytes, passed only " + key.length + " bytes");
        }
        if (iv.length < 15) {
            throw new IllegalArgumentException(this + " requires an iv of 15 bytes, passed only " + iv.length + " bytes");
        }
        return new Decrypter(constructor.apply(key), iv);
    }

    private enum State {
        INGESTING, FIRST_PASS, SECOND_PASS, CLOSED
    }

    public static class Encrypter {

        private final MemorySegment buffer = MemorySegment.allocateNative(16, SegmentScope.auto());
        private int position = 0;

        private final int[] auth = new int[4], tweak = new int[4], data = new int[4], savednonce, savedtag = new int[4];

        private final DeoxysTBC blockCipher;

        private long counter = 0;

        private State state = State.INGESTING;

        private Encrypter(DeoxysTBC blockCipher, byte[] iv) {
            this.blockCipher = blockCipher;
            savednonce = new int[]{
                load32BE(iv, 0) >>> 8,
                load32BE(iv, 3),
                load32BE(iv, 7),
                load32BE(iv, 11)
            };
            tweak[0] = AAD_BLOCK;
        }

        private void ingestOneBlock(MemorySegment aad, long offset) {
            tweak[2] = (int) (counter >>> 32);
            tweak[3] = (int) counter;

            data[0] = aad.get(BIG_ENDIAN_32_BIT, offset + 0);
            data[1] = aad.get(BIG_ENDIAN_32_BIT, offset + 4);
            data[2] = aad.get(BIG_ENDIAN_32_BIT, offset + 8);
            data[3] = aad.get(BIG_ENDIAN_32_BIT, offset + 12);

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
                ozpad(buffer, position);
                tweak[0] |= LAST;
                ingestOneBlock(buffer, 0);
                position = 0;
            }
            tweak[0] = 0;
            counter = 0;
        }

        public void ingestAAD(MemorySegment input) {
            if (state != State.INGESTING) {
                throw new IllegalStateException("Cannot ingest AAD after starting encrypting!");
            }
            long offset = 0, length = input.byteSize();
            if (position > 0) {
                int take = (int) Math.min(length, 16 - position);
                MemorySegment.copy(input, offset, buffer, position, take);
                offset += take;
                length -= take;
                position += take;
                if (position == 16) {
                    ingestOneBlock(buffer, 0);
                    position = 0;
                }
            }
            while (length >= 16) {
                ingestOneBlock(input, offset);
                offset += 16;
                length -= 16;
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
            tweak[2] = savedtag[2] ^ (int) (counter >>> 32);
            tweak[3] = savedtag[3] ^ (int) counter;

            blockCipher.setTweak(tweak);
            blockCipher.encryptBlock(savednonce, 0, data, 0);

            ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 0, plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 0) ^ data[0]);
            ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 4, plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 4) ^ data[1]);
            ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 8, plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 8) ^ data[2]);
            ciphertext.set(BIG_ENDIAN_32_BIT, cOffset + 12, plaintext.get(BIG_ENDIAN_32_BIT, pOffset + 12) ^ data[3]);

            counter++;
        }

        private void generateTag() {
            tweak[0] = FINAL | savednonce[0];
            tweak[1] = savednonce[1];
            tweak[2] = savednonce[2];
            tweak[3] = savednonce[3];

            blockCipher.setTweak(tweak);
            blockCipher.encryptBlock(auth, 0, savedtag, 0);

            tweak[0] = TAG | savedtag[0];
            tweak[1] = savedtag[1];

            counter = 0;
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
                int take = (int) Math.min(length, 16 - position);
                MemorySegment.copy(plaintext, offset, buffer, position, take);
                offset += take;
                length -= take;
                position += take;
                if (position == 16) {
                    ingestOneBlock(buffer, 0);
                    position = 0;
                }
            }

            while (length >= 16) {
                ingestOneBlock(plaintext, offset);

                offset += 16;
                length -= 16;
            }
            if (length > 0) {
                MemorySegment.copy(plaintext, offset, buffer, 0, length);
                position = (int) length;
            }
        }

        public void authenticate(byte[] tag, int offset) {
            if (tag.length - offset < 16) {
                throw new IllegalArgumentException("Deoxys-II always exports a 16 byte tag, but buffer provided has size " + (tag.length - offset));
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

        private final MemorySegment buffer = MemorySegment.allocateNative(16, SegmentScope.auto());
        private int position = 0;

        private final int[] auth = new int[4], tweak = new int[4], crypttweak = new int[4], data = new int[4], savednonce, savedtag = new int[4];

        private final DeoxysTBC blockCipher;

        private long counter = 0;

        private boolean ingestingAAD = true, tagSet = false;

        private Decrypter(DeoxysTBC blockCipher, byte[] iv) {
            this.blockCipher = blockCipher;
            savednonce = new int[]{
                load32BE(iv, 0) >>> 8,
                load32BE(iv, 3),
                load32BE(iv, 7),
                load32BE(iv, 11)
            };
            tweak[0] = AAD_BLOCK;
        }

        private void ingestOneBlock(MemorySegment aad, long offset) {
            tweak[2] = (int) (counter >>> 32);
            tweak[3] = (int) counter;

            data[0] = aad.get(BIG_ENDIAN_32_BIT, offset + 0);
            data[1] = aad.get(BIG_ENDIAN_32_BIT, offset + 4);
            data[2] = aad.get(BIG_ENDIAN_32_BIT, offset + 8);
            data[3] = aad.get(BIG_ENDIAN_32_BIT, offset + 12);

            blockCipher.setTweak(tweak);
            blockCipher.encryptBlock(data, 0, data, 0);

            auth[0] ^= data[0];
            auth[1] ^= data[1];
            auth[2] ^= data[2];
            auth[3] ^= data[3];

            counter++;

        }

        public void ingestAAD(MemorySegment input) {
            if (!ingestingAAD) {
                throw new IllegalStateException("Cannot ingest AAD after starting to encrypt!");
            }
            long offset = 0, length = input.byteSize();
            if (position > 0) {
                int take = (int) Math.min(length, 16 - position);
                MemorySegment.copy(input, offset, buffer, position, take);
                offset += take;
                length -= take;
                position += take;
                if (position == 16) {
                    ingestOneBlock(buffer, 0);
                    position = 0;
                }
            }
            while (length >= 16) {
                ingestOneBlock(input, offset);
                offset += 16;
                length -= 16;
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

        public void setTag(byte[] tag, int offset) {
            if (tagSet) {
                throw new IllegalStateException("Tag already set!");
            }
            if (tag.length - offset < 16) {
                throw new IllegalArgumentException("Deoxys-II requires a 16 byte tag, passed only " + (tag.length - offset) + " bytes");
            }
            savedtag[0] = load32BE(tag, offset + 0);
            savedtag[1] = load32BE(tag, offset + 4);
            savedtag[2] = load32BE(tag, offset + 8);
            savedtag[3] = load32BE(tag, offset + 12);

            crypttweak[0] = TAG | savedtag[0];
            crypttweak[1] = savedtag[1];

            tagSet = true;
        }

        private void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset) {
            crypttweak[2] = savedtag[2] ^ (int) (counter >>> 32);
            crypttweak[3] = savedtag[3] ^ (int) counter;

            blockCipher.setTweak(crypttweak);
            blockCipher.encryptBlock(savednonce, 0, data, 0);

            data[0] ^= ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 0);
            data[1] ^= ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 4);
            data[2] ^= ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 8);
            data[3] ^= ciphertext.get(BIG_ENDIAN_32_BIT, cOffset + 12);

            plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 0, data[0]);
            plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 4, data[1]);
            plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 8, data[2]);
            plaintext.set(BIG_ENDIAN_32_BIT, pOffset + 12, data[3]);

            tweak[2] = (int) (counter >>> 32);
            tweak[3] = (int) counter;

            blockCipher.setTweak(tweak);
            blockCipher.encryptBlock(data, 0, data, 0);

            auth[0] ^= data[0];
            auth[1] ^= data[1];
            auth[2] ^= data[2];
            auth[3] ^= data[3];

            counter++;

        }

        public long decrypt(MemorySegment ciphertext, MemorySegment plaintext) {
            if (ingestingAAD) {
                ingestLastBlock();
                position = 0;
                ingestingAAD = false;
            }
            if (!tagSet) {
                throw new IllegalStateException("Cannot encrypt before tag is received!");
            }
            long pOffset = 0, length = ciphertext.byteSize(), cOffset = 0;
            if (position > 0) {
                int take = (int) Math.min(length, 16 - position);
                MemorySegment.copy(ciphertext, cOffset, buffer, position, take);
                cOffset += take;
                length -= take;
                position += take;
                if (position == 16) {
                    decryptOneBlock(buffer, 0, plaintext, pOffset);
                    pOffset += 16;
                    position = 0;
                }
            }
            while (length >= 16) {
                decryptOneBlock(ciphertext, cOffset, plaintext, pOffset);
                cOffset += 16;
                length -= 16;
                pOffset += 16;
            }
            if (length > 0) {
                MemorySegment.copy(ciphertext, cOffset, buffer, 0, length);
                position = (int) length;
            }
            return cOffset;
        }

        private void ingestLastBlock() {
            if (position > 0) {
                ozpad(buffer, position);
                tweak[0] |= LAST;
                ingestOneBlock(buffer, 0);
            }
            tweak[0] = 0;
            counter = 0;
        }

        private void decryptLastBlock(MemorySegment plaintext) {
            if (position > 0) {
                crypttweak[2] = savedtag[2] ^ (int) (counter >>> 32);
                crypttweak[3] = savedtag[3] ^ (int) counter;

                blockCipher.setTweak(crypttweak);
                blockCipher.encryptBlock(savednonce, 0, data, 0);

                data[0] ^= buffer.get(BIG_ENDIAN_32_BIT, 0);
                data[1] ^= buffer.get(BIG_ENDIAN_32_BIT, 4);
                data[2] ^= buffer.get(BIG_ENDIAN_32_BIT, 8);
                data[3] ^= buffer.get(BIG_ENDIAN_32_BIT, 12);

                buffer.set(BIG_ENDIAN_32_BIT, 0, data[0]);
                buffer.set(BIG_ENDIAN_32_BIT, 4, data[1]);
                buffer.set(BIG_ENDIAN_32_BIT, 8, data[2]);
                buffer.set(BIG_ENDIAN_32_BIT, 12, data[3]);

                ozpad(buffer, position);
                tweak[0] |= LAST;
                ingestOneBlock(buffer, 0);

                MemorySegment.copy(buffer, 0, plaintext, 0, position);
            }

        }

        public int finish(MemorySegment plaintext) {
            if (ingestingAAD) {
                ingestLastBlock();
                position = 0;
                ingestingAAD = false;
            }
            decryptLastBlock(plaintext);

            savednonce[0] |= FINAL;
            blockCipher.setTweak(savednonce);
            blockCipher.encryptBlock(auth, 0, auth, 0);

            return position;
        }

        public boolean verify() {
            if (!tagSet) {
                throw new IllegalStateException("Tag not set!");
            }
            return ((auth[0] ^ savedtag[0]) | (auth[1] ^ savedtag[1]) | (auth[2] ^ savedtag[2]) | (auth[3] ^ savedtag[3])) == 0;
        }

    }

}
