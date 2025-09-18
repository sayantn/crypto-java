package org.asterisk.crypto.aead;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.Arena;
import java.lang.foreign.ValueLayout;
import java.util.Objects;
import javax.crypto.AEADBadTagException;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.SimpleAead;
import org.asterisk.crypto.lowlevel.AesDecApi;
import org.asterisk.crypto.lowlevel.AesEncApi;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static org.asterisk.crypto.helper.GfHelper.*;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum Colm0 implements SimpleAead {

    COLM_0;

    private static final ValueLayout.OfInt LAYOUT = Tools.BIG_ENDIAN_32_BIT;

    private static final int PARAM = 0x8000;

    public static void rho(int[] x, int[] st) {
        int st0 = st[0], st1 = st[1], st2 = st[2], st3 = st[3];

        st[0] = x[0] ^ ((st0 << 1) | (st1 >>> 31));
        st[1] = x[1] ^ ((st1 << 1) | (st2 >>> 31));
        st[2] = x[2] ^ ((st2 << 1) | (st3 >>> 31));
        st[3] = x[3] ^ ((st3 << 1) | ((st0 >> 31) & 0x87));

        x[0] = st[0] ^ st0;
        x[1] = st[1] ^ st1;
        x[2] = st[2] ^ st2;
        x[3] = st[3] ^ st3;

    }

    public static void rhoInv(int[] y, int[] st) {
        int st0 = st[0], st1 = st[1], st2 = st[2], st3 = st[3];

        st[0] ^= y[0];
        st[1] ^= y[1];
        st[2] ^= y[2];
        st[3] ^= y[3];

        y[0] = st[0] ^ ((st0 << 1) | (st1 >>> 31));
        y[1] = st[1] ^ ((st1 << 1) | (st2 >>> 31));
        y[2] = st[2] ^ ((st2 << 1) | (st3 >>> 31));
        y[3] = st[3] ^ ((st3 << 1) | ((st0 >> 31) & 0x87));

    }

    @Override
    public int keyLength() {
        return 16;
    }

    @Override
    public int ivLength() {
        return 8;
    }

    @Override
    public int tagLength() {
        return 16;
    }

    public long ciphertextSize(long plaintextSize) {
        return plaintextSize;
    }

    public Colm0EncryptEngine startEncryption(byte[] key, byte[] iv) {
        if (key.length < 16) {
            throw new IllegalArgumentException("Colm0 takes a 16 byte key, " + key.length + " bytes provided");
        }
        if (iv.length < 8) {
            throw new IllegalArgumentException("Colm0 takes a 8 byte iv, " + iv.length + " bytes provided");
        }
        return new Colm0EncryptEngine(key, iv);
    }

    public Colm0DecryptEngine startDecryption(byte[] key, byte[] iv) {
        if (key.length < 16) {
            throw new IllegalArgumentException("Colm0 takes a 16 byte key, " + key.length + " bytes provided");
        }
        if (iv.length < 8) {
            throw new IllegalArgumentException("Colm0 takes a 8 byte iv, " + iv.length + " bytes provided");
        }
        return new Colm0DecryptEngine(key, iv);
    }

    @Override
    public long encrypt(byte[] key, byte[] iv, MemorySegment aad, MemorySegment plaintext, MemorySegment ciphertext, byte[] tag, int tOffset, int tLength) {
        if (tLength != tagLength()) {
            throw new IllegalArgumentException("Colm must use a 16-byte tag");
        }
        var encrypter = startEncryption(key, iv);
        encrypter.ingestAAD(aad);
        long offset = encrypter.encrypt(plaintext, ciphertext);
        offset += encrypter.finish(ciphertext, tag, tOffset);
        return offset;
    }

    @Override
    public long decrypt(byte[] key, byte[] iv, MemorySegment aad, MemorySegment ciphertext, MemorySegment plaintext, byte[] tag, int tOffset, int tLength) throws AEADBadTagException {
        if (tLength != tagLength()) {
            throw new IllegalArgumentException("Colm must use a 16-byte tag");
        }
        var decrypter = startDecryption(key, iv);
        decrypter.ingestAAD(aad);
        long offset = decrypter.decrypt(ciphertext, plaintext);
        try {
            offset += decrypter.finish(ciphertext, tag, tOffset);
        } catch (AEADBadTagException ex) {
            plaintext.asSlice(0, ciphertext.byteSize()).fill((byte) 0);
            throw ex;
        }
        return offset;
    }

    /**
     * The normal control flow is (ingestAAD)* (encrypt)* finish
     * <p>
     * The main difference to EncryptEngine is that it must release the tag in
     * finish(), and the tag cannot be truncated
     */
    public static class Colm0EncryptEngine {

        private final int[] deltaA = new int[4], deltaM = new int[4], deltaC = new int[4];

        private final int[] checksum = new int[4], xorBlocks = new int[4];

        private final int[] data = new int[4];

        private final AesEncApi.Aes128EncApi aes;

        private final MemorySegment buffer = Arena.ofAuto().allocate(16);
        private int position = 0;

        private boolean ingestingAAD = true;

        private Colm0EncryptEngine(byte[] key, byte[] iv) {
            aes = new AesEncApi.Aes128EncApi(key);

            aes.encryptBlock(data, 0, deltaM, 0);

            x3(deltaM, deltaA);
            x3(deltaA, deltaC);

            data[0] = Tools.load32BE(iv, 0) ^ deltaA[0];
            data[1] = Tools.load32BE(iv, 4) ^ deltaA[1];
            data[2] = PARAM ^ deltaA[2];
            data[3] = deltaA[3];

            aes.encryptBlock(data, 0, checksum, 0);

        }

        private void ingestOneBlock(MemorySegment aad, long offset) {
            x2(deltaA);

            data[0] = aad.get(LAYOUT, offset + 0) ^ deltaA[0];
            data[1] = aad.get(LAYOUT, offset + 4) ^ deltaA[1];
            data[2] = aad.get(LAYOUT, offset + 8) ^ deltaA[2];
            data[3] = aad.get(LAYOUT, offset + 12) ^ deltaA[3];

            aes.encryptBlock(data, 0, data, 0);

            checksum[0] ^= data[0];
            checksum[1] ^= data[1];
            checksum[2] ^= data[2];
            checksum[3] ^= data[3];

        }

        private void ingestLastBlock() {
            if (position > 0) {
                x7(deltaA);

                Tools.ozpad(buffer, position);

                data[0] = buffer.get(LAYOUT, 0) ^ deltaA[0];
                data[1] = buffer.get(LAYOUT, 4) ^ deltaA[1];
                data[2] = buffer.get(LAYOUT, 8) ^ deltaA[2];
                data[3] = buffer.get(LAYOUT, 12) ^ deltaA[3];

                aes.encryptBlock(data, 0, data, 0);

                checksum[0] ^= data[0];
                checksum[1] ^= data[1];
                checksum[2] ^= data[2];
                checksum[3] ^= data[3];
            }
        }

        private void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
            data[0] = plaintext.get(LAYOUT, pOffset + 0);
            data[1] = plaintext.get(LAYOUT, pOffset + 4);
            data[2] = plaintext.get(LAYOUT, pOffset + 8);
            data[3] = plaintext.get(LAYOUT, pOffset + 12);

            xorBlocks[0] ^= data[0];
            xorBlocks[1] ^= data[1];
            xorBlocks[2] ^= data[2];
            xorBlocks[3] ^= data[3];

            x2(deltaM);

            data[0] ^= deltaM[0];
            data[1] ^= deltaM[1];
            data[2] ^= deltaM[2];
            data[3] ^= deltaM[3];

            aes.encryptBlock(data, 0, data, 0);

            rho(data, checksum);

            aes.encryptBlock(data, 0, data, 0);

            x2(deltaC);

            ciphertext.set(LAYOUT, cOffset + 0, data[0] ^ deltaC[0]);
            ciphertext.set(LAYOUT, cOffset + 4, data[1] ^ deltaC[1]);
            ciphertext.set(LAYOUT, cOffset + 8, data[2] ^ deltaC[2]);
            ciphertext.set(LAYOUT, cOffset + 12, data[3] ^ deltaC[3]);

        }

        private void encryptLastBlock(MemorySegment ciphertext, byte[] tag, int tOffset) {
            x7(deltaM);
            x7(deltaC);

            if (position < 16) {
                x7(deltaM);
                x7(deltaC);

                Tools.ozpad(buffer, position);
            }

            xorBlocks[0] ^= buffer.get(LAYOUT, 0);
            xorBlocks[1] ^= buffer.get(LAYOUT, 4);
            xorBlocks[2] ^= buffer.get(LAYOUT, 8);
            xorBlocks[3] ^= buffer.get(LAYOUT, 12);

            data[0] = xorBlocks[0] ^ deltaM[0];
            data[1] = xorBlocks[1] ^ deltaM[1];
            data[2] = xorBlocks[2] ^ deltaM[2];
            data[3] = xorBlocks[3] ^ deltaM[3];

            aes.encryptBlock(data, 0, data, 0);

            rho(data, checksum);

            aes.encryptBlock(data, 0, data, 0);

            buffer.set(LAYOUT, 0, data[0] ^ deltaC[0]);
            buffer.set(LAYOUT, 4, data[1] ^ deltaC[1]);
            buffer.set(LAYOUT, 8, data[2] ^ deltaC[2]);
            buffer.set(LAYOUT, 12, data[3] ^ deltaC[3]);

            MemorySegment.copy(buffer, 0, ciphertext, 0, position);
            MemorySegment.copy(buffer, JAVA_BYTE, position, tag, tOffset, 16 - position);

            if (position > 0) {

                x2(deltaM);

                data[0] = xorBlocks[0] ^ deltaM[0];
                data[1] = xorBlocks[1] ^ deltaM[1];
                data[2] = xorBlocks[2] ^ deltaM[2];
                data[3] = xorBlocks[3] ^ deltaM[3];

                aes.encryptBlock(data, 0, data, 0);

                rho(data, checksum);

                aes.encryptBlock(data, 0, data, 0);

                x2(deltaC);

                buffer.set(LAYOUT, 0, data[0] ^ deltaC[0]);
                buffer.set(LAYOUT, 4, data[1] ^ deltaC[1]);
                buffer.set(LAYOUT, 8, data[2] ^ deltaC[2]);
                buffer.set(LAYOUT, 12, data[3] ^ deltaC[3]);

                MemorySegment.copy(buffer, JAVA_BYTE, 0, tag, tOffset + 16 - position, position);

            }

        }

        public void ingestAAD(MemorySegment input) {
            if (!ingestingAAD) {
                throw new IllegalStateException("Cannot ingest aad after starting to encrypt!");
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
            ingestAAD(aad, 0, aad.length);
        }

        public long encrypt(MemorySegment plaintext, MemorySegment ciphertext) {
            if (ingestingAAD) {
                ingestLastBlock();
                position = 0;
                ingestingAAD = false;
            }
            long pOffset = 0, length = plaintext.byteSize(), cOffset = 0;
            if (position > 0) {
                int take = (int) Math.min(length, 16 - position);
                MemorySegment.copy(plaintext, pOffset, buffer, position, take);
                pOffset += take;
                length -= take;
                position += take;
                if (position == 16 && length > 0) {
                    encryptOneBlock(buffer, 0, ciphertext, cOffset);
                    cOffset += 16;
                    position = 0;
                }
            }
            while (length > 16) {
                encryptOneBlock(plaintext, pOffset, ciphertext, cOffset);
                pOffset += 16;
                length -= 16;
                cOffset += 16;
            }
            if (length > 0) {
                MemorySegment.copy(plaintext, pOffset, buffer, 0, length);
                position = (int) length;
            }
            return cOffset;
        }

        public int encrypt(byte[] plaintext, int pOffset, int length, byte[] ciphertext, int cOffset) {
            return (int) encrypt(MemorySegment.ofArray(plaintext).asSlice(pOffset, length), MemorySegment.ofArray(ciphertext).asSlice(cOffset));
        }

        public int encrypt(byte[] plaintext, byte[] ciphertext) {
            return encrypt(plaintext, 0, plaintext.length, ciphertext, 0);
        }

        public int finish(MemorySegment ciphertext, byte[] tag, int tOffset) {
            Objects.checkFromIndexSize(tOffset, 16, tag.length);

            if (ingestingAAD) {
                ingestLastBlock();
                position = 0;
                ingestingAAD = false;
            }
            encryptLastBlock(ciphertext, tag, tOffset);
            return position;
        }

        public int finish(byte[] ciphertext, int cOffset, byte[] tag, int tOffset) {
            return finish(MemorySegment.ofArray(tag).asSlice(cOffset), tag, tOffset);
        }

        public int finish(byte[] ciphertext, byte[] tag) {
            return finish(ciphertext, 0, tag, 0);
        }

    }

    public static final class Colm0DecryptEngine {

        private final int[] deltaA = new int[4], deltaM = new int[4], deltaC = new int[4];

        private final int[] checksum = new int[4], xorBlocks = new int[4];

        private final int[] data = new int[4];

        private final AesEncApi.Aes128EncApi aes;
        private final AesDecApi.Aes128DecApi aesDec;

        private final MemorySegment buffer = Arena.ofAuto().allocate(16);
        private int position = 0;

        private boolean ingestingAAD = true;

        private Colm0DecryptEngine(byte[] key, byte[] iv) {
            aes = new AesEncApi.Aes128EncApi(key);
            aesDec = aes.decrypter();

            aes.encryptBlock(data, 0, deltaM, 0);

            x3(deltaM, deltaA);
            x3(deltaA, deltaC);

            data[0] = Tools.load32BE(iv, 0) ^ deltaA[0];
            data[1] = Tools.load32BE(iv, 4) ^ deltaA[1];
            data[2] = PARAM ^ deltaA[2];
            data[3] = deltaA[3];

            aes.encryptBlock(data, 0, checksum, 0);

        }

        private void ingestOneBlock(MemorySegment aad, long offset) {
            x2(deltaA);

            data[0] = aad.get(LAYOUT, offset + 0) ^ deltaA[0];
            data[1] = aad.get(LAYOUT, offset + 4) ^ deltaA[1];
            data[2] = aad.get(LAYOUT, offset + 8) ^ deltaA[2];
            data[3] = aad.get(LAYOUT, offset + 12) ^ deltaA[3];

            aes.encryptBlock(data, 0, data, 0);

            checksum[0] ^= data[0];
            checksum[1] ^= data[1];
            checksum[2] ^= data[2];
            checksum[3] ^= data[3];

        }

        private void ingestLastBlock() {
            if (position > 0) {
                x7(deltaA);

                Tools.ozpad(buffer, position);

                data[0] = buffer.get(LAYOUT, 0) ^ deltaA[0];
                data[1] = buffer.get(LAYOUT, 4) ^ deltaA[1];
                data[2] = buffer.get(LAYOUT, 8) ^ deltaA[2];
                data[3] = buffer.get(LAYOUT, 12) ^ deltaA[3];

                aes.encryptBlock(data, 0, data, 0);

                checksum[0] ^= data[0];
                checksum[1] ^= data[1];
                checksum[2] ^= data[2];
                checksum[3] ^= data[3];
            }
        }

        private void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset) {
            x2(deltaC);

            data[0] = ciphertext.get(LAYOUT, cOffset + 0) ^ deltaC[0];
            data[1] = ciphertext.get(LAYOUT, cOffset + 4) ^ deltaC[1];
            data[2] = ciphertext.get(LAYOUT, cOffset + 8) ^ deltaC[2];
            data[3] = ciphertext.get(LAYOUT, cOffset + 12) ^ deltaC[3];

            aesDec.decryptBlock(data, 0, data, 0);

            rhoInv(data, checksum);

            aesDec.decryptBlock(data, 0, data, 0);

            x2(deltaM);

            data[0] ^= deltaM[0];
            data[1] ^= deltaM[1];
            data[2] ^= deltaM[2];
            data[3] ^= deltaM[3];

            xorBlocks[0] ^= data[0];
            xorBlocks[1] ^= data[1];
            xorBlocks[2] ^= data[2];
            xorBlocks[3] ^= data[3];

            plaintext.set(LAYOUT, pOffset + 0, data[0]);
            plaintext.set(LAYOUT, pOffset + 4, data[1]);
            plaintext.set(LAYOUT, pOffset + 8, data[2]);
            plaintext.set(LAYOUT, pOffset + 12, data[3]);

        }

        private void decryptLastBlock(MemorySegment plaintext, byte[] tag, int tOffset) throws AEADBadTagException {
            x7(deltaM);
            x7(deltaC);

            if (position < 16) {
                x7(deltaM);
                x7(deltaC);
            }

            MemorySegment.copy(tag, tOffset, buffer, JAVA_BYTE, position, 16 - position);

            data[0] = buffer.get(LAYOUT, 0) ^ deltaC[0];
            data[1] = buffer.get(LAYOUT, 4) ^ deltaC[1];
            data[2] = buffer.get(LAYOUT, 8) ^ deltaC[2];
            data[3] = buffer.get(LAYOUT, 12) ^ deltaC[3];

            aesDec.decryptBlock(data, 0, data, 0);

            rhoInv(data, checksum);

            aesDec.decryptBlock(data, 0, data, 0);

            data[0] ^= deltaM[0];
            data[1] ^= deltaM[1];
            data[2] ^= deltaM[2];
            data[3] ^= deltaM[3];

            xorBlocks[0] ^= data[0];
            xorBlocks[1] ^= data[1];
            xorBlocks[2] ^= data[2];
            xorBlocks[3] ^= data[3];

            //now, data has M[l](and M[l+1]) and xorBlocks has M*[l]
            buffer.set(LAYOUT, 0, xorBlocks[0]);
            buffer.set(LAYOUT, 4, xorBlocks[1]);
            buffer.set(LAYOUT, 8, xorBlocks[2]);
            buffer.set(LAYOUT, 12, xorBlocks[3]);

            if (position < 16) {
                int result = buffer.get(JAVA_BYTE, position) ^ (byte) 0x80;
                for (int i = position + 1; i < 16; i++) {
                    result |= buffer.get(JAVA_BYTE, i);
                }
                if (result != 0) {
                    throw new AEADBadTagException();
                }
            }

            MemorySegment.copy(buffer, 0, plaintext, 0, position);

            if (position > 0) {
                x2(deltaM);

                data[0] ^= deltaM[0];
                data[1] ^= deltaM[1];
                data[2] ^= deltaM[2];
                data[3] ^= deltaM[3];

                aes.encryptBlock(data, 0, data, 0);

                rho(data, checksum);

                aes.encryptBlock(data, 0, data, 0);

                x2(deltaC);

                buffer.set(LAYOUT, 0, data[0] ^ deltaC[0]);
                buffer.set(LAYOUT, 4, data[1] ^ deltaC[1]);
                buffer.set(LAYOUT, 8, data[2] ^ deltaC[2]);
                buffer.set(LAYOUT, 12, data[3] ^ deltaC[3]);

                int result = 0;
                for (int i = 0, j = 16 - position; i < position; i++, j++) {
                    result |= buffer.get(JAVA_BYTE, i) ^ tag[tOffset + j];
                }

                if (result != 0) {
                    throw new AEADBadTagException();
                }

            }

        }

        public void ingestAAD(MemorySegment input) {
            if (!ingestingAAD) {
                throw new IllegalStateException("Cannot ingest aad after starting to encrypt!");
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
            ingestAAD(aad, 0, aad.length);
        }

        public long decrypt(MemorySegment ciphertext, MemorySegment plaintext) {
            if (ingestingAAD) {
                ingestLastBlock();
                position = 0;
                ingestingAAD = false;
            }
            long pOffset = 0, length = ciphertext.byteSize(), cOffset = 0;
            if (position > 0) {
                int take = (int) Math.min(length, 16 - position);
                MemorySegment.copy(ciphertext, cOffset, buffer, position, take);
                cOffset += take;
                length -= take;
                position += take;
                if (position == 16 && length > 0) {
                    decryptOneBlock(buffer, 0, plaintext, pOffset);
                    pOffset += 16;
                    position = 0;
                }
            }
            while (length > 16) {
                decryptOneBlock(ciphertext, cOffset, plaintext, pOffset);
                pOffset += 16;
                length -= 16;
                cOffset += 16;
            }
            if (length > 0) {
                MemorySegment.copy(ciphertext, cOffset, buffer, 0, length);
                position = (int) length;
            }
            return pOffset;
        }

        public int decrypt(byte[] ciphertext, int cOffset, int length, byte[] plaintext, int pOffset) {
            return (int) decrypt(MemorySegment.ofArray(ciphertext).asSlice(cOffset, length), MemorySegment.ofArray(plaintext).asSlice(pOffset));
        }

        public int decrypt(byte[] ciphertext, byte[] plaintext) {
            return decrypt(ciphertext, 0, ciphertext.length, plaintext, 0);
        }

        public int finish(MemorySegment plaintext, byte[] tag, int tOffset) throws AEADBadTagException {
            Objects.checkFromIndexSize(tOffset, 16, tag.length);

            if (ingestingAAD) {
                ingestLastBlock();
                position = 0;
                ingestingAAD = false;
            }
            decryptLastBlock(plaintext, tag, tOffset);
            return position;
        }

        public int finish(byte[] plaintext, int cOffset, byte[] tag, int tOffset) throws AEADBadTagException {
            return finish(MemorySegment.ofArray(plaintext).asSlice(cOffset), tag, tOffset);
        }

        public int finish(byte[] plaintext, byte[] tag) throws AEADBadTagException {
            return finish(plaintext, 0, tag, 0);
        }

    }

}
