/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Interface.java to edit this template
 */
package org.asterisk.crypto.interfaces;

import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import javax.crypto.AEADBadTagException;

/**
 *
 * @author Sayantan Chakraborty
 */
public interface AuthenticatedCipher extends SimpleAead {

    @Override
    default long encrypt(byte[] key, byte[] iv, MemorySegment aad, MemorySegment plaintext, MemorySegment ciphertext, byte[] tag, int tOffset, int tLength) {
        var encrypter = startEncryption(key, iv);
        encrypter.ingestAAD(aad);
        var offset = encrypter.encrypt(plaintext, ciphertext);
        offset += encrypter.finish(ciphertext.asSlice(offset));
        encrypter.authenticate(tag, tOffset, tLength);
        return offset;
    }

    @Override
    default long decrypt(byte[] key, byte[] iv, MemorySegment aad, MemorySegment ciphertext, MemorySegment plaintext, byte[] tag, int tOffset, int tLength) throws AEADBadTagException {
        var decrypter = startDecryption(key, iv);
        decrypter.ingestAAD(aad);
        var offset = decrypter.decrypt(ciphertext, plaintext);
        offset += decrypter.finish(plaintext.asSlice(offset));
        if (!decrypter.verify(tag, tOffset, tLength)) {
            plaintext.asSlice(0, offset).fill((byte) 0);
            throw new AEADBadTagException();
        }
        return offset;
    }

    EncryptEngine startEncryption(byte[] key, byte[] iv);

    DecryptEngine startDecryption(byte[] key, byte[] iv);

    /**
     * The normal control flow is (ingestAAD)* (encrypt)* finish authenticate
     * <p>
     * Some implementations might permit a more relaxed control flow, but they
     * must not use a more restricted version
     */
    static interface EncryptEngine {

        void ingestAAD(MemorySegment aad);

        default void ingestAAD(byte[] aad, int offset, int length) {
            ingestAAD(MemorySegment.ofArray(aad).asSlice(offset, length));
        }

        default void ingestAAD(byte[] aad) {
            ingestAAD(aad, 0, aad.length);
        }

        default void ingestAAD(ByteBuffer aad) {
            ingestAAD(MemorySegment.ofBuffer(aad));
        }

        long encrypt(MemorySegment plaintext, MemorySegment ciphertext);

        default int encrypt(byte[] plaintext, int pOffset, int length, byte[] ciphertext, int cOffset) {
            return (int) encrypt(MemorySegment.ofArray(plaintext).asSlice(pOffset, length), MemorySegment.ofArray(ciphertext).asSlice(cOffset));
        }

        default int encrypt(byte[] plaintext, byte[] ciphertext) {
            return encrypt(plaintext, 0, plaintext.length, ciphertext, 0);
        }

        default int encrypt(MemorySegment plaintext, byte[] ciphertext, int cOffset) {
            return (int) encrypt(plaintext, MemorySegment.ofArray(ciphertext).asSlice(cOffset));
        }

        default int encrypt(byte[] plaintext, int pOffset, int length, MemorySegment ciphertext) {
            return (int) encrypt(MemorySegment.ofArray(plaintext).asSlice(pOffset, length), ciphertext);
        }

        int finish(MemorySegment ciphertext);

        default int finish(byte[] ciphertext, int cOffset) {
            return finish(MemorySegment.ofArray(ciphertext).asSlice(cOffset));
        }

        default int finish(byte[] ciphertext) {
            return finish(ciphertext, 0);
        }

        void authenticate(byte[] tag, int offset, int length);

        default void authenticate(byte[] tag) {
            authenticate(tag, 0, Math.min(tag.length, getAlgorithm().tagLength()));
        }

        AuthenticatedCipher getAlgorithm();

    }

    /**
     * /**
     * The normal control flow is (ingestAAD)* (decrypt)* finish verify
     * <p>
     * if verify fails, the user MUST NOT release the plaintext and preferably
     * zeroize the memory to avoid leaks
     * <p>
     * Some implementations might permit a more relaxed control flow, but they
     * must not use a more restricted version
     */
    static interface DecryptEngine {

        void ingestAAD(MemorySegment aad);

        default void ingestAAD(byte[] aad, int offset, int length) {
            ingestAAD(MemorySegment.ofArray(aad).asSlice(offset, length));
        }

        default void ingestAAD(byte[] aad) {
            ingestAAD(aad, 0, aad.length);
        }

        default void ingestAAD(ByteBuffer aad) {
            ingestAAD(MemorySegment.ofBuffer(aad));
        }

        long decrypt(MemorySegment ciphertext, MemorySegment plaintext);

        default int decrypt(byte[] ciphertext, int cOffset, int length, byte[] plaintext, int pOffset) {
            return (int) decrypt(MemorySegment.ofArray(ciphertext).asSlice(cOffset, length), MemorySegment.ofArray(plaintext).asSlice(pOffset));
        }

        default int decrypt(byte[] ciphertext, byte[] plaintext) {
            return decrypt(ciphertext, 0, ciphertext.length, plaintext, 0);
        }

        default int decrypt(MemorySegment ciphertext, byte[] plaintext, int pOffset) {
            return (int) decrypt(ciphertext, MemorySegment.ofArray(plaintext).asSlice(pOffset));
        }

        default int decrypt(byte[] ciphertext, int cOffset, int length, MemorySegment plaintext) {
            return (int) decrypt(MemorySegment.ofArray(ciphertext).asSlice(cOffset, length), plaintext);
        }

        int finish(MemorySegment plaintext);

        default int finish(byte[] plaintext, int pOffset) {
            return finish(MemorySegment.ofArray(plaintext).asSlice(pOffset));
        }

        default int finish(byte[] plaintext) {
            return finish(plaintext, 0);
        }

        boolean verify(byte[] tag, int offset, int length);

        default boolean verify(byte[] tag) {
            return verify(tag, 0, Math.min(tag.length, getAlgorithm().tagLength()));
        }

        AuthenticatedCipher getAlgorithm();

    }

}
