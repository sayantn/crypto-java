/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Interface.java to edit this template
 */
package org.asterisk.crypto.interfaces;

import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;

/**
 *
 * @author Sayantan Chakraborty
 */
public interface AuthenticatedCipher {

    EncryptEngine startEncryption(byte[] key, byte[] iv);

    DecryptEngine startDecryption(byte[] key, byte[] iv);

    int keyLength();

    int ivLength();

    int tagLength();

    long ciphertextSize(long plaintextSize);

    long plaintextSize(long ciphertextSize);

    default int encrypt(byte[] key, byte[] iv, byte[] plaintext, byte[] aad, byte[] ciphertext, byte[] tag) {
        var enc = startEncryption(key, iv);
        enc.ingestAAD(aad);
        var ret = enc.encrypt(plaintext, ciphertext);
        ret += enc.finish(ciphertext, ret);
        enc.authenticate(tag);
        return ret;
    }

    default int decrypt(byte[] key, byte[] iv, byte[] ciphertext, byte[] aad, byte[] plaintext, byte[] tag) throws AEADBadTagException {
        var dec = startDecryption(key, iv);
        dec.ingestAAD(aad);
        var ret = dec.decrypt(ciphertext, plaintext);
        ret += dec.finish(plaintext, ret);
        if (!dec.verify(tag)) {
            Arrays.fill(plaintext, 0, ret, (byte) 0);
            throw new AEADBadTagException();
        }
        return ret;
    }

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
