/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Interface.java to edit this template
 */
package org.asterisk.crypto.interfaces;

import java.lang.foreign.MemorySegment;

/**
 *
 * @author Sayantan Chakraborty
 */
public interface Cipher {

    EncryptEngine startEncryption(byte[] key, byte[] iv);

    DecryptEngine startDecryption(byte[] key, byte[] iv);

    int keyLength();

    int ivLength();

    long ciphertextSize(long plaintextSize);

    long plaintextSize(long ciphertextSize);

    default int encrypt(byte[] key, byte[] iv, byte[] plaintext, byte[] ciphertext) {
        var enc = startEncryption(key, iv);
        var ret = enc.encrypt(plaintext, ciphertext);
        ret += enc.finish(ciphertext, ret);
        return ret;
    }

    default int decrypt(byte[] key, byte[] iv, byte[] ciphertext, byte[] plaintext) {
        var dec = startDecryption(key, iv);
        var ret = dec.decrypt(ciphertext, plaintext);
        ret += dec.finish(plaintext, ret);
        return ret;
    }

    static interface EncryptEngine {

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

        Cipher getAlgorithm();

    }

    static interface DecryptEngine {

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

        Cipher getAlgorithm();

    }

}
