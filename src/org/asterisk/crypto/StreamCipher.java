/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Interface.java to edit this template
 */
package org.asterisk.crypto;

import java.lang.foreign.MemorySegment;

/**
 *
 * @author Sayantan Chakraborty
 */
public interface StreamCipher extends Cipher {

    @Override
    default DecryptEngine startDecryption(byte[] key, byte[] iv) {
        var enc = startEncryption(key, iv);
        return new DecryptEngine() {
            @Override
            public long decrypt(MemorySegment ciphertext, MemorySegment plaintext) {
                return enc.encrypt(plaintext, ciphertext);
            }

            @Override
            public int finish(MemorySegment plaintext) {
                return enc.finish(plaintext);
            }

            @Override
            public Cipher getAlgorithm() {
                return enc.getAlgorithm();
            }
        };
    }

}
