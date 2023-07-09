/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.stream;

import java.lang.foreign.MemorySegment;
import org.asterisk.crypto.helper.AbstractStreamEncrypter;
import org.asterisk.crypto.Cipher;
import org.asterisk.crypto.StreamCipher;

import static org.asterisk.crypto.helper.Tools.load32LE;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum XChaCha implements StreamCipher {

    XCHACHA20(10), XCHACHA6(3), XCHACHA12(6);

    private final int rounds;

    private XChaCha(int rounds) {
        this.rounds = rounds;
    }

    private int[] expand(byte[] key, byte[] iv) {
        if (key.length < 32) {
            throw new IllegalArgumentException("XChaCha requires a 32-byte key, provided " + key.length + " bytes");
        }
        if (iv.length < 24) {
            throw new IllegalArgumentException("XChaCha requires a 24-byte iv, provided " + iv.length + " bytes");
        }

        int[] state = {
            Salsa20.CONST_0, Salsa20.CONST_1, Salsa20.CONST_2, Salsa20.CONST_3,
            load32LE(key, 0), load32LE(key, 4), load32LE(key, 8), load32LE(key, 12),
            load32LE(key, 16), load32LE(key, 20), load32LE(key, 24), load32LE(key, 28),
            load32LE(iv, 0), load32LE(iv, 4), load32LE(iv, 8), load32LE(iv, 12)
        };

        ChaCha.chachaCore(state, state, rounds);

        return new int[]{
            Salsa20.CONST_0, Salsa20.CONST_1, Salsa20.CONST_2, Salsa20.CONST_3,
            state[0], state[1], state[2], state[3],
            state[12], state[13], state[14], state[15],
            0, 0, load32LE(iv, 16), load32LE(iv, 20)
        };

    }

    @Override
    public Cipher.EncryptEngine startEncryption(byte[] key, byte[] iv) {
        return new AbstractStreamEncrypter(64) {

            private final int[] state = expand(key, iv), buffer = new int[16];

            private long counter = 0;

            @Override
            protected void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
                state[12] = (int) counter;
                state[13] = (int) (counter >>> 32);
                ChaCha.keystreamOneBlock(state, buffer, rounds, plaintext, pOffset, ciphertext, cOffset);
                counter++;
            }

            @Override
            public Cipher getAlgorithm() {
                return XChaCha.this;
            }
        };
    }

    @Override
    public int keyLength() {
        return 32;
    }

    @Override
    public int ivLength() {
        return 24;
    }

}
