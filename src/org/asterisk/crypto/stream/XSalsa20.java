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
import static org.asterisk.crypto.stream.Salsa20.keystreamOneBlock;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum XSalsa20 implements StreamCipher {

    XSALSA20(10), XSALSA20_12(6), XSALSA20_8(4);

    private final int rounds;

    private XSalsa20(int rounds) {
        this.rounds = rounds;
    }

    private int[] expand(byte[] key, byte[] iv) {
        if (key.length < 32) {
            throw new IllegalArgumentException("XSalsa20 requires a 32-byte key, provided " + key.length + " bytes");
        }
        if (iv.length < 24) {
            throw new IllegalArgumentException("XSalsa20 requires a 24-byte iv, provided " + iv.length + " bytes");
        }

        int[] state = {
            Salsa20.CONST_0, load32LE(key, 0), load32LE(key, 4), load32LE(key, 8),
            load32LE(key, 12), Salsa20.CONST_1, load32LE(iv, 0), load32LE(iv, 4),
            load32LE(iv, 8), load32LE(iv, 12), Salsa20.CONST_2, load32LE(key, 16),
            load32LE(key, 20), load32LE(key, 24), load32LE(key, 28), Salsa20.CONST_3
        };

        Salsa20.salsa20Core(state, state, rounds);

        return new int[]{
            Salsa20.CONST_0, state[0], state[5], state[10],
            state[15], Salsa20.CONST_1, load32LE(iv, 16), load32LE(iv, 20),
            0, 0, Salsa20.CONST_2, state[6],
            state[7], state[8], state[9], Salsa20.CONST_3
        };

    }

    @Override
    public EncryptEngine startEncryption(byte[] key, byte[] iv) {
        return new AbstractStreamEncrypter(64) {

            private final int[] state = expand(key, iv), buffer = new int[16];

            private long counter = 0;

            @Override
            protected void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
                keystreamOneBlock(state, buffer, counter++, rounds, plaintext, pOffset, ciphertext, cOffset);
            }

            @Override
            public Cipher getAlgorithm() {
                return XSalsa20.this;
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
