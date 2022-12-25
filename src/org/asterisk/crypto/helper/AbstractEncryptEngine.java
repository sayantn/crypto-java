/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.helper;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.MemorySession;
import org.asterisk.crypto.interfaces.Cipher;

/**
 *
 * @author Sayantan Chakraborty
 */
public abstract class AbstractEncryptEngine implements Cipher.EncryptEngine {

    private final MemorySegment buffer;
    private int position = 0;

    private final int blockSize;

    public AbstractEncryptEngine(int blockSize) {
        buffer = MemorySegment.allocateNative(blockSize, MemorySession.global());
        this.blockSize = blockSize;
    }

    protected abstract void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset);

    protected abstract int encryptLastBlock(MemorySegment input, int length, MemorySegment ciphertext);

    @Override
    public long encrypt(MemorySegment plaintext, MemorySegment ciphertext) {
        long pOffset = 0, length = plaintext.byteSize(), cOffset = 0;
        if (position > 0) {
            int take = (int) Math.min(length, blockSize - position);
            MemorySegment.copy(plaintext, pOffset, buffer, position, take);
            pOffset += take;
            length -= take;
            position += take;
            if (position == blockSize && length > 0) {
                encryptOneBlock(buffer, 0, ciphertext, cOffset);
                cOffset += blockSize;
                position = 0;
            }
        }
        while (length > blockSize) {
            encryptOneBlock(plaintext, pOffset, ciphertext, cOffset);
            pOffset += blockSize;
            length -= blockSize;
            cOffset += blockSize;
        }
        if (length > 0) {
            MemorySegment.copy(plaintext, pOffset, buffer, 0, length);
            position = (int) length;
        }
        return cOffset;
    }

    @Override
    public int finish(MemorySegment ciphertext) {
        return encryptLastBlock(buffer, position, ciphertext);
    }

}
