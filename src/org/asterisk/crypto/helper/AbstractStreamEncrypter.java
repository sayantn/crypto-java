/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.helper;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.SegmentScope;
import org.asterisk.crypto.Cipher;

/**
 *
 * @author Sayantan Chakraborty
 */
public abstract class AbstractStreamEncrypter implements Cipher.EncryptEngine {

    private final MemorySegment buffer;
    private int position = 0;

    private final int blockSize;

    public AbstractStreamEncrypter(int blockSize) {
        buffer = MemorySegment.allocateNative(blockSize, SegmentScope.auto());
        this.blockSize = blockSize;
    }

    protected abstract void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset);

    @Override
    public long encrypt(MemorySegment plaintext, MemorySegment ciphertext) {
        long pOffset = 0, length = plaintext.byteSize(), cOffset = 0;
        if (position > 0) {
            int take = (int) Math.min(length, blockSize - position);
            MemorySegment.copy(plaintext, pOffset, buffer, position, take);
            pOffset += take;
            length -= take;
            position += take;
            if (position == blockSize) {
                encryptOneBlock(buffer, 0, ciphertext, cOffset);
                cOffset += blockSize;
                position = 0;
            }
        }
        while (length >= blockSize) {
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
        encryptOneBlock(buffer, 0, buffer, 0);
        MemorySegment.copy(buffer, 0, ciphertext, 0, position);
        return position;
    }

}
