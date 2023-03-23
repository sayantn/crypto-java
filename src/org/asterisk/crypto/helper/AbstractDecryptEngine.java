/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.helper;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.SegmentScope;
import org.asterisk.crypto.interfaces.Cipher;

/**
 *
 * @author Sayantan Chakraborty
 */
public abstract class AbstractDecryptEngine implements Cipher.DecryptEngine {

    private final MemorySegment buffer;
    private int position = 0;

    private final int blockSize;

    public AbstractDecryptEngine(int blockSize) {
        buffer = MemorySegment.allocateNative(blockSize, SegmentScope.auto());
        this.blockSize = blockSize;
    }

    protected abstract void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset);

    protected abstract int decryptLastBlock(MemorySegment buffer, int length, MemorySegment plaintext);

    @Override
    public long decrypt(MemorySegment ciphertext, MemorySegment plaintext) {
        long cOffset = 0, length = ciphertext.byteSize(), pOffset = 0;
        if (position > 0) {
            int take = (int) Math.min(length, blockSize - position);
            MemorySegment.copy(ciphertext, cOffset, buffer, position, take);
            cOffset += take;
            length -= take;
            position += take;
            if (position == blockSize && length > 0) {
                decryptOneBlock(buffer, 0, plaintext, pOffset);
                pOffset += blockSize;
                position = 0;
            }
        }
        while (length > blockSize) {
            decryptOneBlock(ciphertext, cOffset, plaintext, pOffset);
            cOffset += blockSize;
            length -= blockSize;
            pOffset += blockSize;
        }
        if (length > 0) {
            MemorySegment.copy(ciphertext, cOffset, buffer, 0, length);
            position = (int) length;
        }
        return pOffset;
    }

    @Override
    public int finish(MemorySegment plaintext) {
        return decryptLastBlock(buffer, position, plaintext);
    }

}
