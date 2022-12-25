/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.helper;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.MemorySession;
import java.util.Objects;
import org.asterisk.crypto.interfaces.Digest;

/**
 *
 * @author Sayantan Chakraborty
 */
public abstract class AbstractDigestEngine implements Digest.Engine {

    private final MemorySegment buffer;
    private int position = 0;

    private final int blockSize;

    public AbstractDigestEngine(int blockSize) {
        buffer = MemorySegment.allocateNative(blockSize, MemorySession.global());
        this.blockSize = blockSize;
    }

    protected abstract void ingestOneBlock(MemorySegment input, long offset);

    protected abstract void ingestLastBlock(MemorySegment input, int length);

    protected abstract void digestOneBlock(byte[] dest, int offset);

    @Override
    public final void ingest(MemorySegment input) {
        long offset = 0, length = input.byteSize();
        if (position > 0) {
            int take = (int) Math.min(length, blockSize - position);
            MemorySegment.copy(input, offset, buffer, position, take);
            offset += take;
            length -= take;
            position += take;
            if (position == blockSize && length > 0) {
                ingestOneBlock(buffer, 0);
                position = 0;
            }
        }
        while (length > blockSize) {
            ingestOneBlock(input, offset);
            offset += blockSize;
            length -= blockSize;
        }
        if (length > 0) {
            MemorySegment.copy(input, offset, buffer, 0, length);
            position = (int) length;
        }
    }

    @Override
    public final void digestTo(byte[] dest, int offset) {
        Objects.checkFromIndexSize(offset, getAlgorithm().digestSize(), dest.length);
        ingestLastBlock(buffer, position);
        digestOneBlock(dest, offset);
    }
    
    protected void setBufferPosition(int position) {
        this.position = Objects.checkFromIndexSize(position, 0, blockSize);
    }

}
