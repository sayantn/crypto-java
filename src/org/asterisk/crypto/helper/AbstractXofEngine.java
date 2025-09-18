/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.helper;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.Arena;
import java.util.Objects;
import org.asterisk.crypto.Xof;

/**
 *
 * @author Sayantan Chakraborty
 */
public abstract class AbstractXofEngine implements Xof.Engine {

    private final MemorySegment buffer;
    private int position = 0;
    private final byte[] digestBuffer;

    private final int blockSize, digestSize;

    public AbstractXofEngine(int blockSize, int digestSize) {
        buffer = Arena.ofAuto().allocate(blockSize);
        this.blockSize = blockSize;
        this.digestBuffer = new byte[digestSize];
        this.digestSize = digestSize;
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
    public final void startDigesting() {
        ingestLastBlock(buffer, position);
        position = 0;
    }

    @Override
    public void continueDigesting(byte[] dest, int offset, int length) {
        Objects.checkFromIndexSize(offset, length, dest.length);
        if (position > 0) {
            int give = Math.min(digestSize - position, length);
            System.arraycopy(digestBuffer, position, dest, offset, give);
            position += give;
            offset += give;
            length -= give;
            if (position == digestSize) {
                position = 0;
            }
        }
        while (length >= digestSize) {
            digestOneBlock(dest, offset);
            offset += digestSize;
            length -= digestSize;
        }
        if (length > 0) {
            digestOneBlock(digestBuffer, 0);
            System.arraycopy(digestBuffer, 0, dest, offset, length);
            position = length;
        }
    }

}
