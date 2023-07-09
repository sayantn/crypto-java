/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.helper;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.SegmentScope;
import java.util.Objects;
import org.asterisk.crypto.Mac;

/**
 *
 * @author Sayantan Chakraborty
 */
public abstract class AbstractMacEngine implements Mac.Engine {

    private final MemorySegment buffer;
    private int position = 0;

    private final int blockSize;

    public AbstractMacEngine(int blockSize) {
        buffer = MemorySegment.allocateNative(blockSize, SegmentScope.auto());
        this.blockSize = blockSize;
    }

    protected abstract void ingestOneBlock(MemorySegment input, long offset);

    protected abstract void ingestLastBlock(MemorySegment input, int length);

    protected abstract void getTag(byte[] buffer, int offset);

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
    public void authenticateTo(byte[] tag, int offset, int length) {
        int tagLength = getAlgorithm().tagLength();
        if (tagLength < length) {
            throw new IllegalArgumentException(getAlgorithm() + " can produce tags of up to " + tagLength + " bytes, " + length + " bytes requested");
        }
        Objects.checkFromIndexSize(offset, length, tag.length);
        ingestLastBlock(buffer, position);
        if (tagLength > length) {
            byte[] dest = new byte[tagLength];
            getTag(dest, 0);
            System.arraycopy(dest, 0, tag, offset, length);
        } else {
            getTag(tag, offset);
        }
    }

    protected void setBufferPosition(int position) {
        this.position = Objects.checkFromIndexSize(position, 0, blockSize);
    }

}
