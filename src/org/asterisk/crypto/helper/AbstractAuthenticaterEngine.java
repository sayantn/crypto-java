/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.helper;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.SegmentScope;
import java.util.Objects;
import org.asterisk.crypto.interfaces.AuthenticatedCipher;

/**
 *
 * @author Sayantan Chakraborty
 */
public abstract class AbstractAuthenticaterEngine implements AuthenticatedCipher.EncryptEngine {

    private final MemorySegment buffer;
    private int position = 0;

    private final int msgBlockSize, aadBlockSize;

    private boolean ingestingAAD = true;

    public AbstractAuthenticaterEngine(int blockSize) {
        buffer = MemorySegment.allocateNative(blockSize, SegmentScope.auto());
        this.msgBlockSize = blockSize;
        this.aadBlockSize = blockSize;
    }

    public AbstractAuthenticaterEngine(int msgBlockSize, int aadBlockSize) {
        buffer = MemorySegment.allocateNative(Math.max(msgBlockSize, aadBlockSize), SegmentScope.auto());
        this.msgBlockSize = msgBlockSize;
        this.aadBlockSize = aadBlockSize;
    }

    protected abstract void ingestOneBlock(MemorySegment aad, long offset);

    protected abstract void ingestLastBlock(MemorySegment aad, int length);

    protected abstract void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset);

    protected abstract int encryptLastBlock(MemorySegment buffer, int length, MemorySegment ciphertext);

    protected abstract void finalizeState();

    protected abstract void generateTag(byte[] dest);

    @Override
    public final void ingestAAD(MemorySegment input) {
        if (!ingestingAAD) {
            throw new IllegalStateException("Cannot ingest aad after starting to encrypt!");
        }
        long offset = 0, length = input.byteSize();
        if (position > 0) {
            int take = (int) Math.min(length, aadBlockSize - position);
            MemorySegment.copy(input, offset, buffer, position, take);
            offset += take;
            length -= take;
            position += take;
            if (position == aadBlockSize && length > 0) {
                ingestOneBlock(buffer, 0);
                position = 0;
            }
        }
        while (length > aadBlockSize) {
            ingestOneBlock(input, offset);
            offset += aadBlockSize;
            length -= aadBlockSize;
        }
        if (length > 0) {
            MemorySegment.copy(input, offset, buffer, 0, length);
            position = (int) length;
        }
    }

    @Override
    public long encrypt(MemorySegment plaintext, MemorySegment ciphertext) {
        if (ingestingAAD) {
            ingestLastBlock(buffer, position);
            position = 0;
            ingestingAAD = false;
        }
        long pOffset = 0, length = plaintext.byteSize(), cOffset = 0;
        if (position > 0) {
            int take = (int) Math.min(length, msgBlockSize - position);
            MemorySegment.copy(plaintext, pOffset, buffer, position, take);
            pOffset += take;
            length -= take;
            position += take;
            if (position == msgBlockSize && length > 0) {
                encryptOneBlock(buffer, 0, ciphertext, cOffset);
                cOffset += msgBlockSize;
                position = 0;
            }
        }
        while (length > msgBlockSize) {
            encryptOneBlock(plaintext, pOffset, ciphertext, cOffset);
            pOffset += msgBlockSize;
            length -= msgBlockSize;
            cOffset += msgBlockSize;
        }
        if (length > 0) {
            MemorySegment.copy(plaintext, pOffset, buffer, 0, length);
            position = (int) length;
        }
        return cOffset;
    }

    @Override
    public int finish(MemorySegment ciphertext) {
        if (ingestingAAD) {
            ingestLastBlock(buffer, position);
            position = 0;
            ingestingAAD = false;
        }
        var ret = encryptLastBlock(buffer, position, ciphertext);
        position = 0;
        finalizeState();
        return ret;
    }

    @Override
    public void authenticate(byte[] tag, int offset, int length) {
        Objects.checkFromIndexSize(offset, length, tag.length);
        int maxTagLen = getAlgorithm().tagLength();
        if (length > maxTagLen) {
            throw new IllegalArgumentException(this + " can only generate tags upto " + maxTagLen + " bytes, requested " + length + " bytes");
        }
        byte[] temp = new byte[maxTagLen];
        generateTag(temp);
        System.arraycopy(temp, 0, tag, offset, length);
    }

    protected void enableAad(boolean enable) {
        ingestingAAD = enable;
    }

}
