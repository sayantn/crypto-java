/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.helper;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.MemorySession;
import org.asterisk.crypto.interfaces.AuthenticatedCipher;

/**
 *
 * @author Sayantan Chakraborty
 */
public abstract class AbstractVerifierEngine implements AuthenticatedCipher.DecryptEngine {

    private final MemorySegment buffer;
    private int position = 0;

    private final int msgBlockSize, aadBlockSize;

    private boolean ingestingAAD = true;

    public AbstractVerifierEngine(int blockSize) {
        buffer = MemorySegment.allocateNative(blockSize, MemorySession.global());
        this.msgBlockSize = blockSize;
        this.aadBlockSize = blockSize;
    }

    public AbstractVerifierEngine(int msgBlockSize, int aadBlockSize) {
        buffer = MemorySegment.allocateNative(Math.max(msgBlockSize, aadBlockSize), MemorySession.global());
        this.msgBlockSize = msgBlockSize;
        this.aadBlockSize = aadBlockSize;
    }

    protected abstract void ingestOneBlock(MemorySegment aad, long offset);

    protected abstract void ingestLastBlock(MemorySegment aad, int length);

    protected abstract void decryptOneBlock(MemorySegment ciphertext, long cOffset, MemorySegment plaintext, long pOffset);

    protected abstract int decryptLastBlock(MemorySegment input, int length, MemorySegment plaintext);

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
    public long decrypt(MemorySegment ciphertext, MemorySegment plaintext) {
        if (ingestingAAD) {
            ingestLastBlock(buffer, position);
            position = 0;
            ingestingAAD = false;
        }
        long pOffset = 0, length = ciphertext.byteSize(), cOffset = 0;
        if (position > 0) {
            int take = (int) Math.min(length, msgBlockSize - position);
            MemorySegment.copy(ciphertext, cOffset, buffer, position, take);
            cOffset += take;
            length -= take;
            position += take;
            if (position == msgBlockSize && length > 0) {
                decryptOneBlock(buffer, 0, plaintext, pOffset);
                pOffset += msgBlockSize;
                position = 0;
            }
        }
        while (length > msgBlockSize) {
            decryptOneBlock(ciphertext, cOffset, plaintext, pOffset);
            cOffset += msgBlockSize;
            length -= msgBlockSize;
            pOffset += msgBlockSize;
        }
        if (length > 0) {
            MemorySegment.copy(ciphertext, cOffset, buffer, 0, length);
            position = (int) length;
        }
        return cOffset;
    }

    @Override
    public int finish(MemorySegment plaintext) {
        if (ingestingAAD) {
            ingestLastBlock(buffer, position);
            position = 0;
            ingestingAAD = false;
        }
        var ret = decryptLastBlock(buffer, position, plaintext);
        position = 0;
        finalizeState();
        return ret;
    }

    @Override
    public boolean verify(byte[] tag, int offset, int length) {
        byte[] temp = new byte[getAlgorithm().tagLength()];
        generateTag(temp);
        return Tools.equals(temp, 0, tag, offset, length);
    }

    protected void enableAad(boolean enable) {
        ingestingAAD = enable;
    }

}
