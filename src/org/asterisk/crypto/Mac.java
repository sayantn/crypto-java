/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Interface.java to edit this template
 */
package org.asterisk.crypto;

import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import org.asterisk.crypto.helper.Tools;

/**
 *
 * @author Sayantan Chakraborty
 */
public interface Mac {

    Engine start(byte[] key);

    int tagLength();

    int keyLength();

    static interface Engine {

        void ingest(MemorySegment input);

        default void ingest(byte[] input, int offset, int length) {
            ingest(MemorySegment.ofArray(input).asSlice(offset, length));
        }

        default void ingest(byte[] input) {
            ingest(input, 0, input.length);
        }

        default void ingest(ByteBuffer buffer) {
            ingest(MemorySegment.ofBuffer(buffer));
        }

        void authenticateTo(byte[] tag, int offset, int length);

        default void authenticateTo(byte[] tag, int offset) {
            authenticateTo(tag, offset, Math.min(getAlgorithm().tagLength(), tag.length - offset));
        }

        default void authenticateTo(byte[] tag) {
            authenticateTo(tag, 0);
        }

        default byte[] authenticate(int length) {
            byte[] ret = new byte[length];
            authenticateTo(ret, 0, length);
            return ret;
        }

        default byte[] authenticate() {
            return authenticate(getAlgorithm().tagLength());
        }

        default boolean verify(byte[] tag, int offset, int length) {
            var buffer = new byte[length];
            authenticateTo(buffer, 0, length);
            return Tools.equals(buffer, 0, tag, offset, length);
        }

        default boolean verify(byte[] tag, int offset) {
            return verify(tag, offset, Math.min(getAlgorithm().tagLength(), tag.length - offset));
        }

        default boolean verify(byte[] tag) {
            return verify(tag, 0);
        }

        Mac getAlgorithm();

    }

}
