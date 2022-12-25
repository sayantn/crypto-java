/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.interfaces;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.MemorySession;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 *
 * @author Sayantan Chakraborty
 */
public interface Digest {

    Engine start();

    int digestSize();
    
    int blockSize();

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

        default void ingest(Path file) throws IOException {
            ingest(file, 0, Long.MAX_VALUE);
        }

        /**
         * ingests the contents of the {@code Path} passed, starting in position
         * {@code offset} and reading at most {@code length} bytes
         *
         * @implSpec this implementation creates a {@link java.nio.file.StandardOpenOption#READ read}
         * {@link java.nio.channels.FileChannel FileChannel} and uses its
         * {@link java.nio.channels.FileChannel#map(java.nio.channels.FileChannel.MapMode, long, long, java.lang.foreign.MemorySession) map}
         * method to get a {@link java.lang.foreign.MemorySegment MemorySegment}
         * in {@link java.nio.channels.FileChannel.MapMode#READ_ONLY read only}
         * mode in the {@link java.lang.foreign.MemorySession#global() global}
         * session to ingest the file at one go
         *
         * @param file
         * @param offset
         * @param length the maximum number of bytes to read. Less may be read
         *               if the file doesn't have as many
         *
         * @return the number of bytes actually read
         *
         * @throws IOException               if any read operation throws
         * @throws IndexOutOfBoundsException if {@code offset<0} or
         *                                   {@code length>0} or
         *                                   {@code offset>size} where
         *                                   size is the size of the file in
         *                                   bytes
         */
        default long ingest(Path file, long offset, long length) throws IOException {
            try ( var channel = FileChannel.open(file, StandardOpenOption.READ)) {
                length = Math.min(length, channel.size() - offset);
                ingest(channel.map(MapMode.READ_ONLY, offset, length, MemorySession.global()));
            }
            return length;
        }

        void digestTo(byte[] dest, int offset);

        default void digestTo(byte[] dest) {
            digestTo(dest, 0);
        }

        default byte[] digest() {
            byte[] digest = new byte[getAlgorithm().digestSize()];
            digestTo(digest);
            return digest;
        }

        Digest getAlgorithm();

    }

}
