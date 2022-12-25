/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.helper;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Objects;

import static java.nio.ByteOrder.BIG_ENDIAN;
import static java.nio.ByteOrder.LITTLE_ENDIAN;

/**
 *
 * @author Sayantan Chakraborty
 */
public class Tools {

    public static final ValueLayout.OfInt BIG_ENDIAN_32_BIT = ValueLayout.JAVA_INT.withBitAlignment(8).withOrder(BIG_ENDIAN);

    public static final ValueLayout.OfInt LITTLE_ENDIAN_32_BIT = ValueLayout.JAVA_INT.withBitAlignment(8).withOrder(LITTLE_ENDIAN);

    public static final ValueLayout.OfLong BIG_ENDIAN_64_BIT = ValueLayout.JAVA_LONG.withBitAlignment(8).withOrder(BIG_ENDIAN);

    public static final ValueLayout.OfLong LITTLE_ENDIAN_64_BIT = ValueLayout.JAVA_LONG.withBitAlignment(8).withOrder(LITTLE_ENDIAN);

    public static boolean equals(byte[] arr1, int off1, byte[] arr2, int off2, int len) {
        Objects.checkFromIndexSize(off1, len, arr1.length);
        Objects.checkFromIndexSize(off2, len, arr2.length);
        int result = 0;
        for (int i = 0; i < len; i++) {
            result |= arr1[off1 + i] ^ arr2[off2 + i];
        }
        return result == 0;
    }

    public static int load32BE(byte[] src, int offset) {
        return (src[offset + 0]) << 24
                | (src[offset + 1] & 0xff) << 16
                | (src[offset + 2] & 0xff) << 8
                | (src[offset + 3] & 0xff);
    }

    public static void store32BE(int src, byte[] dest, int dstOffset) {
        dest[dstOffset++] = (byte) (src >>> 24);
        dest[dstOffset++] = (byte) (src >>> 16);
        dest[dstOffset++] = (byte) (src >>> 8);
        dest[dstOffset] = (byte) src;
    }

    public static long load64BE(byte[] src, int offset) {
        return (src[offset + 0] & 0xffL) << 56
                | (src[offset + 1] & 0xffL) << 48
                | (src[offset + 2] & 0xffL) << 40
                | (src[offset + 3] & 0xffL) << 32
                | (src[offset + 4] & 0xffL) << 24
                | (src[offset + 5] & 0xffL) << 16
                | (src[offset + 6] & 0xffL) << 8
                | (src[offset + 7] & 0xffL);
    }

    public static void store64BE(long src, byte[] dest, int dstOffset) {
        dest[dstOffset++] = (byte) (src >>> 56);
        dest[dstOffset++] = (byte) (src >>> 48);
        dest[dstOffset++] = (byte) (src >>> 40);
        dest[dstOffset++] = (byte) (src >>> 32);
        dest[dstOffset++] = (byte) (src >>> 24);
        dest[dstOffset++] = (byte) (src >>> 16);
        dest[dstOffset++] = (byte) (src >>> 8);
        dest[dstOffset] = (byte) src;
    }

    public static int load32LE(byte[] src, int offset) {
        return (src[offset + 0] & 0xff)
                | (src[offset + 1] & 0xff) << 8
                | (src[offset + 2] & 0xff) << 16
                | (src[offset + 3] & 0xff) << 24;
    }

    public static void store32LE(int src, byte[] dest, int dstOffset) {
        dest[dstOffset++] = (byte) ((src) & 0xff);
        dest[dstOffset++] = (byte) ((src >>> 8) & 0xff);
        dest[dstOffset++] = (byte) ((src >>> 16) & 0xff);
        dest[dstOffset] = (byte) ((src >>> 24) & 0xff);
    }

    public static long load64LE(byte[] src, int offset) {
        return (src[offset + 0] & 0xffL)
                | (src[offset + 1] & 0xffL) << 8
                | (src[offset + 2] & 0xffL) << 16
                | (src[offset + 3] & 0xffL) << 24
                | (src[offset + 4] & 0xffL) << 32
                | (src[offset + 5] & 0xffL) << 40
                | (src[offset + 6] & 0xffL) << 48
                | (src[offset + 7] & 0xffL) << 56;
    }

    public static void store64LE(long src, byte[] dest, int dstOffset) {
        dest[dstOffset++] = (byte) ((src) & 0xffL);
        dest[dstOffset++] = (byte) ((src >>> 8) & 0xffL);
        dest[dstOffset++] = (byte) ((src >>> 16) & 0xffL);
        dest[dstOffset++] = (byte) ((src >>> 24) & 0xffL);
        dest[dstOffset++] = (byte) ((src >>> 32) & 0xffL);
        dest[dstOffset++] = (byte) ((src >>> 40) & 0xffL);
        dest[dstOffset++] = (byte) ((src >>> 48) & 0xffL);
        dest[dstOffset] = (byte) ((src >>> 56) & 0xffL);
    }

    public static byte rotateLeft8(byte b, int distance) {
        return (byte) ((b << distance) | ((b & 0xff) >>> (8 - distance)));
    }

    public static short rotateLeft16(short b, int distance) {
        return (short) ((b << distance) | ((b & 0xffff) >>> (16 - distance)));
    }

    public static void ozpad(MemorySegment buffer, long position) {
        buffer.set(ValueLayout.JAVA_BYTE, position, (byte) 0x80);
        buffer.asSlice(position + 1).fill((byte) 0);
    }

    public static void zeropad(MemorySegment buffer, long position) {
        buffer.asSlice(position).fill((byte) 0);
    }

    private Tools() {
    }

}
