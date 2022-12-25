/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.lowlevel;

import org.asterisk.crypto.helper.Tools;

import static org.asterisk.crypto.lowlevel.AesPermutation.aesRound;
import static org.asterisk.crypto.lowlevel.AesPermutation.invAesRound;
import static org.asterisk.crypto.lowlevel.AesPermutation.invMixColumns;
import static org.asterisk.crypto.lowlevel.AesPermutation.mixColumns;

/**
 *
 * @author Sayantan Chakraborty
 */
public sealed abstract class DeoxysTBC {

    private static final int[] LFSR2 = {
        0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
        0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e,
        0x41, 0x43, 0x45, 0x47, 0x49, 0x4b, 0x4d, 0x4f, 0x51, 0x53, 0x55, 0x57, 0x59, 0x5b, 0x5d, 0x5f,
        0x61, 0x63, 0x65, 0x67, 0x69, 0x6b, 0x6d, 0x6f, 0x71, 0x73, 0x75, 0x77, 0x79, 0x7b, 0x7d, 0x7f,
        0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
        0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
        0xc1, 0xc3, 0xc5, 0xc7, 0xc9, 0xcb, 0xcd, 0xcf, 0xd1, 0xd3, 0xd5, 0xd7, 0xd9, 0xdb, 0xdd, 0xdf,
        0xe1, 0xe3, 0xe5, 0xe7, 0xe9, 0xeb, 0xed, 0xef, 0xf1, 0xf3, 0xf5, 0xf7, 0xf9, 0xfb, 0xfd, 0xff,
        0x01, 0x03, 0x05, 0x07, 0x09, 0x0b, 0x0d, 0x0f, 0x11, 0x13, 0x15, 0x17, 0x19, 0x1b, 0x1d, 0x1f,
        0x21, 0x23, 0x25, 0x27, 0x29, 0x2b, 0x2d, 0x2f, 0x31, 0x33, 0x35, 0x37, 0x39, 0x3b, 0x3d, 0x3f,
        0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
        0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,
        0x81, 0x83, 0x85, 0x87, 0x89, 0x8b, 0x8d, 0x8f, 0x91, 0x93, 0x95, 0x97, 0x99, 0x9b, 0x9d, 0x9f,
        0xa1, 0xa3, 0xa5, 0xa7, 0xa9, 0xab, 0xad, 0xaf, 0xb1, 0xb3, 0xb5, 0xb7, 0xb9, 0xbb, 0xbd, 0xbf,
        0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde,
        0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee, 0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe
    };

    private static final int[] LFSR3 = {
        0x00, 0x80, 0x01, 0x81, 0x02, 0x82, 0x03, 0x83, 0x04, 0x84, 0x05, 0x85, 0x06, 0x86, 0x07, 0x87,
        0x08, 0x88, 0x09, 0x89, 0x0a, 0x8a, 0x0b, 0x8b, 0x0c, 0x8c, 0x0d, 0x8d, 0x0e, 0x8e, 0x0f, 0x8f,
        0x10, 0x90, 0x11, 0x91, 0x12, 0x92, 0x13, 0x93, 0x14, 0x94, 0x15, 0x95, 0x16, 0x96, 0x17, 0x97,
        0x18, 0x98, 0x19, 0x99, 0x1a, 0x9a, 0x1b, 0x9b, 0x1c, 0x9c, 0x1d, 0x9d, 0x1e, 0x9e, 0x1f, 0x9f,
        0xa0, 0x20, 0xa1, 0x21, 0xa2, 0x22, 0xa3, 0x23, 0xa4, 0x24, 0xa5, 0x25, 0xa6, 0x26, 0xa7, 0x27,
        0xa8, 0x28, 0xa9, 0x29, 0xaa, 0x2a, 0xab, 0x2b, 0xac, 0x2c, 0xad, 0x2d, 0xae, 0x2e, 0xaf, 0x2f,
        0xb0, 0x30, 0xb1, 0x31, 0xb2, 0x32, 0xb3, 0x33, 0xb4, 0x34, 0xb5, 0x35, 0xb6, 0x36, 0xb7, 0x37,
        0xb8, 0x38, 0xb9, 0x39, 0xba, 0x3a, 0xbb, 0x3b, 0xbc, 0x3c, 0xbd, 0x3d, 0xbe, 0x3e, 0xbf, 0x3f,
        0x40, 0xc0, 0x41, 0xc1, 0x42, 0xc2, 0x43, 0xc3, 0x44, 0xc4, 0x45, 0xc5, 0x46, 0xc6, 0x47, 0xc7,
        0x48, 0xc8, 0x49, 0xc9, 0x4a, 0xca, 0x4b, 0xcb, 0x4c, 0xcc, 0x4d, 0xcd, 0x4e, 0xce, 0x4f, 0xcf,
        0x50, 0xd0, 0x51, 0xd1, 0x52, 0xd2, 0x53, 0xd3, 0x54, 0xd4, 0x55, 0xd5, 0x56, 0xd6, 0x57, 0xd7,
        0x58, 0xd8, 0x59, 0xd9, 0x5a, 0xda, 0x5b, 0xdb, 0x5c, 0xdc, 0x5d, 0xdd, 0x5e, 0xde, 0x5f, 0xdf,
        0xe0, 0x60, 0xe1, 0x61, 0xe2, 0x62, 0xe3, 0x63, 0xe4, 0x64, 0xe5, 0x65, 0xe6, 0x66, 0xe7, 0x67,
        0xe8, 0x68, 0xe9, 0x69, 0xea, 0x6a, 0xeb, 0x6b, 0xec, 0x6c, 0xed, 0x6d, 0xee, 0x6e, 0xef, 0x6f,
        0xf0, 0x70, 0xf1, 0x71, 0xf2, 0x72, 0xf3, 0x73, 0xf4, 0x74, 0xf5, 0x75, 0xf6, 0x76, 0xf7, 0x77,
        0xf8, 0x78, 0xf9, 0x79, 0xfa, 0x7a, 0xfb, 0x7b, 0xfc, 0x7c, 0xfd, 0x7d, 0xfe, 0x7e, 0xff, 0x7f
    };

    private static final int[] RCON32 = {
        0x2f2f2f2f, 0x5e5e5e5e, 0xbcbcbcbc, 0x63636363, 0xc6c6c6c6, 0x97979797, 0x35353535, 0x6a6a6a6a, 0xd4d4d4d4,
        0xb3b3b3b3, 0x7d7d7d7d, 0xfafafafa, 0xefefefef, 0xc5c5c5c5, 0x91919191, 0x39393939, 0x72727272
    };

    private static final int RCON_ROW = 0x01020408;

    public abstract void encryptBlock(int[] plaintext, int pOffset, int[] ciphertext, int cOffset);

    public abstract void decryptBlock(int[] ciphertext, int cOffset, int[] plaintext, int pOffset);

    public abstract void setTweak(int[] tweak);

    public static final class DeoxysTBC_256 extends DeoxysTBC {

        private final int[] tweakeys = new int[120], data = new int[8];

        public DeoxysTBC_256(DeoxysTBC_256 other) {
            System.arraycopy(other.tweakeys, 0, tweakeys, 0, tweakeys.length);
        }

        public DeoxysTBC_256(byte[] key) {
            tweakeys[0] = Tools.load32BE(key, 0);
            tweakeys[1] = Tools.load32BE(key, 4);
            tweakeys[2] = Tools.load32BE(key, 8);
            tweakeys[3] = Tools.load32BE(key, 12);

            for (int offset = 8; offset < 120; offset += 8) {
                tweakeys[offset + 0] = ((tweakeys[offset - 7] & 0xff) << 24)
                        | ((tweakeys[offset - 8] & 0xff000000) >>> 8)
                        | ((tweakeys[offset - 5] & 0xff0000) >>> 8)
                        | ((tweakeys[offset - 6] & 0xff00) >>> 8);
                tweakeys[offset + 1] = ((tweakeys[offset - 6] & 0xff) << 24)
                        | ((tweakeys[offset - 7] & 0xff000000) >>> 8)
                        | ((tweakeys[offset - 8] & 0xff0000) >>> 8)
                        | ((tweakeys[offset - 5] & 0xff00) >>> 8);
                tweakeys[offset + 2] = ((tweakeys[offset - 5] & 0xff) << 24)
                        | ((tweakeys[offset - 6] & 0xff000000) >>> 8)
                        | ((tweakeys[offset - 7] & 0xff0000) >>> 8)
                        | ((tweakeys[offset - 8] & 0xff00) >>> 8);
                tweakeys[offset + 3] = ((tweakeys[offset - 8] & 0xff) << 24)
                        | ((tweakeys[offset - 5] & 0xff000000) >>> 8)
                        | ((tweakeys[offset - 6] & 0xff0000) >>> 8)
                        | ((tweakeys[offset - 7] & 0xff00) >>> 8);
            }
        }

        @Override
        public void setTweak(int[] tweak) {
            System.arraycopy(tweak, 0, tweakeys, 4, 4);

            for (int offset = 8; offset < 120; offset += 8) {
                tweakeys[offset + 4] = (LFSR2[(tweakeys[offset - 3] & 0xff)] << 24)
                        | (LFSR2[(tweakeys[offset - 4] & 0xff000000) >>> 24] << 16)
                        | (LFSR2[(tweakeys[offset - 1] & 0xff0000) >>> 16] << 8)
                        | (LFSR2[(tweakeys[offset - 2] & 0xff00) >>> 8]);
                tweakeys[offset + 5] = (LFSR2[(tweakeys[offset - 2] & 0xff)] << 24)
                        | (LFSR2[(tweakeys[offset - 3] & 0xff000000) >>> 24] << 16)
                        | (LFSR2[(tweakeys[offset - 4] & 0xff0000) >>> 16] << 8)
                        | (LFSR2[(tweakeys[offset - 1] & 0xff00) >>> 8]);
                tweakeys[offset + 6] = (LFSR2[(tweakeys[offset - 1] & 0xff)] << 24)
                        | (LFSR2[(tweakeys[offset - 2] & 0xff000000) >>> 24] << 16)
                        | (LFSR2[(tweakeys[offset - 3] & 0xff0000) >>> 16] << 8)
                        | (LFSR2[(tweakeys[offset - 4] & 0xff00) >>> 8]);
                tweakeys[offset + 7] = (LFSR2[(tweakeys[offset - 4] & 0xff)] << 24)
                        | (LFSR2[(tweakeys[offset - 1] & 0xff000000) >>> 24] << 16)
                        | (LFSR2[(tweakeys[offset - 2] & 0xff0000) >>> 16] << 8)
                        | (LFSR2[(tweakeys[offset - 3] & 0xff00) >>> 8]);
            }
        }

        @Override
        public void encryptBlock(int[] src, int srcOffset, int[] dest, int dstOffset) {
            data[0] = src[srcOffset + 0] ^ tweakeys[0] ^ tweakeys[4] ^ RCON_ROW;
            data[1] = src[srcOffset + 1] ^ tweakeys[1] ^ tweakeys[5] ^ RCON32[0];
            data[2] = src[srcOffset + 2] ^ tweakeys[2] ^ tweakeys[6];
            data[3] = src[srcOffset + 3] ^ tweakeys[3] ^ tweakeys[7];

            aesRound(data, 0, data, 4,
                    tweakeys[8] ^ tweakeys[12] ^ RCON_ROW,
                    tweakeys[9] ^ tweakeys[13] ^ RCON32[1],
                    tweakeys[10] ^ tweakeys[14],
                    tweakeys[11] ^ tweakeys[15]);
            aesRound(data, 4, data, 0,
                    tweakeys[16] ^ tweakeys[20] ^ RCON_ROW,
                    tweakeys[17] ^ tweakeys[21] ^ RCON32[2],
                    tweakeys[18] ^ tweakeys[22],
                    tweakeys[19] ^ tweakeys[23]);
            aesRound(data, 0, data, 4,
                    tweakeys[24] ^ tweakeys[28] ^ RCON_ROW,
                    tweakeys[25] ^ tweakeys[29] ^ RCON32[3],
                    tweakeys[26] ^ tweakeys[30],
                    tweakeys[27] ^ tweakeys[31]);
            aesRound(data, 4, data, 0,
                    tweakeys[32] ^ tweakeys[36] ^ RCON_ROW,
                    tweakeys[33] ^ tweakeys[37] ^ RCON32[4],
                    tweakeys[34] ^ tweakeys[38],
                    tweakeys[35] ^ tweakeys[39]);
            aesRound(data, 0, data, 4,
                    tweakeys[40] ^ tweakeys[44] ^ RCON_ROW,
                    tweakeys[41] ^ tweakeys[45] ^ RCON32[5],
                    tweakeys[42] ^ tweakeys[46],
                    tweakeys[43] ^ tweakeys[47]);
            aesRound(data, 4, data, 0,
                    tweakeys[48] ^ tweakeys[52] ^ RCON_ROW,
                    tweakeys[49] ^ tweakeys[53] ^ RCON32[6],
                    tweakeys[50] ^ tweakeys[54],
                    tweakeys[51] ^ tweakeys[55]);
            aesRound(data, 0, data, 4,
                    tweakeys[56] ^ tweakeys[60] ^ RCON_ROW,
                    tweakeys[57] ^ tweakeys[61] ^ RCON32[7],
                    tweakeys[58] ^ tweakeys[62],
                    tweakeys[59] ^ tweakeys[63]);
            aesRound(data, 4, data, 0,
                    tweakeys[64] ^ tweakeys[68] ^ RCON_ROW,
                    tweakeys[65] ^ tweakeys[69] ^ RCON32[8],
                    tweakeys[66] ^ tweakeys[70],
                    tweakeys[67] ^ tweakeys[71]);
            aesRound(data, 0, data, 4,
                    tweakeys[72] ^ tweakeys[76] ^ RCON_ROW,
                    tweakeys[73] ^ tweakeys[77] ^ RCON32[9],
                    tweakeys[74] ^ tweakeys[78],
                    tweakeys[75] ^ tweakeys[79]);
            aesRound(data, 4, data, 0,
                    tweakeys[80] ^ tweakeys[84] ^ RCON_ROW,
                    tweakeys[81] ^ tweakeys[85] ^ RCON32[10],
                    tweakeys[82] ^ tweakeys[86],
                    tweakeys[83] ^ tweakeys[87]);
            aesRound(data, 0, data, 4,
                    tweakeys[88] ^ tweakeys[92] ^ RCON_ROW,
                    tweakeys[89] ^ tweakeys[93] ^ RCON32[11],
                    tweakeys[90] ^ tweakeys[94],
                    tweakeys[91] ^ tweakeys[95]);
            aesRound(data, 4, data, 0,
                    tweakeys[96] ^ tweakeys[100] ^ RCON_ROW,
                    tweakeys[97] ^ tweakeys[101] ^ RCON32[12],
                    tweakeys[98] ^ tweakeys[102],
                    tweakeys[99] ^ tweakeys[103]);
            aesRound(data, 0, data, 4,
                    tweakeys[104] ^ tweakeys[108] ^ RCON_ROW,
                    tweakeys[105] ^ tweakeys[109] ^ RCON32[13],
                    tweakeys[106] ^ tweakeys[110],
                    tweakeys[107] ^ tweakeys[111]);
            aesRound(data, 4, dest, dstOffset,
                    tweakeys[112] ^ tweakeys[116] ^ RCON_ROW,
                    tweakeys[113] ^ tweakeys[117] ^ RCON32[14],
                    tweakeys[114] ^ tweakeys[118],
                    tweakeys[115] ^ tweakeys[119]);
        }

        @Override
        public void decryptBlock(int[] src, int srcOffset, int[] dest, int dstOffset) {
            data[0] = invMixColumns(src[srcOffset + 0] ^ tweakeys[112] ^ tweakeys[116] ^ RCON_ROW);
            data[1] = invMixColumns(src[srcOffset + 1] ^ tweakeys[113] ^ tweakeys[117] ^ RCON32[14]);
            data[2] = invMixColumns(src[srcOffset + 2] ^ tweakeys[114] ^ tweakeys[118]);
            data[3] = invMixColumns(src[srcOffset + 3] ^ tweakeys[115] ^ tweakeys[119]);

            invAesRound(data, 0, data, 4,
                    invMixColumns(tweakeys[104] ^ tweakeys[108] ^ RCON_ROW),
                    invMixColumns(tweakeys[105] ^ tweakeys[109] ^ RCON32[13]),
                    invMixColumns(tweakeys[106] ^ tweakeys[110]),
                    invMixColumns(tweakeys[107] ^ tweakeys[111]));
            invAesRound(data, 4, data, 0,
                    invMixColumns(tweakeys[96] ^ tweakeys[100] ^ RCON_ROW),
                    invMixColumns(tweakeys[97] ^ tweakeys[101] ^ RCON32[12]),
                    invMixColumns(tweakeys[98] ^ tweakeys[102]),
                    invMixColumns(tweakeys[99] ^ tweakeys[103]));
            invAesRound(data, 0, data, 4,
                    invMixColumns(tweakeys[88] ^ tweakeys[92] ^ RCON_ROW),
                    invMixColumns(tweakeys[89] ^ tweakeys[93] ^ RCON32[11]),
                    invMixColumns(tweakeys[90] ^ tweakeys[94]),
                    invMixColumns(tweakeys[91] ^ tweakeys[95]));
            invAesRound(data, 4, data, 0,
                    invMixColumns(tweakeys[80] ^ tweakeys[84] ^ RCON_ROW),
                    invMixColumns(tweakeys[81] ^ tweakeys[85] ^ RCON32[10]),
                    invMixColumns(tweakeys[82] ^ tweakeys[86]),
                    invMixColumns(tweakeys[83] ^ tweakeys[87]));
            invAesRound(data, 0, data, 4,
                    invMixColumns(tweakeys[72] ^ tweakeys[76] ^ RCON_ROW),
                    invMixColumns(tweakeys[73] ^ tweakeys[77] ^ RCON32[9]),
                    invMixColumns(tweakeys[74] ^ tweakeys[78]),
                    invMixColumns(tweakeys[75] ^ tweakeys[79]));
            invAesRound(data, 4, data, 0,
                    invMixColumns(tweakeys[64] ^ tweakeys[68] ^ RCON_ROW),
                    invMixColumns(tweakeys[65] ^ tweakeys[69] ^ RCON32[8]),
                    invMixColumns(tweakeys[66] ^ tweakeys[70]),
                    invMixColumns(tweakeys[67] ^ tweakeys[71]));
            invAesRound(data, 0, data, 4,
                    invMixColumns(tweakeys[56] ^ tweakeys[60] ^ RCON_ROW),
                    invMixColumns(tweakeys[57] ^ tweakeys[61] ^ RCON32[7]),
                    invMixColumns(tweakeys[58] ^ tweakeys[62]),
                    invMixColumns(tweakeys[59] ^ tweakeys[63]));
            invAesRound(data, 4, data, 0,
                    invMixColumns(tweakeys[48] ^ tweakeys[52] ^ RCON_ROW),
                    invMixColumns(tweakeys[49] ^ tweakeys[53] ^ RCON32[6]),
                    invMixColumns(tweakeys[50] ^ tweakeys[54]),
                    invMixColumns(tweakeys[51] ^ tweakeys[55]));
            invAesRound(data, 0, data, 4,
                    invMixColumns(tweakeys[40] ^ tweakeys[44] ^ RCON_ROW),
                    invMixColumns(tweakeys[41] ^ tweakeys[45] ^ RCON32[5]),
                    invMixColumns(tweakeys[42] ^ tweakeys[46]),
                    invMixColumns(tweakeys[43] ^ tweakeys[47]));
            invAesRound(data, 4, data, 0,
                    invMixColumns(tweakeys[32] ^ tweakeys[36] ^ RCON_ROW),
                    invMixColumns(tweakeys[33] ^ tweakeys[37] ^ RCON32[4]),
                    invMixColumns(tweakeys[34] ^ tweakeys[38]),
                    invMixColumns(tweakeys[35] ^ tweakeys[39]));
            invAesRound(data, 0, data, 4,
                    invMixColumns(tweakeys[24] ^ tweakeys[28] ^ RCON_ROW),
                    invMixColumns(tweakeys[25] ^ tweakeys[29] ^ RCON32[3]),
                    invMixColumns(tweakeys[26] ^ tweakeys[30]),
                    invMixColumns(tweakeys[27] ^ tweakeys[31]));
            invAesRound(data, 4, data, 0,
                    invMixColumns(tweakeys[16] ^ tweakeys[20] ^ RCON_ROW),
                    invMixColumns(tweakeys[17] ^ tweakeys[21] ^ RCON32[2]),
                    invMixColumns(tweakeys[18] ^ tweakeys[22]),
                    invMixColumns(tweakeys[19] ^ tweakeys[23]));
            invAesRound(data, 0, data, 4,
                    invMixColumns(tweakeys[8] ^ tweakeys[12] ^ RCON_ROW),
                    invMixColumns(tweakeys[9] ^ tweakeys[13] ^ RCON32[1]),
                    invMixColumns(tweakeys[10] ^ tweakeys[14]),
                    invMixColumns(tweakeys[11] ^ tweakeys[15]));
            invAesRound(data, 4, data, 0,
                    invMixColumns(tweakeys[0] ^ tweakeys[4] ^ RCON_ROW),
                    invMixColumns(tweakeys[1] ^ tweakeys[5] ^ RCON32[0]),
                    invMixColumns(tweakeys[2] ^ tweakeys[6]),
                    invMixColumns(tweakeys[3] ^ tweakeys[7]));

            dest[dstOffset + 0] = mixColumns(data[0]);
            dest[dstOffset + 1] = mixColumns(data[1]);
            dest[dstOffset + 2] = mixColumns(data[2]);
            dest[dstOffset + 3] = mixColumns(data[3]);
        }

    }

    public static sealed abstract class DeoxysTBC_384 extends DeoxysTBC {

        private final int[] data = new int[8];

        protected final int[] tweakeys = new int[204];

        @Override
        public void encryptBlock(int[] src, int srcOffset, int[] dest, int dstOffset) {
            data[0] = src[srcOffset + 0] ^ tweakeys[0] ^ tweakeys[4] ^ tweakeys[8] ^ RCON_ROW;
            data[1] = src[srcOffset + 1] ^ tweakeys[1] ^ tweakeys[5] ^ tweakeys[9] ^ RCON32[0];
            data[2] = src[srcOffset + 2] ^ tweakeys[2] ^ tweakeys[6] ^ tweakeys[10];
            data[3] = src[srcOffset + 3] ^ tweakeys[3] ^ tweakeys[7] ^ tweakeys[11];

            aesRound(data, 0, data, 4,
                    tweakeys[12] ^ tweakeys[16] ^ tweakeys[20] ^ RCON_ROW,
                    tweakeys[13] ^ tweakeys[17] ^ tweakeys[21] ^ RCON32[1],
                    tweakeys[14] ^ tweakeys[18] ^ tweakeys[22],
                    tweakeys[15] ^ tweakeys[19] ^ tweakeys[23]);
            aesRound(data, 4, data, 0,
                    tweakeys[24] ^ tweakeys[28] ^ tweakeys[32] ^ RCON_ROW,
                    tweakeys[25] ^ tweakeys[29] ^ tweakeys[33] ^ RCON32[2],
                    tweakeys[26] ^ tweakeys[30] ^ tweakeys[34],
                    tweakeys[27] ^ tweakeys[31] ^ tweakeys[35]);
            aesRound(data, 0, data, 4,
                    tweakeys[36] ^ tweakeys[40] ^ tweakeys[44] ^ RCON_ROW,
                    tweakeys[37] ^ tweakeys[41] ^ tweakeys[45] ^ RCON32[3],
                    tweakeys[38] ^ tweakeys[42] ^ tweakeys[46],
                    tweakeys[39] ^ tweakeys[43] ^ tweakeys[47]);
            aesRound(data, 4, data, 0,
                    tweakeys[48] ^ tweakeys[52] ^ tweakeys[56] ^ RCON_ROW,
                    tweakeys[49] ^ tweakeys[53] ^ tweakeys[57] ^ RCON32[4],
                    tweakeys[50] ^ tweakeys[54] ^ tweakeys[58],
                    tweakeys[51] ^ tweakeys[55] ^ tweakeys[59]);
            aesRound(data, 0, data, 4,
                    tweakeys[60] ^ tweakeys[64] ^ tweakeys[68] ^ RCON_ROW,
                    tweakeys[61] ^ tweakeys[65] ^ tweakeys[69] ^ RCON32[5],
                    tweakeys[62] ^ tweakeys[66] ^ tweakeys[70],
                    tweakeys[63] ^ tweakeys[67] ^ tweakeys[71]);
            aesRound(data, 4, data, 0,
                    tweakeys[72] ^ tweakeys[76] ^ tweakeys[80] ^ RCON_ROW,
                    tweakeys[73] ^ tweakeys[77] ^ tweakeys[81] ^ RCON32[6],
                    tweakeys[74] ^ tweakeys[78] ^ tweakeys[82],
                    tweakeys[75] ^ tweakeys[79] ^ tweakeys[83]);
            aesRound(data, 0, data, 4,
                    tweakeys[84] ^ tweakeys[88] ^ tweakeys[92] ^ RCON_ROW,
                    tweakeys[85] ^ tweakeys[89] ^ tweakeys[93] ^ RCON32[7],
                    tweakeys[86] ^ tweakeys[90] ^ tweakeys[94],
                    tweakeys[87] ^ tweakeys[91] ^ tweakeys[95]);
            aesRound(data, 4, data, 0,
                    tweakeys[96] ^ tweakeys[100] ^ tweakeys[104] ^ RCON_ROW,
                    tweakeys[97] ^ tweakeys[101] ^ tweakeys[105] ^ RCON32[8],
                    tweakeys[98] ^ tweakeys[102] ^ tweakeys[106],
                    tweakeys[99] ^ tweakeys[103] ^ tweakeys[107]);
            aesRound(data, 0, data, 4,
                    tweakeys[108] ^ tweakeys[112] ^ tweakeys[116] ^ RCON_ROW,
                    tweakeys[109] ^ tweakeys[113] ^ tweakeys[117] ^ RCON32[9],
                    tweakeys[110] ^ tweakeys[114] ^ tweakeys[118],
                    tweakeys[111] ^ tweakeys[115] ^ tweakeys[119]);
            aesRound(data, 4, data, 0,
                    tweakeys[120] ^ tweakeys[124] ^ tweakeys[128] ^ RCON_ROW,
                    tweakeys[121] ^ tweakeys[125] ^ tweakeys[129] ^ RCON32[10],
                    tweakeys[122] ^ tweakeys[126] ^ tweakeys[130],
                    tweakeys[123] ^ tweakeys[127] ^ tweakeys[131]);
            aesRound(data, 0, data, 4,
                    tweakeys[132] ^ tweakeys[136] ^ tweakeys[140] ^ RCON_ROW,
                    tweakeys[133] ^ tweakeys[137] ^ tweakeys[141] ^ RCON32[11],
                    tweakeys[134] ^ tweakeys[138] ^ tweakeys[142],
                    tweakeys[135] ^ tweakeys[139] ^ tweakeys[143]);
            aesRound(data, 4, data, 0,
                    tweakeys[144] ^ tweakeys[148] ^ tweakeys[152] ^ RCON_ROW,
                    tweakeys[145] ^ tweakeys[149] ^ tweakeys[153] ^ RCON32[12],
                    tweakeys[146] ^ tweakeys[150] ^ tweakeys[154],
                    tweakeys[147] ^ tweakeys[151] ^ tweakeys[155]);
            aesRound(data, 0, data, 4,
                    tweakeys[156] ^ tweakeys[160] ^ tweakeys[164] ^ RCON_ROW,
                    tweakeys[157] ^ tweakeys[161] ^ tweakeys[165] ^ RCON32[13],
                    tweakeys[158] ^ tweakeys[162] ^ tweakeys[166],
                    tweakeys[159] ^ tweakeys[163] ^ tweakeys[167]);
            aesRound(data, 4, data, 0,
                    tweakeys[168] ^ tweakeys[172] ^ tweakeys[176] ^ RCON_ROW,
                    tweakeys[169] ^ tweakeys[173] ^ tweakeys[177] ^ RCON32[14],
                    tweakeys[170] ^ tweakeys[174] ^ tweakeys[178],
                    tweakeys[171] ^ tweakeys[175] ^ tweakeys[179]);
            aesRound(data, 0, data, 4,
                    tweakeys[180] ^ tweakeys[184] ^ tweakeys[188] ^ RCON_ROW,
                    tweakeys[181] ^ tweakeys[185] ^ tweakeys[189] ^ RCON32[15],
                    tweakeys[182] ^ tweakeys[186] ^ tweakeys[190],
                    tweakeys[183] ^ tweakeys[187] ^ tweakeys[191]);
            aesRound(data, 4, dest, dstOffset,
                    tweakeys[192] ^ tweakeys[196] ^ tweakeys[200] ^ RCON_ROW,
                    tweakeys[193] ^ tweakeys[197] ^ tweakeys[201] ^ RCON32[16],
                    tweakeys[194] ^ tweakeys[198] ^ tweakeys[202],
                    tweakeys[195] ^ tweakeys[199] ^ tweakeys[203]);
        }

        @Override
        public void decryptBlock(int[] src, int srcOffset, int[] dest, int dstOffset) {
            data[0] = invMixColumns(src[srcOffset + 0] ^ tweakeys[192] ^ tweakeys[196] ^ tweakeys[200] ^ RCON_ROW);
            data[1] = invMixColumns(src[srcOffset + 1] ^ tweakeys[193] ^ tweakeys[197] ^ tweakeys[201] ^ RCON32[16]);
            data[2] = invMixColumns(src[srcOffset + 2] ^ tweakeys[194] ^ tweakeys[198] ^ tweakeys[202]);
            data[3] = invMixColumns(src[srcOffset + 3] ^ tweakeys[195] ^ tweakeys[199] ^ tweakeys[203]);

            invAesRound(data, 0, data, 4,
                    invMixColumns(tweakeys[180] ^ tweakeys[184] ^ tweakeys[188] ^ RCON_ROW),
                    invMixColumns(tweakeys[181] ^ tweakeys[185] ^ tweakeys[189] ^ RCON32[15]),
                    invMixColumns(tweakeys[182] ^ tweakeys[186] ^ tweakeys[190]),
                    invMixColumns(tweakeys[183] ^ tweakeys[187] ^ tweakeys[191]));
            invAesRound(data, 4, data, 0,
                    invMixColumns(tweakeys[168] ^ tweakeys[172] ^ tweakeys[176] ^ RCON_ROW),
                    invMixColumns(tweakeys[169] ^ tweakeys[173] ^ tweakeys[177] ^ RCON32[14]),
                    invMixColumns(tweakeys[170] ^ tweakeys[174] ^ tweakeys[178]),
                    invMixColumns(tweakeys[171] ^ tweakeys[175] ^ tweakeys[179]));
            invAesRound(data, 0, data, 4,
                    invMixColumns(tweakeys[156] ^ tweakeys[160] ^ tweakeys[164] ^ RCON_ROW),
                    invMixColumns(tweakeys[157] ^ tweakeys[161] ^ tweakeys[165] ^ RCON32[13]),
                    invMixColumns(tweakeys[158] ^ tweakeys[162] ^ tweakeys[166]),
                    invMixColumns(tweakeys[159] ^ tweakeys[163] ^ tweakeys[167]));
            invAesRound(data, 4, data, 0,
                    invMixColumns(tweakeys[144] ^ tweakeys[148] ^ tweakeys[152] ^ RCON_ROW),
                    invMixColumns(tweakeys[145] ^ tweakeys[149] ^ tweakeys[153] ^ RCON32[12]),
                    invMixColumns(tweakeys[146] ^ tweakeys[150] ^ tweakeys[154]),
                    invMixColumns(tweakeys[147] ^ tweakeys[151] ^ tweakeys[155]));
            invAesRound(data, 0, data, 4,
                    invMixColumns(tweakeys[132] ^ tweakeys[136] ^ tweakeys[140] ^ RCON_ROW),
                    invMixColumns(tweakeys[133] ^ tweakeys[137] ^ tweakeys[141] ^ RCON32[11]),
                    invMixColumns(tweakeys[134] ^ tweakeys[138] ^ tweakeys[142]),
                    invMixColumns(tweakeys[135] ^ tweakeys[139] ^ tweakeys[143]));
            invAesRound(data, 4, data, 0,
                    invMixColumns(tweakeys[120] ^ tweakeys[124] ^ tweakeys[128] ^ RCON_ROW),
                    invMixColumns(tweakeys[121] ^ tweakeys[125] ^ tweakeys[129] ^ RCON32[10]),
                    invMixColumns(tweakeys[122] ^ tweakeys[126] ^ tweakeys[130]),
                    invMixColumns(tweakeys[123] ^ tweakeys[127] ^ tweakeys[131]));
            invAesRound(data, 0, data, 4,
                    invMixColumns(tweakeys[108] ^ tweakeys[112] ^ tweakeys[116] ^ RCON_ROW),
                    invMixColumns(tweakeys[109] ^ tweakeys[113] ^ tweakeys[117] ^ RCON32[9]),
                    invMixColumns(tweakeys[110] ^ tweakeys[114] ^ tweakeys[118]),
                    invMixColumns(tweakeys[111] ^ tweakeys[115] ^ tweakeys[119]));
            invAesRound(data, 4, data, 0,
                    invMixColumns(tweakeys[96] ^ tweakeys[100] ^ tweakeys[104] ^ RCON_ROW),
                    invMixColumns(tweakeys[97] ^ tweakeys[101] ^ tweakeys[105] ^ RCON32[8]),
                    invMixColumns(tweakeys[98] ^ tweakeys[102] ^ tweakeys[106]),
                    invMixColumns(tweakeys[99] ^ tweakeys[103] ^ tweakeys[107]));
            invAesRound(data, 0, data, 4,
                    invMixColumns(tweakeys[84] ^ tweakeys[88] ^ tweakeys[92] ^ RCON_ROW),
                    invMixColumns(tweakeys[85] ^ tweakeys[89] ^ tweakeys[93] ^ RCON32[7]),
                    invMixColumns(tweakeys[86] ^ tweakeys[90] ^ tweakeys[94]),
                    invMixColumns(tweakeys[87] ^ tweakeys[91] ^ tweakeys[95]));
            invAesRound(data, 4, data, 0,
                    invMixColumns(tweakeys[72] ^ tweakeys[76] ^ tweakeys[80] ^ RCON_ROW),
                    invMixColumns(tweakeys[73] ^ tweakeys[77] ^ tweakeys[81] ^ RCON32[6]),
                    invMixColumns(tweakeys[74] ^ tweakeys[78] ^ tweakeys[82]),
                    invMixColumns(tweakeys[75] ^ tweakeys[79] ^ tweakeys[83]));
            invAesRound(data, 0, data, 4,
                    invMixColumns(tweakeys[60] ^ tweakeys[64] ^ tweakeys[68] ^ RCON_ROW),
                    invMixColumns(tweakeys[61] ^ tweakeys[65] ^ tweakeys[69] ^ RCON32[5]),
                    invMixColumns(tweakeys[62] ^ tweakeys[66] ^ tweakeys[70]),
                    invMixColumns(tweakeys[63] ^ tweakeys[67] ^ tweakeys[71]));
            invAesRound(data, 4, data, 0,
                    invMixColumns(tweakeys[48] ^ tweakeys[52] ^ tweakeys[56] ^ RCON_ROW),
                    invMixColumns(tweakeys[49] ^ tweakeys[53] ^ tweakeys[57] ^ RCON32[4]),
                    invMixColumns(tweakeys[50] ^ tweakeys[54] ^ tweakeys[58]),
                    invMixColumns(tweakeys[51] ^ tweakeys[55] ^ tweakeys[59]));
            invAesRound(data, 0, data, 4,
                    invMixColumns(tweakeys[36] ^ tweakeys[40] ^ tweakeys[44] ^ RCON_ROW),
                    invMixColumns(tweakeys[37] ^ tweakeys[41] ^ tweakeys[45] ^ RCON32[3]),
                    invMixColumns(tweakeys[38] ^ tweakeys[42] ^ tweakeys[46]),
                    invMixColumns(tweakeys[39] ^ tweakeys[43] ^ tweakeys[47]));
            invAesRound(data, 4, data, 0,
                    invMixColumns(tweakeys[24] ^ tweakeys[28] ^ tweakeys[32] ^ RCON_ROW),
                    invMixColumns(tweakeys[25] ^ tweakeys[29] ^ tweakeys[33] ^ RCON32[2]),
                    invMixColumns(tweakeys[26] ^ tweakeys[30] ^ tweakeys[34]),
                    invMixColumns(tweakeys[27] ^ tweakeys[31] ^ tweakeys[35]));
            invAesRound(data, 0, data, 4,
                    invMixColumns(tweakeys[12] ^ tweakeys[16] ^ tweakeys[20] ^ RCON_ROW),
                    invMixColumns(tweakeys[13] ^ tweakeys[17] ^ tweakeys[21] ^ RCON32[1]),
                    invMixColumns(tweakeys[14] ^ tweakeys[18] ^ tweakeys[22]),
                    invMixColumns(tweakeys[15] ^ tweakeys[19] ^ tweakeys[23]));
            invAesRound(data, 4, data, 0,
                    invMixColumns(tweakeys[0] ^ tweakeys[4] ^ tweakeys[8] ^ RCON_ROW),
                    invMixColumns(tweakeys[1] ^ tweakeys[5] ^ tweakeys[9] ^ RCON32[0]),
                    invMixColumns(tweakeys[2] ^ tweakeys[6] ^ tweakeys[10]),
                    invMixColumns(tweakeys[3] ^ tweakeys[7] ^ tweakeys[11]));

            dest[dstOffset + 0] = mixColumns(data[0]);
            dest[dstOffset + 1] = mixColumns(data[1]);
            dest[dstOffset + 2] = mixColumns(data[2]);
            dest[dstOffset + 3] = mixColumns(data[3]);
        }
    }

    public static final class DeoxysTBC_256_128 extends DeoxysTBC_384 {
        
        public DeoxysTBC_256_128(DeoxysTBC_256_128 other) {
            System.arraycopy(other.tweakeys, 0, tweakeys, 0, tweakeys.length);
        }

        public DeoxysTBC_256_128(byte[] key) {
            tweakeys[0] = Tools.load32BE(key, 0);
            tweakeys[1] = Tools.load32BE(key, 4);
            tweakeys[2] = Tools.load32BE(key, 8);
            tweakeys[3] = Tools.load32BE(key, 12);
            tweakeys[4] = Tools.load32BE(key, 16);
            tweakeys[5] = Tools.load32BE(key, 20);
            tweakeys[6] = Tools.load32BE(key, 24);
            tweakeys[7] = Tools.load32BE(key, 28);

            for (int offset = 12; offset < 204; offset += 12) {
                tweakeys[offset + 0] = ((tweakeys[offset - 11] & 0xff) << 24)
                        | ((tweakeys[offset - 12] & 0xff000000) >>> 8)
                        | ((tweakeys[offset - 9] & 0xff0000) >>> 8)
                        | ((tweakeys[offset - 10] & 0xff00) >>> 8);
                tweakeys[offset + 1] = ((tweakeys[offset - 10] & 0xff) << 24)
                        | ((tweakeys[offset - 11] & 0xff000000) >>> 8)
                        | ((tweakeys[offset - 12] & 0xff0000) >>> 8)
                        | ((tweakeys[offset - 9] & 0xff00) >>> 8);
                tweakeys[offset + 2] = ((tweakeys[offset - 9] & 0xff) << 24)
                        | ((tweakeys[offset - 10] & 0xff000000) >>> 8)
                        | ((tweakeys[offset - 11] & 0xff0000) >>> 8)
                        | ((tweakeys[offset - 12] & 0xff00) >>> 8);
                tweakeys[offset + 3] = ((tweakeys[offset - 12] & 0xff) << 24)
                        | ((tweakeys[offset - 9] & 0xff000000) >>> 8)
                        | ((tweakeys[offset - 10] & 0xff0000) >>> 8)
                        | ((tweakeys[offset - 11] & 0xff00) >>> 8);

                tweakeys[offset + 4] = (LFSR2[(tweakeys[offset - 7] & 0xff)] << 24)
                        | (LFSR2[(tweakeys[offset - 8] & 0xff000000) >>> 24] << 16)
                        | (LFSR2[(tweakeys[offset - 5] & 0xff0000) >>> 16] << 8)
                        | (LFSR2[(tweakeys[offset - 6] & 0xff00) >>> 8]);
                tweakeys[offset + 5] = (LFSR2[(tweakeys[offset - 6] & 0xff)] << 24)
                        | (LFSR2[(tweakeys[offset - 7] & 0xff000000) >>> 24] << 16)
                        | (LFSR2[(tweakeys[offset - 8] & 0xff0000) >>> 16] << 8)
                        | (LFSR2[(tweakeys[offset - 5] & 0xff00) >>> 8]);
                tweakeys[offset + 6] = (LFSR2[(tweakeys[offset - 5] & 0xff)] << 24)
                        | (LFSR2[(tweakeys[offset - 6] & 0xff000000) >>> 24] << 16)
                        | (LFSR2[(tweakeys[offset - 7] & 0xff0000) >>> 16] << 8)
                        | (LFSR2[(tweakeys[offset - 8] & 0xff00) >>> 8]);
                tweakeys[offset + 7] = (LFSR2[(tweakeys[offset - 8] & 0xff)] << 24)
                        | (LFSR2[(tweakeys[offset - 5] & 0xff000000) >>> 24] << 16)
                        | (LFSR2[(tweakeys[offset - 6] & 0xff0000) >>> 16] << 8)
                        | (LFSR2[(tweakeys[offset - 7] & 0xff00) >>> 8]);
            }
        }

        @Override
        public void setTweak(int[] tweak) {
            System.arraycopy(tweak, 0, tweakeys, 8, 4);

            for (int offset = 12; offset < 204; offset += 12) {
                tweakeys[offset + 8] = (LFSR3[(tweakeys[offset - 3] & 0xff)] << 24)
                        | (LFSR3[(tweakeys[offset - 4] & 0xff000000) >>> 24] << 16)
                        | (LFSR3[(tweakeys[offset - 1] & 0xff0000) >>> 16] << 8)
                        | (LFSR3[(tweakeys[offset - 2] & 0xff00) >>> 8]);
                tweakeys[offset + 9] = (LFSR3[(tweakeys[offset - 2] & 0xff)] << 24)
                        | (LFSR3[(tweakeys[offset - 3] & 0xff000000) >>> 24] << 16)
                        | (LFSR3[(tweakeys[offset - 4] & 0xff0000) >>> 16] << 8)
                        | (LFSR3[(tweakeys[offset - 1] & 0xff00) >>> 8]);
                tweakeys[offset + 10] = (LFSR3[(tweakeys[offset - 1] & 0xff)] << 24)
                        | (LFSR3[(tweakeys[offset - 2] & 0xff000000) >>> 24] << 16)
                        | (LFSR3[(tweakeys[offset - 3] & 0xff0000) >>> 16] << 8)
                        | (LFSR3[(tweakeys[offset - 4] & 0xff00) >>> 8]);
                tweakeys[offset + 11] = (LFSR3[(tweakeys[offset - 4] & 0xff)] << 24)
                        | (LFSR3[(tweakeys[offset - 1] & 0xff000000) >>> 24] << 16)
                        | (LFSR3[(tweakeys[offset - 2] & 0xff0000) >>> 16] << 8)
                        | (LFSR3[(tweakeys[offset - 3] & 0xff00) >>> 8]);
            }
        }

    }

    public static final class DeoxysTBC_128_256 extends DeoxysTBC_384 {
        
        public DeoxysTBC_128_256(DeoxysTBC_128_256 other) {
            System.arraycopy(other.tweakeys, 0, tweakeys, 0, tweakeys.length);
        }

        public DeoxysTBC_128_256(byte[] key) {
            tweakeys[0] = Tools.load32BE(key, 0);
            tweakeys[1] = Tools.load32BE(key, 4);
            tweakeys[2] = Tools.load32BE(key, 8);
            tweakeys[3] = Tools.load32BE(key, 12);

            for (int offset = 12; offset < 204; offset += 12) {
                tweakeys[offset + 0] = ((tweakeys[offset - 11] & 0xff) << 24)
                        | ((tweakeys[offset - 12] & 0xff000000) >>> 8)
                        | ((tweakeys[offset - 9] & 0xff0000) >>> 8)
                        | ((tweakeys[offset - 10] & 0xff00) >>> 8);
                tweakeys[offset + 1] = ((tweakeys[offset - 10] & 0xff) << 24)
                        | ((tweakeys[offset - 11] & 0xff000000) >>> 8)
                        | ((tweakeys[offset - 12] & 0xff0000) >>> 8)
                        | ((tweakeys[offset - 9] & 0xff00) >>> 8);
                tweakeys[offset + 2] = ((tweakeys[offset - 9] & 0xff) << 24)
                        | ((tweakeys[offset - 10] & 0xff000000) >>> 8)
                        | ((tweakeys[offset - 11] & 0xff0000) >>> 8)
                        | ((tweakeys[offset - 12] & 0xff00) >>> 8);
                tweakeys[offset + 3] = ((tweakeys[offset - 12] & 0xff) << 24)
                        | ((tweakeys[offset - 9] & 0xff000000) >>> 8)
                        | ((tweakeys[offset - 10] & 0xff0000) >>> 8)
                        | ((tweakeys[offset - 11] & 0xff00) >>> 8);
            }
        }

        public void setTweak0(int[] tweak) {
            System.arraycopy(tweak, 0, tweakeys, 4, 4);

            for (int offset = 12; offset < 204; offset += 12) {

                tweakeys[offset + 4] = (LFSR2[(tweakeys[offset - 7] & 0xff)] << 24)
                        | (LFSR2[(tweakeys[offset - 8] & 0xff000000) >>> 24] << 16)
                        | (LFSR2[(tweakeys[offset - 5] & 0xff0000) >>> 16] << 8)
                        | (LFSR2[(tweakeys[offset - 6] & 0xff00) >>> 8]);
                tweakeys[offset + 5] = (LFSR2[(tweakeys[offset - 6] & 0xff)] << 24)
                        | (LFSR2[(tweakeys[offset - 7] & 0xff000000) >>> 24] << 16)
                        | (LFSR2[(tweakeys[offset - 8] & 0xff0000) >>> 16] << 8)
                        | (LFSR2[(tweakeys[offset - 5] & 0xff00) >>> 8]);
                tweakeys[offset + 6] = (LFSR2[(tweakeys[offset - 5] & 0xff)] << 24)
                        | (LFSR2[(tweakeys[offset - 6] & 0xff000000) >>> 24] << 16)
                        | (LFSR2[(tweakeys[offset - 7] & 0xff0000) >>> 16] << 8)
                        | (LFSR2[(tweakeys[offset - 8] & 0xff00) >>> 8]);
                tweakeys[offset + 7] = (LFSR2[(tweakeys[offset - 8] & 0xff)] << 24)
                        | (LFSR2[(tweakeys[offset - 5] & 0xff000000) >>> 24] << 16)
                        | (LFSR2[(tweakeys[offset - 6] & 0xff0000) >>> 16] << 8)
                        | (LFSR2[(tweakeys[offset - 7] & 0xff00) >>> 8]);
            }
        }

        public void setTweak1(int[] tweak) {
            System.arraycopy(tweak, 0, tweakeys, 8, 4);

            for (int offset = 12; offset < 204; offset += 12) {

                tweakeys[offset + 8] = (LFSR3[(tweakeys[offset - 3] & 0xff)] << 24)
                        | (LFSR3[(tweakeys[offset - 4] & 0xff000000) >>> 24] << 16)
                        | (LFSR3[(tweakeys[offset - 1] & 0xff0000) >>> 16] << 8)
                        | (LFSR3[(tweakeys[offset - 2] & 0xff00) >>> 8]);
                tweakeys[offset + 9] = (LFSR3[(tweakeys[offset - 2] & 0xff)] << 24)
                        | (LFSR3[(tweakeys[offset - 3] & 0xff000000) >>> 24] << 16)
                        | (LFSR3[(tweakeys[offset - 4] & 0xff0000) >>> 16] << 8)
                        | (LFSR3[(tweakeys[offset - 1] & 0xff00) >>> 8]);
                tweakeys[offset + 10] = (LFSR3[(tweakeys[offset - 1] & 0xff)] << 24)
                        | (LFSR3[(tweakeys[offset - 2] & 0xff000000) >>> 24] << 16)
                        | (LFSR3[(tweakeys[offset - 3] & 0xff0000) >>> 16] << 8)
                        | (LFSR3[(tweakeys[offset - 4] & 0xff00) >>> 8]);
                tweakeys[offset + 11] = (LFSR3[(tweakeys[offset - 4] & 0xff)] << 24)
                        | (LFSR3[(tweakeys[offset - 1] & 0xff000000) >>> 24] << 16)
                        | (LFSR3[(tweakeys[offset - 2] & 0xff0000) >>> 16] << 8)
                        | (LFSR3[(tweakeys[offset - 3] & 0xff00) >>> 8]);
            }
        }

        @Override
        public void setTweak(int[] tweak) {
            System.arraycopy(tweak, 0, tweakeys, 4, 8);

            for (int offset = 12; offset < 204; offset += 12) {

                tweakeys[offset + 4] = (LFSR2[(tweakeys[offset - 7] & 0xff)] << 24)
                        | (LFSR2[(tweakeys[offset - 8] & 0xff000000) >>> 24] << 16)
                        | (LFSR2[(tweakeys[offset - 5] & 0xff0000) >>> 16] << 8)
                        | (LFSR2[(tweakeys[offset - 6] & 0xff00) >>> 8]);
                tweakeys[offset + 5] = (LFSR2[(tweakeys[offset - 6] & 0xff)] << 24)
                        | (LFSR2[(tweakeys[offset - 7] & 0xff000000) >>> 24] << 16)
                        | (LFSR2[(tweakeys[offset - 8] & 0xff0000) >>> 16] << 8)
                        | (LFSR2[(tweakeys[offset - 5] & 0xff00) >>> 8]);
                tweakeys[offset + 6] = (LFSR2[(tweakeys[offset - 5] & 0xff)] << 24)
                        | (LFSR2[(tweakeys[offset - 6] & 0xff000000) >>> 24] << 16)
                        | (LFSR2[(tweakeys[offset - 7] & 0xff0000) >>> 16] << 8)
                        | (LFSR2[(tweakeys[offset - 8] & 0xff00) >>> 8]);
                tweakeys[offset + 7] = (LFSR2[(tweakeys[offset - 8] & 0xff)] << 24)
                        | (LFSR2[(tweakeys[offset - 5] & 0xff000000) >>> 24] << 16)
                        | (LFSR2[(tweakeys[offset - 6] & 0xff0000) >>> 16] << 8)
                        | (LFSR2[(tweakeys[offset - 7] & 0xff00) >>> 8]);

                tweakeys[offset + 8] = (LFSR3[(tweakeys[offset - 3] & 0xff)] << 24)
                        | (LFSR3[(tweakeys[offset - 4] & 0xff000000) >>> 24] << 16)
                        | (LFSR3[(tweakeys[offset - 1] & 0xff0000) >>> 16] << 8)
                        | (LFSR3[(tweakeys[offset - 2] & 0xff00) >>> 8]);
                tweakeys[offset + 9] = (LFSR3[(tweakeys[offset - 2] & 0xff)] << 24)
                        | (LFSR3[(tweakeys[offset - 3] & 0xff000000) >>> 24] << 16)
                        | (LFSR3[(tweakeys[offset - 4] & 0xff0000) >>> 16] << 8)
                        | (LFSR3[(tweakeys[offset - 1] & 0xff00) >>> 8]);
                tweakeys[offset + 10] = (LFSR3[(tweakeys[offset - 1] & 0xff)] << 24)
                        | (LFSR3[(tweakeys[offset - 2] & 0xff000000) >>> 24] << 16)
                        | (LFSR3[(tweakeys[offset - 3] & 0xff0000) >>> 16] << 8)
                        | (LFSR3[(tweakeys[offset - 4] & 0xff00) >>> 8]);
                tweakeys[offset + 11] = (LFSR3[(tweakeys[offset - 4] & 0xff)] << 24)
                        | (LFSR3[(tweakeys[offset - 1] & 0xff000000) >>> 24] << 16)
                        | (LFSR3[(tweakeys[offset - 2] & 0xff0000) >>> 16] << 8)
                        | (LFSR3[(tweakeys[offset - 3] & 0xff00) >>> 8]);
            }
        }
    }

}
