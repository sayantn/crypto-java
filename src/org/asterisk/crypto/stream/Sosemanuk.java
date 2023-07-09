/*
 * Copyright (C) 2023 Sayantan Chakraborty
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
package org.asterisk.crypto.stream;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import org.asterisk.crypto.helper.AbstractStreamEncrypter;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.Cipher;
import org.asterisk.crypto.StreamCipher;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum Sosemanuk implements StreamCipher {

    SOSEMANUK;

    private static final ValueLayout.OfInt LAYOUT = Tools.BIG_ENDIAN_32_BIT;

    private static final int MUL_CONST = 0x54655307, XOR_CONST = 0x9e3779b9;

    private static final int[] MUL_A = {
        0x00000000, 0xe19fcf13, 0x6b973726, 0x8a08f835, 0xd6876e4c, 0x3718a15f, 0xbd10596a, 0x5c8f9679,
        0x05a7dc98, 0xe438138b, 0x6e30ebbe, 0x8faf24ad, 0xd320b2d4, 0x32bf7dc7, 0xb8b785f2, 0x59284ae1,
        0x0ae71199, 0xeb78de8a, 0x617026bf, 0x80efe9ac, 0xdc607fd5, 0x3dffb0c6, 0xb7f748f3, 0x566887e0,
        0x0f40cd01, 0xeedf0212, 0x64d7fa27, 0x85483534, 0xd9c7a34d, 0x38586c5e, 0xb250946b, 0x53cf5b78,
        0x1467229b, 0xf5f8ed88, 0x7ff015bd, 0x9e6fdaae, 0xc2e04cd7, 0x237f83c4, 0xa9777bf1, 0x48e8b4e2,
        0x11c0fe03, 0xf05f3110, 0x7a57c925, 0x9bc80636, 0xc747904f, 0x26d85f5c, 0xacd0a769, 0x4d4f687a,
        0x1e803302, 0xff1ffc11, 0x75170424, 0x9488cb37, 0xc8075d4e, 0x2998925d, 0xa3906a68, 0x420fa57b,
        0x1b27ef9a, 0xfab82089, 0x70b0d8bc, 0x912f17af, 0xcda081d6, 0x2c3f4ec5, 0xa637b6f0, 0x47a879e3,
        0x28ce449f, 0xc9518b8c, 0x435973b9, 0xa2c6bcaa, 0xfe492ad3, 0x1fd6e5c0, 0x95de1df5, 0x7441d2e6,
        0x2d699807, 0xccf65714, 0x46feaf21, 0xa7616032, 0xfbeef64b, 0x1a713958, 0x9079c16d, 0x71e60e7e,
        0x22295506, 0xc3b69a15, 0x49be6220, 0xa821ad33, 0xf4ae3b4a, 0x1531f459, 0x9f390c6c, 0x7ea6c37f,
        0x278e899e, 0xc611468d, 0x4c19beb8, 0xad8671ab, 0xf109e7d2, 0x109628c1, 0x9a9ed0f4, 0x7b011fe7,
        0x3ca96604, 0xdd36a917, 0x573e5122, 0xb6a19e31, 0xea2e0848, 0x0bb1c75b, 0x81b93f6e, 0x6026f07d,
        0x390eba9c, 0xd891758f, 0x52998dba, 0xb30642a9, 0xef89d4d0, 0x0e161bc3, 0x841ee3f6, 0x65812ce5,
        0x364e779d, 0xd7d1b88e, 0x5dd940bb, 0xbc468fa8, 0xe0c919d1, 0x0156d6c2, 0x8b5e2ef7, 0x6ac1e1e4,
        0x33e9ab05, 0xd2766416, 0x587e9c23, 0xb9e15330, 0xe56ec549, 0x04f10a5a, 0x8ef9f26f, 0x6f663d7c,
        0x50358897, 0xb1aa4784, 0x3ba2bfb1, 0xda3d70a2, 0x86b2e6db, 0x672d29c8, 0xed25d1fd, 0x0cba1eee,
        0x5592540f, 0xb40d9b1c, 0x3e056329, 0xdf9aac3a, 0x83153a43, 0x628af550, 0xe8820d65, 0x091dc276,
        0x5ad2990e, 0xbb4d561d, 0x3145ae28, 0xd0da613b, 0x8c55f742, 0x6dca3851, 0xe7c2c064, 0x065d0f77,
        0x5f754596, 0xbeea8a85, 0x34e272b0, 0xd57dbda3, 0x89f22bda, 0x686de4c9, 0xe2651cfc, 0x03fad3ef,
        0x4452aa0c, 0xa5cd651f, 0x2fc59d2a, 0xce5a5239, 0x92d5c440, 0x734a0b53, 0xf942f366, 0x18dd3c75,
        0x41f57694, 0xa06ab987, 0x2a6241b2, 0xcbfd8ea1, 0x977218d8, 0x76edd7cb, 0xfce52ffe, 0x1d7ae0ed,
        0x4eb5bb95, 0xaf2a7486, 0x25228cb3, 0xc4bd43a0, 0x9832d5d9, 0x79ad1aca, 0xf3a5e2ff, 0x123a2dec,
        0x4b12670d, 0xaa8da81e, 0x2085502b, 0xc11a9f38, 0x9d950941, 0x7c0ac652, 0xf6023e67, 0x179df174,
        0x78fbcc08, 0x9964031b, 0x136cfb2e, 0xf2f3343d, 0xae7ca244, 0x4fe36d57, 0xc5eb9562, 0x24745a71,
        0x7d5c1090, 0x9cc3df83, 0x16cb27b6, 0xf754e8a5, 0xabdb7edc, 0x4a44b1cf, 0xc04c49fa, 0x21d386e9,
        0x721cdd91, 0x93831282, 0x198beab7, 0xf81425a4, 0xa49bb3dd, 0x45047cce, 0xcf0c84fb, 0x2e934be8,
        0x77bb0109, 0x9624ce1a, 0x1c2c362f, 0xfdb3f93c, 0xa13c6f45, 0x40a3a056, 0xcaab5863, 0x2b349770,
        0x6c9cee93, 0x8d032180, 0x070bd9b5, 0xe69416a6, 0xba1b80df, 0x5b844fcc, 0xd18cb7f9, 0x301378ea,
        0x693b320b, 0x88a4fd18, 0x02ac052d, 0xe333ca3e, 0xbfbc5c47, 0x5e239354, 0xd42b6b61, 0x35b4a472,
        0x667bff0a, 0x87e43019, 0x0decc82c, 0xec73073f, 0xb0fc9146, 0x51635e55, 0xdb6ba660, 0x3af46973,
        0x63dc2392, 0x8243ec81, 0x084b14b4, 0xe9d4dba7, 0xb55b4dde, 0x54c482cd, 0xdecc7af8, 0x3f53b5eb
    };
    private static final int[] DIV_A = {
        0x00000000, 0x180f40cd, 0x301e8033, 0x2811c0fe, 0x603ca966, 0x7833e9ab, 0x50222955, 0x482d6998,
        0xc078fbcc, 0xd877bb01, 0xf0667bff, 0xe8693b32, 0xa04452aa, 0xb84b1267, 0x905ad299, 0x88559254,
        0x29f05f31, 0x31ff1ffc, 0x19eedf02, 0x01e19fcf, 0x49ccf657, 0x51c3b69a, 0x79d27664, 0x61dd36a9,
        0xe988a4fd, 0xf187e430, 0xd99624ce, 0xc1996403, 0x89b40d9b, 0x91bb4d56, 0xb9aa8da8, 0xa1a5cd65,
        0x5249be62, 0x4a46feaf, 0x62573e51, 0x7a587e9c, 0x32751704, 0x2a7a57c9, 0x026b9737, 0x1a64d7fa,
        0x923145ae, 0x8a3e0563, 0xa22fc59d, 0xba208550, 0xf20decc8, 0xea02ac05, 0xc2136cfb, 0xda1c2c36,
        0x7bb9e153, 0x63b6a19e, 0x4ba76160, 0x53a821ad, 0x1b854835, 0x038a08f8, 0x2b9bc806, 0x339488cb,
        0xbbc11a9f, 0xa3ce5a52, 0x8bdf9aac, 0x93d0da61, 0xdbfdb3f9, 0xc3f2f334, 0xebe333ca, 0xf3ec7307,
        0xa492d5c4, 0xbc9d9509, 0x948c55f7, 0x8c83153a, 0xc4ae7ca2, 0xdca13c6f, 0xf4b0fc91, 0xecbfbc5c,
        0x64ea2e08, 0x7ce56ec5, 0x54f4ae3b, 0x4cfbeef6, 0x04d6876e, 0x1cd9c7a3, 0x34c8075d, 0x2cc74790,
        0x8d628af5, 0x956dca38, 0xbd7c0ac6, 0xa5734a0b, 0xed5e2393, 0xf551635e, 0xdd40a3a0, 0xc54fe36d,
        0x4d1a7139, 0x551531f4, 0x7d04f10a, 0x650bb1c7, 0x2d26d85f, 0x35299892, 0x1d38586c, 0x053718a1,
        0xf6db6ba6, 0xeed42b6b, 0xc6c5eb95, 0xdecaab58, 0x96e7c2c0, 0x8ee8820d, 0xa6f942f3, 0xbef6023e,
        0x36a3906a, 0x2eacd0a7, 0x06bd1059, 0x1eb25094, 0x569f390c, 0x4e9079c1, 0x6681b93f, 0x7e8ef9f2,
        0xdf2b3497, 0xc724745a, 0xef35b4a4, 0xf73af469, 0xbf179df1, 0xa718dd3c, 0x8f091dc2, 0x97065d0f,
        0x1f53cf5b, 0x075c8f96, 0x2f4d4f68, 0x37420fa5, 0x7f6f663d, 0x676026f0, 0x4f71e60e, 0x577ea6c3,
        0xe18d0321, 0xf98243ec, 0xd1938312, 0xc99cc3df, 0x81b1aa47, 0x99beea8a, 0xb1af2a74, 0xa9a06ab9,
        0x21f5f8ed, 0x39fab820, 0x11eb78de, 0x09e43813, 0x41c9518b, 0x59c61146, 0x71d7d1b8, 0x69d89175,
        0xc87d5c10, 0xd0721cdd, 0xf863dc23, 0xe06c9cee, 0xa841f576, 0xb04eb5bb, 0x985f7545, 0x80503588,
        0x0805a7dc, 0x100ae711, 0x381b27ef, 0x20146722, 0x68390eba, 0x70364e77, 0x58278e89, 0x4028ce44,
        0xb3c4bd43, 0xabcbfd8e, 0x83da3d70, 0x9bd57dbd, 0xd3f81425, 0xcbf754e8, 0xe3e69416, 0xfbe9d4db,
        0x73bc468f, 0x6bb30642, 0x43a2c6bc, 0x5bad8671, 0x1380efe9, 0x0b8faf24, 0x239e6fda, 0x3b912f17,
        0x9a34e272, 0x823ba2bf, 0xaa2a6241, 0xb225228c, 0xfa084b14, 0xe2070bd9, 0xca16cb27, 0xd2198bea,
        0x5a4c19be, 0x42435973, 0x6a52998d, 0x725dd940, 0x3a70b0d8, 0x227ff015, 0x0a6e30eb, 0x12617026,
        0x451fd6e5, 0x5d109628, 0x750156d6, 0x6d0e161b, 0x25237f83, 0x3d2c3f4e, 0x153dffb0, 0x0d32bf7d,
        0x85672d29, 0x9d686de4, 0xb579ad1a, 0xad76edd7, 0xe55b844f, 0xfd54c482, 0xd545047c, 0xcd4a44b1,
        0x6cef89d4, 0x74e0c919, 0x5cf109e7, 0x44fe492a, 0x0cd320b2, 0x14dc607f, 0x3ccda081, 0x24c2e04c,
        0xac977218, 0xb49832d5, 0x9c89f22b, 0x8486b2e6, 0xccabdb7e, 0xd4a49bb3, 0xfcb55b4d, 0xe4ba1b80,
        0x17566887, 0x0f59284a, 0x2748e8b4, 0x3f47a879, 0x776ac1e1, 0x6f65812c, 0x477441d2, 0x5f7b011f,
        0xd72e934b, 0xcf21d386, 0xe7301378, 0xff3f53b5, 0xb7123a2d, 0xaf1d7ae0, 0x870cba1e, 0x9f03fad3,
        0x3ea637b6, 0x26a9777b, 0x0eb8b785, 0x16b7f748, 0x5e9a9ed0, 0x4695de1d, 0x6e841ee3, 0x768b5e2e,
        0xfedecc7a, 0xe6d18cb7, 0xcec04c49, 0xd6cf0c84, 0x9ee2651c, 0x86ed25d1, 0xaefce52f, 0xb6f3a5e2
    };

    private static int mulA(int x) {
        return (x << 8) ^ MUL_A[x >>> 24];
    }

    private static int divA(int x) {
        return (x >>> 8) ^ DIV_A[x & 0xff];
    }

    private static int[] scheduleKey(byte[] key) {
        int[] sk = new int[100];

        int r0, r1, r2, r3, r4;

        int w0 = Tools.load32LE(key, 0);
        int w1 = Tools.load32LE(key, 4);
        int w2 = Tools.load32LE(key, 8);
        int w3 = Tools.load32LE(key, 12);
        int w4 = 0x01;
        int w5 = 0;
        int w6 = 0;
        int w7 = 0;

        int i = 0;
        for (int cc = 0; cc < 96; cc += 32) {
            w0 = Integer.rotateLeft(w0 ^ w3 ^ w5 ^ w7 ^ XOR_CONST ^ (cc + 0), 11);
            w1 = Integer.rotateLeft(w1 ^ w4 ^ w6 ^ w0 ^ XOR_CONST ^ (cc + 1), 11);
            w2 = Integer.rotateLeft(w2 ^ w5 ^ w7 ^ w1 ^ XOR_CONST ^ (cc + 2), 11);
            w3 = Integer.rotateLeft(w3 ^ w6 ^ w0 ^ w2 ^ XOR_CONST ^ (cc + 3), 11);

            r0 = w0 | w3;
            r3 = w3 ^ w1;
            r1 = w1 & w0;
            r4 = (w0 ^ w2) | r1;
            r2 = w2 ^ r3;
            r3 = (r3 & r0) ^ r4;
            r0 ^= r1;
            r4 = (r4 & r0) ^ r2;
            r2 = ((r1 ^ r3) | r0) ^ r2;

            sk[i++] = (r2 | r3) ^ (r0 ^ r3);
            sk[i++] = r2;
            sk[i++] = r3;
            sk[i++] = r4;

            w4 = Integer.rotateLeft(w4 ^ w7 ^ w1 ^ w3 ^ XOR_CONST ^ (cc + 4), 11);
            w5 = Integer.rotateLeft(w5 ^ w0 ^ w2 ^ w4 ^ XOR_CONST ^ (cc + 5), 11);
            w6 = Integer.rotateLeft(w6 ^ w1 ^ w3 ^ w5 ^ XOR_CONST ^ (cc + 6), 11);
            w7 = Integer.rotateLeft(w7 ^ w2 ^ w4 ^ w6 ^ XOR_CONST ^ (cc + 7), 11);

            r0 = (w4 & w6) ^ w7;
            r2 = w6 ^ w5 ^ r0;
            r3 = (w7 | w4) ^ w5;
            r4 = w4 ^ r2;
            r1 = r3;
            r3 = (r3 | r4) ^ r0;

            sk[i++] = r2;
            sk[i++] = r3;
            sk[i++] = r1 ^ r3 ^ r4;
            sk[i++] = ~r4;

            w0 = Integer.rotateLeft(w0 ^ w3 ^ w5 ^ w7 ^ XOR_CONST ^ (cc + 8), 11);
            w1 = Integer.rotateLeft(w1 ^ w4 ^ w6 ^ w0 ^ XOR_CONST ^ (cc + 9), 11);
            w2 = Integer.rotateLeft(w2 ^ w5 ^ w7 ^ w1 ^ XOR_CONST ^ (cc + 10), 11);
            w3 = Integer.rotateLeft(w3 ^ w6 ^ w0 ^ w2 ^ XOR_CONST ^ (cc + 11), 11);

            r0 = ~w0;

            r4 = r0;
            r0 &= w1;
            r2 = ~w2 ^ r0;
            r0 |= w3;
            r3 = w3 ^ r2;
            r1 = w1 ^ r0 ^ r3;
            r0 ^= r4;
            r4 |= r1;
            r2 = (r2 | r0) & r4;
            r0 ^= r1;

            sk[i++] = r2;
            sk[i++] = (r0 & r2) ^ r4;
            sk[i++] = r3;
            sk[i++] = (r1 & r2) ^ r0;

            w4 = Integer.rotateLeft(w4 ^ w7 ^ w1 ^ w3 ^ XOR_CONST ^ (cc + 12), 11);
            w5 = Integer.rotateLeft(w5 ^ w0 ^ w2 ^ w4 ^ XOR_CONST ^ (cc + 13), 11);
            w6 = Integer.rotateLeft(w6 ^ w1 ^ w3 ^ w5 ^ XOR_CONST ^ (cc + 14), 11);
            w7 = Integer.rotateLeft(w7 ^ w2 ^ w4 ^ w6 ^ XOR_CONST ^ (cc + 15), 11);

            r3 = w7 ^ w4;
            r4 = w5 ^ w6;
            r1 = (w5 & r3) ^ w4;
            r0 = (w4 | r3) ^ r4;
            r4 ^= r3;
            r2 = (w6 | r1) ^ r4;
            r4 = ~r4 | r1;
            r1 ^= r3 ^ w6 ^ r4;
            r3 |= r0;

            sk[i++] = r1 ^ r3;
            sk[i++] = r4 ^ r3;
            sk[i++] = r2;
            sk[i++] = r0;

            w0 = Integer.rotateLeft(w0 ^ w3 ^ w5 ^ w7 ^ XOR_CONST ^ (cc + 16), 11);
            w1 = Integer.rotateLeft(w1 ^ w4 ^ w6 ^ w0 ^ XOR_CONST ^ (cc + 17), 11);
            w2 = Integer.rotateLeft(w2 ^ w5 ^ w7 ^ w1 ^ XOR_CONST ^ (cc + 18), 11);
            w3 = Integer.rotateLeft(w3 ^ w6 ^ w0 ^ w2 ^ XOR_CONST ^ (cc + 19), 11);

            r4 = w1 ^ w2;
            r1 = (w1 | w2) ^ w3;
            r2 = w2 ^ r1;
            r3 = ((w3 | r4) & w0) ^ r1;
            r4 ^= r2;
            r1 = (r1 | r4) ^ w0 ^ r4;
            r0 = (w0 | r4) ^ r2;

            sk[i++] = r4 ^ ~(r2 ^ r1);
            sk[i++] = r3;
            sk[i++] = ((r1 & r0) ^ r4) | r0;
            sk[i++] = r0;

            w4 = Integer.rotateLeft(w4 ^ w7 ^ w1 ^ w3 ^ XOR_CONST ^ (cc + 20), 11);
            w5 = Integer.rotateLeft(w5 ^ w0 ^ w2 ^ w4 ^ XOR_CONST ^ (cc + 21), 11);
            w6 = Integer.rotateLeft(w6 ^ w1 ^ w3 ^ w5 ^ XOR_CONST ^ (cc + 22), 11);
            w7 = Integer.rotateLeft(w7 ^ w2 ^ w4 ^ w6 ^ XOR_CONST ^ (cc + 23), 11);

            r2 = ~w6;

            r3 = (w7 & w4) ^ r2;
            r0 = w4 ^ w7;
            r1 = w5 ^ r3;
            r2 = (r2 | w7) ^ r0 ^ r1;
            r0 |= r1;
            r4 = w7 ^ r0 ^ r3;
            r0 = (r0 | r3) ^ r2;
            r4 ^= r0;

            sk[i++] = r0;
            sk[i++] = r1;
            sk[i++] = r4;
            sk[i++] = (r2 & r4) ^ ~r3;

            w0 = Integer.rotateLeft(w0 ^ w3 ^ w5 ^ w7 ^ XOR_CONST ^ (cc + 24), 11);
            w1 = Integer.rotateLeft(w1 ^ w4 ^ w6 ^ w0 ^ XOR_CONST ^ (cc + 25), 11);
            w2 = Integer.rotateLeft(w2 ^ w5 ^ w7 ^ w1 ^ XOR_CONST ^ (cc + 26), 11);
            w3 = Integer.rotateLeft(w3 ^ w6 ^ w0 ^ w2 ^ XOR_CONST ^ (cc + 27), 11);

            r0 = w0 ^ w1;
            r3 = ~w3;
            r4 = w1 ^ w3;
            r2 = w2 ^ r3;
            r1 = (r4 & r0) ^ r2;
            r2 |= r4;
            r4 ^= r3 ^ r1 ^ r2;
            r3 = (r3 & r1) ^ r0;

            sk[i++] = r1;
            sk[i++] = r3;
            sk[i++] = (r0 & r3) ^ r4;
            sk[i++] = ~(r2 ^ r0) ^ (r4 | r3);

            w4 = Integer.rotateLeft(w4 ^ w7 ^ w1 ^ w3 ^ XOR_CONST ^ (cc + 28), 11);
            w5 = Integer.rotateLeft(w5 ^ w0 ^ w2 ^ w4 ^ XOR_CONST ^ (cc + 29), 11);
            w6 = Integer.rotateLeft(w6 ^ w1 ^ w3 ^ w5 ^ XOR_CONST ^ (cc + 30), 11);
            w7 = Integer.rotateLeft(w7 ^ w2 ^ w4 ^ w6 ^ XOR_CONST ^ (cc + 31), 11);

            r1 = w5 ^ w7;
            r3 = ~w7;
            r2 = w6 ^ r3;
            r3 ^= w4;
            r4 = r1 ^ r3;
            r1 = (r1 & r3) ^ r2;
            r0 = w4 ^ r4;
            r2 = (r2 & r4) ^ r0;
            r0 &= r1;
            r3 ^= r0;

            sk[i++] = r1;
            sk[i++] = ((r4 | r1) ^ r0) ^ (r2 & r3);
            sk[i++] = ~((r0 | r3) ^ r2);
            sk[i++] = r3;

        }

        w0 = Integer.rotateLeft(w0 ^ w3 ^ w5 ^ w7 ^ XOR_CONST ^ 96, 11);
        w1 = Integer.rotateLeft(w1 ^ w4 ^ w6 ^ w0 ^ XOR_CONST ^ 97, 11);
        w2 = Integer.rotateLeft(w2 ^ w5 ^ w7 ^ w1 ^ XOR_CONST ^ 98, 11);
        w3 = Integer.rotateLeft(w3 ^ w6 ^ w0 ^ w2 ^ XOR_CONST ^ 99, 11);

        r0 = w0 | w3;
        r3 = w3 ^ w1;
        r1 = w1 & w0;
        r4 = (w0 ^ w2) | r1;
        r2 = w2 ^ r3;
        r3 = (r3 & r0) ^ r4;
        r0 ^= r1;
        r4 = (r4 & r0) ^ r2;
        r2 = ((r1 ^ r3) | r0) ^ r2;

        sk[i++] = (r2 | r3) ^ (r0 ^ r3);
        sk[i++] = r2;
        sk[i++] = r3;
        sk[i++] = r4;

        return sk;

    }

    private static int[] scheduleIv(int[] sk, byte[] iv, int[] register) {
        int[] state = new int[10];

        int r0, r1, r2, r3, r4;

        r0 = Tools.load32LE(iv, 0) ^ sk[0];
        r1 = Tools.load32LE(iv, 4) ^ sk[1];
        r2 = Tools.load32LE(iv, 8) ^ sk[2];
        r3 = Tools.load32LE(iv, 12) ^ sk[3];

        r0 ^= sk[0];
        r1 ^= sk[1];
        r2 ^= sk[2];
        r3 ^= sk[3];

        r3 ^= r0;
        r4 = r1 ^ r2;
        r1 = (r1 & r3) ^ r0;
        r0 = (r0 | r3) ^ r4;
        r4 ^= r3;
        r3 ^= r2;
        r2 = (r2 | r1) ^ r4;
        r4 = ~r4 | r1;
        r1 ^= r3 ^ r4;
        r3 |= r0;
        r1 ^= r3;
        r4 ^= r3;

        r1 = Integer.rotateLeft(r1, 13);
        r2 = Integer.rotateLeft(r2, 3);
        r4 = Integer.rotateLeft(r4 ^ r1 ^ r2, 1);
        r0 = Integer.rotateLeft(r0 ^ r2 ^ (r1 << 3), 7);
        r1 = Integer.rotateLeft(r1 ^ r4 ^ r0, 5);
        r2 = Integer.rotateLeft(r2 ^ r0 ^ (r4 << 7), 22);

        r1 ^= sk[4];
        r4 ^= sk[5];
        r2 ^= sk[6];
        r0 ^= sk[7];

        r1 = ~r1;
        r2 = ~r2;
        r3 = r1;
        r1 &= r4;
        r2 ^= r1;
        r1 |= r0;
        r0 ^= r2;
        r4 ^= r1;
        r1 ^= r3;
        r3 |= r4;
        r4 ^= r0;
        r2 = (r2 | r1) & r3;
        r1 ^= r4;
        r4 = (r4 & r2) ^ r1;
        r1 = (r1 & r2) ^ r3;

        r2 = Integer.rotateLeft(r2, 13);
        r0 = Integer.rotateLeft(r0, 3);
        r1 = Integer.rotateLeft(r1 ^ r2 ^ r0, 1);
        r4 = Integer.rotateLeft(r4 ^ r0 ^ (r2 << 3), 7);
        r2 = Integer.rotateLeft(r2 ^ r1 ^ r4, 5);
        r0 = Integer.rotateLeft(r0 ^ r4 ^ (r1 << 7), 22);

        r2 ^= sk[8];
        r1 ^= sk[9];
        r0 ^= sk[10];
        r4 ^= sk[11];

        r3 = r2;
        r2 = (r2 & r0) ^ r4;
        r0 ^= r1 ^ r2;
        r4 = (r4 | r3) ^ r1;
        r3 ^= r0;
        r4 = (r4 | r3) ^ r2;
        r3 ^= r2 & r1;
        r1 ^= r4 ^ r3;
        r3 = ~r3;

        r0 = Integer.rotateLeft(r0, 13);
        r1 = Integer.rotateLeft(r1, 3);
        r4 = Integer.rotateLeft(r4 ^ r0 ^ r1, 1);
        r3 = Integer.rotateLeft(r3 ^ r1 ^ (r0 << 3), 7);
        r0 = Integer.rotateLeft(r0 ^ r4 ^ r3, 5);
        r1 = Integer.rotateLeft(r1 ^ r3 ^ (r4 << 7), 22);

        r0 ^= sk[12];
        r4 ^= sk[13];
        r1 ^= sk[14];
        r3 ^= sk[15];

        r2 = r0;
        r0 |= r3;
        r3 ^= r4;
        r4 &= r2;
        r2 ^= r1;
        r1 ^= r3;
        r3 = (r3 & r0) ^ r2;
        r0 ^= r4;
        r2 = ((r2 | r4) & r0) ^ r1;
        r1 ^= (r4 ^ r3) | r0;
        r4 = (r1 | r3) ^ r0 ^ r3;

        r4 = Integer.rotateLeft(r4, 13);
        r3 = Integer.rotateLeft(r3, 3);
        r1 = Integer.rotateLeft(r1 ^ r4 ^ r3, 1);
        r2 = Integer.rotateLeft(r2 ^ r3 ^ (r4 << 3), 7);
        r4 = Integer.rotateLeft(r4 ^ r1 ^ r2, 5);
        r3 = Integer.rotateLeft(r3 ^ r2 ^ (r1 << 7), 22);

        r4 ^= sk[16];
        r1 ^= sk[17];
        r3 ^= sk[18];
        r2 ^= sk[19];

        r1 ^= r2;
        r2 = ~r2;
        r3 ^= r2;
        r2 ^= r4;
        r0 = r1 ^ r2;
        r1 = (r1 & r2) ^ r3;
        r4 ^= r0;
        r3 = (r3 & r0) ^ r4;
        r4 &= r1;
        r2 ^= r4;
        r0 = (r0 | r1) ^ r4;
        r4 = (r4 | r2) ^ r3;
        r3 &= r2;
        r4 = ~r4;
        r0 ^= r3;

        r1 = Integer.rotateLeft(r1, 13);
        r4 = Integer.rotateLeft(r4, 3);
        r0 = Integer.rotateLeft(r0 ^ r1 ^ r4, 1);
        r2 = Integer.rotateLeft(r2 ^ r4 ^ (r1 << 3), 7);
        r1 = Integer.rotateLeft(r1 ^ r0 ^ r2, 5);
        r4 = Integer.rotateLeft(r4 ^ r2 ^ (r0 << 7), 22);

        r1 ^= sk[20];
        r0 ^= sk[21];
        r4 ^= sk[22];
        r2 ^= sk[23];

        r1 ^= r0;
        r0 ^= r2;
        r3 = r0;
        r2 = ~r2;
        r4 ^= r2;
        r0 = (r0 & r1) ^ r4;
        r4 |= r3;
        r3 ^= r2 ^ r0 ^ r4;
        r2 = (r2 & r0) ^ r1;
        r4 = ~(r4 ^ r1) ^ (r3 | r2);
        r1 = (r1 & r2) ^ r3;

        r0 = Integer.rotateLeft(r0, 13);
        r1 = Integer.rotateLeft(r1, 3);
        r2 = Integer.rotateLeft(r2 ^ r0 ^ r1, 1);
        r4 = Integer.rotateLeft(r4 ^ r1 ^ (r0 << 3), 7);
        r0 = Integer.rotateLeft(r0 ^ r2 ^ r4, 5);
        r1 = Integer.rotateLeft(r1 ^ r4 ^ (r2 << 7), 22);

        r0 ^= sk[24];
        r2 ^= sk[25];
        r1 ^= sk[26];
        r4 ^= sk[27];

        r1 = ~r1;
        r3 = r4;
        r4 = (r4 & r0) ^ r1;
        r0 ^= r3;
        r2 ^= r4;
        r1 = (r1 | r3) ^ r0 ^ r2;
        r0 |= r2;
        r3 ^= r0;
        r0 = (r0 | r4) ^ r1;
        r3 ^= r4 ^ r0;
        r1 = (r1 & r3) ^ ~r4;

        r0 = Integer.rotateLeft(r0, 13);
        r3 = Integer.rotateLeft(r3, 3);
        r2 = Integer.rotateLeft(r2 ^ r0 ^ r3, 1);
        r1 = Integer.rotateLeft(r1 ^ r3 ^ (r0 << 3), 7);
        r0 = Integer.rotateLeft(r0 ^ r2 ^ r1, 5);
        r3 = Integer.rotateLeft(r3 ^ r1 ^ (r2 << 7), 22);

        r0 ^= sk[28];
        r2 ^= sk[29];
        r3 ^= sk[30];
        r1 ^= sk[31];

        r4 = r2 ^ r3;
        r2 = (r2 | r3) ^ r1;
        r3 ^= r2;
        r1 = ((r1 | r4) & r0) ^ r2;
        r4 ^= r3;
        r2 = (r2 | r4) ^ r0;
        r0 = (r0 | r4) ^ r3;
        r2 ^= r4;
        r3 = ~(r3 ^ r2) | r0;
        r2 = (r2 & r0) ^ r4;
        r4 ^= r3;

        r4 = Integer.rotateLeft(r4, 13);
        r2 = Integer.rotateLeft(r2, 3);
        r1 = Integer.rotateLeft(r1 ^ r4 ^ r2, 1);
        r0 = Integer.rotateLeft(r0 ^ r2 ^ (r4 << 3), 7);
        r4 = Integer.rotateLeft(r4 ^ r1 ^ r0, 5);
        r2 = Integer.rotateLeft(r2 ^ r0 ^ (r1 << 7), 22);

        r4 ^= sk[32];
        r1 ^= sk[33];
        r2 ^= sk[34];
        r0 ^= sk[35];

        r0 ^= r4;
        r3 = r1 ^ r2;
        r1 = (r1 & r0) ^ r4;
        r4 = (r4 | r0) ^ r3;
        r3 ^= r0;
        r0 ^= r2;
        r2 = (r2 | r1) ^ r3;
        r3 = ~r3 | r1;
        r1 ^= r0 ^ r3;
        r0 |= r4;
        r1 ^= r0;
        r3 ^= r0;

        r1 = Integer.rotateLeft(r1, 13);
        r2 = Integer.rotateLeft(r2, 3);
        r3 = Integer.rotateLeft(r3 ^ r1 ^ r2, 1);
        r4 = Integer.rotateLeft(r4 ^ r2 ^ (r1 << 3), 7);
        r1 = Integer.rotateLeft(r1 ^ r3 ^ r4, 5);
        r2 = Integer.rotateLeft(r2 ^ r4 ^ (r3 << 7), 22);

        r1 ^= sk[36];
        r3 ^= sk[37];
        r2 ^= sk[38];
        r4 ^= sk[39];

        r1 = ~r1;
        r2 = ~r2;
        r0 = r1;
        r1 &= r3;
        r2 ^= r1;
        r1 |= r4;
        r4 ^= r2;
        r3 ^= r1;
        r1 ^= r0;
        r0 |= r3;
        r3 ^= r4;
        r2 = (r2 | r1) & r0;
        r1 ^= r3;
        r3 = (r3 & r2) ^ r1;
        r1 = (r1 & r2) ^ r0;

        r2 = Integer.rotateLeft(r2, 13);
        r4 = Integer.rotateLeft(r4, 3);
        r1 = Integer.rotateLeft(r1 ^ r2 ^ r4, 1);
        r3 = Integer.rotateLeft(r3 ^ r4 ^ (r2 << 3), 7);
        r2 = Integer.rotateLeft(r2 ^ r1 ^ r3, 5);
        r4 = Integer.rotateLeft(r4 ^ r3 ^ (r1 << 7), 22);

        r2 ^= sk[40];
        r1 ^= sk[41];
        r4 ^= sk[42];
        r3 ^= sk[43];

        r0 = r2;
        r2 = (r2 & r4) ^ r3;
        r4 ^= r1 ^ r2;
        r3 = (r3 | r0) ^ r1;
        r0 ^= r4;
        r3 = (r3 | r0) ^ r2;
        r0 ^= r2 & r1;
        r1 ^= r3 ^ r0;
        r0 = ~r0;

        r4 = Integer.rotateLeft(r4, 13);
        r1 = Integer.rotateLeft(r1, 3);
        r3 = Integer.rotateLeft(r3 ^ r4 ^ r1, 1);
        r0 = Integer.rotateLeft(r0 ^ r1 ^ (r4 << 3), 7);
        r4 = Integer.rotateLeft(r4 ^ r3 ^ r0, 5);
        r1 = Integer.rotateLeft(r1 ^ r0 ^ (r3 << 7), 22);

        r4 ^= sk[44];
        r3 ^= sk[45];
        r1 ^= sk[46];
        r0 ^= sk[47];

        r2 = r4;
        r4 |= r0;
        r0 ^= r3;
        r3 &= r2;
        r2 ^= r1;
        r1 ^= r0;
        r0 = (r0 & r4) ^ r2;
        r4 ^= r3;
        r2 = ((r2 | r3) & r4) ^ r1;
        r1 ^= (r3 ^ r0) | r4;
        r3 = (r1 | r0) ^ r4 ^ r0;

        r3 = Integer.rotateLeft(r3, 13);
        r0 = Integer.rotateLeft(r0, 3);
        r1 = Integer.rotateLeft(r1 ^ r3 ^ r0, 1);
        r2 = Integer.rotateLeft(r2 ^ r0 ^ (r3 << 3), 7);
        r3 = Integer.rotateLeft(r3 ^ r1 ^ r2, 5);
        r0 = Integer.rotateLeft(r0 ^ r2 ^ (r1 << 7), 22);

        state[6] = r2;
        state[7] = r0;
        state[8] = r1;
        state[9] = r3;

        r3 ^= sk[48];
        r1 ^= sk[49];
        r0 ^= sk[50];
        r2 ^= sk[51];

        r1 ^= r2;
        r2 = ~r2;
        r0 ^= r2;
        r2 ^= r3;
        r4 = r1 ^ r2;
        r1 = (r1 & r2) ^ r0;
        r3 ^= r4;
        r0 = (r0 & r4) ^ r3;
        r3 &= r1;
        r2 ^= r3;
        r4 = (r4 | r1) ^ r3;
        r3 = (r3 | r2) ^ r0;
        r0 &= r2;
        r3 = ~r3;
        r4 ^= r0;

        r1 = Integer.rotateLeft(r1, 13);
        r3 = Integer.rotateLeft(r3, 3);
        r4 = Integer.rotateLeft(r4 ^ r1 ^ r3, 1);
        r2 = Integer.rotateLeft(r2 ^ r3 ^ (r1 << 3), 7);
        r1 = Integer.rotateLeft(r1 ^ r4 ^ r2, 5);
        r3 = Integer.rotateLeft(r3 ^ r2 ^ (r4 << 7), 22);

        r1 ^= sk[52];
        r4 ^= sk[53];
        r3 ^= sk[54];
        r2 ^= sk[55];

        r1 ^= r4;
        r4 ^= r2;
        r0 = r4;
        r2 = ~r2;
        r3 ^= r2;
        r4 = (r4 & r1) ^ r3;
        r3 |= r0;
        r0 ^= r2 ^ r4 ^ r3;
        r2 = (r2 & r4) ^ r1;
        r3 = ~(r3 ^ r1) ^ (r0 | r2);
        r1 = (r1 & r2) ^ r0;

        r4 = Integer.rotateLeft(r4, 13);
        r1 = Integer.rotateLeft(r1, 3);
        r2 = Integer.rotateLeft(r2 ^ r4 ^ r1, 1);
        r3 = Integer.rotateLeft(r3 ^ r1 ^ (r4 << 3), 7);
        r4 = Integer.rotateLeft(r4 ^ r2 ^ r3, 5);
        r1 = Integer.rotateLeft(r1 ^ r3 ^ (r2 << 7), 22);

        r4 ^= sk[56];
        r2 ^= sk[57];
        r1 ^= sk[58];
        r3 ^= sk[59];

        r1 = ~r1;
        r0 = r3;
        r3 = (r3 & r4) ^ r1;
        r4 ^= r0;
        r2 ^= r3;
        r1 = (r1 | r0) ^ r4 ^ r2;
        r4 |= r2;
        r0 ^= r4;
        r4 = (r4 | r3) ^ r1;
        r0 ^= r3 ^ r4;
        r1 = (r1 & r0) ^ ~r3;

        r4 = Integer.rotateLeft(r4, 13);
        r0 = Integer.rotateLeft(r0, 3);
        r2 = Integer.rotateLeft(r2 ^ r4 ^ r0, 1);
        r1 = Integer.rotateLeft(r1 ^ r0 ^ (r4 << 3), 7);
        r4 = Integer.rotateLeft(r4 ^ r2 ^ r1, 5);
        r0 = Integer.rotateLeft(r0 ^ r1 ^ (r2 << 7), 22);

        r4 ^= sk[60];
        r2 ^= sk[61];
        r0 ^= sk[62];
        r1 ^= sk[63];

        r3 = r2 ^ r0;
        r2 = (r2 | r0) ^ r1;
        r0 ^= r2;
        r1 = ((r1 | r3) & r4) ^ r2;
        r3 ^= r0;
        r2 = (r2 | r3) ^ r4;
        r4 = (r4 | r3) ^ r0;
        r2 ^= r3;
        r0 = ~(r0 ^ r2) | r4;
        r2 = (r2 & r4) ^ r3;
        r3 ^= r0;

        r3 = Integer.rotateLeft(r3, 13);
        r2 = Integer.rotateLeft(r2, 3);
        r1 = Integer.rotateLeft(r1 ^ r3 ^ r2, 1);
        r4 = Integer.rotateLeft(r4 ^ r2 ^ (r3 << 3), 7);
        r3 = Integer.rotateLeft(r3 ^ r1 ^ r4, 5);
        r2 = Integer.rotateLeft(r2 ^ r4 ^ (r1 << 7), 22);

        r3 ^= sk[64];
        r1 ^= sk[65];
        r2 ^= sk[66];
        r4 ^= sk[67];

        r4 ^= r3;
        r0 = r1 ^ r2;
        r1 = (r1 & r4) ^ r3;
        r3 = (r3 | r4) ^ r0;
        r0 ^= r4;
        r4 ^= r2;
        r2 = (r2 | r1) ^ r0;
        r0 = ~r0 | r1;
        r1 ^= r4 ^ r0;
        r4 |= r3;
        r1 ^= r4;
        r0 ^= r4;

        r1 = Integer.rotateLeft(r1, 13);
        r2 = Integer.rotateLeft(r2, 3);
        r0 = Integer.rotateLeft(r0 ^ r1 ^ r2, 1);
        r3 = Integer.rotateLeft(r3 ^ r2 ^ (r1 << 3), 7);
        r1 = Integer.rotateLeft(r1 ^ r0 ^ r3, 5);
        r2 = Integer.rotateLeft(r2 ^ r3 ^ (r0 << 7), 22);

        r1 ^= sk[68];
        r0 ^= sk[69];
        r2 ^= sk[70];
        r3 ^= sk[71];

        r1 = ~r1;
        r2 = ~r2;
        r4 = r1;
        r1 &= r0;
        r2 ^= r1;
        r1 |= r3;
        r3 ^= r2;
        r0 ^= r1;
        r1 ^= r4;
        r4 |= r0;
        r0 ^= r3;
        r2 = (r2 | r1) & r4;
        r1 ^= r0;
        r0 = (r0 & r2) ^ r1;
        r1 = (r1 & r2) ^ r4;

        r2 = Integer.rotateLeft(r2, 13);
        r3 = Integer.rotateLeft(r3, 3);
        r1 = Integer.rotateLeft(r1 ^ r2 ^ r3, 1);
        r0 = Integer.rotateLeft(r0 ^ r3 ^ (r2 << 3), 7);
        r2 = Integer.rotateLeft(r2 ^ r1 ^ r0, 5);
        r3 = Integer.rotateLeft(r3 ^ r0 ^ (r1 << 7), 22);

        state[5] = r0;
        register[1] = r3;
        state[4] = r1;
        register[0] = r2;

        r2 ^= sk[72];
        r1 ^= sk[73];
        r3 ^= sk[74];
        r0 ^= sk[75];

        r4 = r2;
        r2 = (r2 & r3) ^ r0;
        r3 ^= r1 ^ r2;
        r0 = (r0 | r4) ^ r1;
        r4 ^= r3;
        r0 = (r0 | r4) ^ r2;
        r4 ^= r2 & r1;
        r1 ^= r0 ^ r4;
        r4 = ~r4;

        r3 = Integer.rotateLeft(r3, 13);
        r1 = Integer.rotateLeft(r1, 3);
        r0 = Integer.rotateLeft(r0 ^ r3 ^ r1, 1);
        r4 = Integer.rotateLeft(r4 ^ r1 ^ (r3 << 3), 7);
        r3 = Integer.rotateLeft(r3 ^ r0 ^ r4, 5);
        r1 = Integer.rotateLeft(r1 ^ r4 ^ (r0 << 7), 22);

        r3 ^= sk[76];
        r0 ^= sk[77];
        r1 ^= sk[78];
        r4 ^= sk[79];

        r2 = r3;
        r3 |= r4;
        r4 ^= r0;
        r0 &= r2;
        r2 ^= r1;
        r1 ^= r4;
        r4 = (r4 & r3) ^ r2;
        r3 ^= r0;
        r2 = ((r2 | r0) & r3) ^ r1;
        r1 ^= (r0 ^ r4) | r3;
        r0 = (r1 | r4) ^ r3 ^ r4;

        r0 = Integer.rotateLeft(r0, 13);
        r4 = Integer.rotateLeft(r4, 3);
        r1 = Integer.rotateLeft(r1 ^ r0 ^ r4, 1);
        r2 = Integer.rotateLeft(r2 ^ r4 ^ (r0 << 3), 7);
        r0 = Integer.rotateLeft(r0 ^ r1 ^ r2, 5);
        r4 = Integer.rotateLeft(r4 ^ r2 ^ (r1 << 7), 22);

        r0 ^= sk[80];
        r1 ^= sk[81];
        r4 ^= sk[82];
        r2 ^= sk[83];

        r1 ^= r2;
        r2 = ~r2;
        r4 ^= r2;
        r2 ^= r0;
        r3 = r1 ^ r2;
        r1 = (r1 & r2) ^ r4;
        r0 ^= r3;
        r4 = (r4 & r3) ^ r0;
        r0 &= r1;
        r2 ^= r0;
        r3 = (r3 | r1) ^ r0;
        r0 = (r0 | r2) ^ r4;
        r4 &= r2;
        r0 = ~r0;
        r3 ^= r4;

        r1 = Integer.rotateLeft(r1, 13);
        r0 = Integer.rotateLeft(r0, 3);
        r3 = Integer.rotateLeft(r3 ^ r1 ^ r0, 1);
        r2 = Integer.rotateLeft(r2 ^ r0 ^ (r1 << 3), 7);
        r1 = Integer.rotateLeft(r1 ^ r3 ^ r2, 5);
        r0 = Integer.rotateLeft(r0 ^ r2 ^ (r3 << 7), 22);

        r1 ^= sk[84];
        r3 ^= sk[85];
        r0 ^= sk[86];
        r2 ^= sk[87];

        r1 ^= r3;
        r3 ^= r2;
        r4 = r3;
        r2 = ~r2;
        r0 ^= r2;
        r3 = (r3 & r1) ^ r0;
        r0 |= r4;
        r4 ^= r2 ^ r3 ^ r0;
        r2 = (r2 & r3) ^ r1;
        r0 = ~(r0 ^ r1) ^ (r4 | r2);
        r1 = (r1 & r2) ^ r4;

        r3 = Integer.rotateLeft(r3, 13);
        r1 = Integer.rotateLeft(r1, 3);
        r2 = Integer.rotateLeft(r2 ^ r3 ^ r1, 1);
        r0 = Integer.rotateLeft(r0 ^ r1 ^ (r3 << 3), 7);
        r3 = Integer.rotateLeft(r3 ^ r2 ^ r0, 5);
        r1 = Integer.rotateLeft(r1 ^ r0 ^ (r2 << 7), 22);

        r3 ^= sk[88];
        r2 ^= sk[89];
        r1 ^= sk[90];
        r0 ^= sk[91];

        r1 = ~r1;
        r4 = r0;
        r0 = (r0 & r3) ^ r1;
        r3 ^= r4;
        r2 ^= r0;
        r1 = (r1 | r4) ^ r3 ^ r2;
        r3 |= r2;
        r4 ^= r3;
        r3 = (r3 | r0) ^ r1;
        r4 ^= r0 ^ r3;
        r1 = (r1 & r4) ^ ~r0;

        r3 = Integer.rotateLeft(r3, 13);
        r4 = Integer.rotateLeft(r4, 3);
        r2 = Integer.rotateLeft(r2 ^ r3 ^ r4, 1);
        r1 = Integer.rotateLeft(r1 ^ r4 ^ (r3 << 3), 7);
        r3 = Integer.rotateLeft(r3 ^ r2 ^ r1, 5);
        r4 = Integer.rotateLeft(r4 ^ r1 ^ (r2 << 7), 22);

        r3 ^= sk[92];
        r2 ^= sk[93];
        r4 ^= sk[94];
        r1 ^= sk[95];

        r0 = r2 ^ r4;
        r2 = (r2 | r4) ^ r1;
        r4 ^= r2;
        r1 = ((r1 | r0) & r3) ^ r2;
        r0 ^= r4;
        r2 = (r2 | r0) ^ r3;
        r3 = (r3 | r0) ^ r4;
        r2 ^= r0;
        r4 = ~(r4 ^ r2) | r3;
        r2 = (r2 & r3) ^ r0;
        r0 ^= r4;

        r0 = Integer.rotateLeft(r0, 13);
        r2 = Integer.rotateLeft(r2, 3);
        r1 = Integer.rotateLeft(r1 ^ r0 ^ r2, 1);
        r3 = Integer.rotateLeft(r3 ^ r2 ^ (r0 << 3), 7);
        r0 = Integer.rotateLeft(r0 ^ r1 ^ r3, 5);
        r2 = Integer.rotateLeft(r2 ^ r3 ^ (r1 << 7), 22);

        state[0] = r3 ^ sk[99];
        state[1] = r2 ^ sk[98];
        state[2] = r1 ^ sk[97];
        state[3] = r0 ^ sk[96];

        return state;
    }

    private static void keystream(int[] state, int[] register, int[] keystream) {
        int s0 = state[0], s1 = state[1], s2 = state[2], s3 = state[3], s4 = state[4];
        int s5 = state[5], s6 = state[6], s7 = state[7], s8 = state[8], s9 = state[9];
        int r1 = register[0], r2 = register[1];

        int tt, f0, f1, f2, f3, f4;

        tt = r2 + s1 ^ (-(r1 & 1) & s8);
        r2 = Integer.rotateLeft(r1 * MUL_CONST, 7);
        int s10 = mulA(s0) ^ divA(s3) ^ s9;
        f0 = (s9 + r1) ^ r2;

        r1 = r2 + s2 ^ (-(tt & 1) & s9);
        r2 = Integer.rotateLeft(tt * MUL_CONST, 7);
        int s11 = mulA(s1) ^ divA(s4) ^ s10;
        f1 = (s10 + r1) ^ r2;

        tt = r2 + s3 ^ (-(r1 & 1) & s10);
        r2 = Integer.rotateLeft(r1 * MUL_CONST, 7);
        int s12 = mulA(s2) ^ divA(s5) ^ s11;
        f2 = (s11 + r1) ^ r2;

        r1 = r2 + s4 ^ (-(tt & 1) & s11);
        r2 = Integer.rotateLeft(tt * MUL_CONST, 7);
        int s13 = mulA(s3) ^ divA(s6) ^ s12;
        f3 = (s12 + r1) ^ r2;

        f4 = f0;
        f0 = (f0 & f2) ^ f3;
        f2 ^= f0 ^ f1;
        f3 = (f3 | f4) ^ f1;
        f4 ^= f2;
        f1 = f3;
        f3 = (f3 | f4) ^ f0;
        f4 ^= f0 & f1;

        keystream[0] = f2 ^ s0;
        keystream[1] = f3 ^ s1;
        keystream[2] = f1 ^ f3 ^ f4 ^ s2;
        keystream[3] = ~f4 ^ s3;

        tt = r2 + s5 ^ (-(r1 & 1) & s12);
        r2 = Integer.rotateLeft(r1 * MUL_CONST, 7);
        int s14 = mulA(s4) ^ divA(s7) ^ s13;
        f0 = (s13 + r1) ^ r2;

        r1 = r2 + s6 ^ (-(tt & 1) & s13);
        r2 = Integer.rotateLeft(tt * MUL_CONST, 7);
        int s15 = mulA(s5) ^ divA(s8) ^ s14;
        f1 = (s14 + r1) ^ r2;

        tt = r2 + s7 ^ (-(r1 & 1) & s14);
        r2 = Integer.rotateLeft(r1 * MUL_CONST, 7);
        int s16 = mulA(s6) ^ divA(s9) ^ s15;
        f2 = (s15 + r1) ^ r2;

        r1 = r2 + s8 ^ (-(tt & 1) & s15);
        r2 = Integer.rotateLeft(tt * MUL_CONST, 7);
        int s17 = mulA(s7) ^ divA(s10) ^ s16;
        f3 = (s16 + r1) ^ r2;

        f4 = f0;
        f0 = (f0 & f2) ^ f3;
        f2 ^= f0 ^ f1;
        f3 = (f3 | f4) ^ f1;
        f4 ^= f2;
        f1 = f3;
        f3 = (f3 | f4) ^ f0;
        f4 ^= f0 & f1;

        keystream[4] = f2 ^ s4;
        keystream[5] = f3 ^ s5;
        keystream[6] = f1 ^ f3 ^ f4 ^ s6;
        keystream[7] = ~f4 ^ s7;

        tt = r2 + s9 ^ (-(r1 & 1) & s16);
        r2 = Integer.rotateLeft(r1 * MUL_CONST, 7);
        int s18 = mulA(s8) ^ divA(s11) ^ s17;
        f0 = (s17 + r1) ^ r2;

        r1 = r2 + s10 ^ (-(tt & 1) & s17);
        r2 = Integer.rotateLeft(tt * MUL_CONST, 7);
        int s19 = mulA(s9) ^ divA(s12) ^ s18;
        f1 = (s18 + r1) ^ r2;

        tt = r2 + s11 ^ (-(r1 & 1) & s18);
        r2 = Integer.rotateLeft(r1 * MUL_CONST, 7);
        s0 = mulA(s10) ^ divA(s13) ^ s19;
        f2 = (s19 + r1) ^ r2;

        r1 = r2 + s12 ^ (-(tt & 1) & s19);
        r2 = Integer.rotateLeft(tt * MUL_CONST, 7);
        s1 = mulA(s11) ^ divA(s14) ^ s0;
        f3 = (s0 + r1) ^ r2;

        f4 = f0;
        f0 = (f0 & f2) ^ f3;
        f2 ^= f0 ^ f1;
        f3 = (f3 | f4) ^ f1;
        f4 ^= f2;
        f1 = f3;
        f3 = (f3 | f4) ^ f0;
        f4 ^= f0 & f1;

        keystream[8] = f2 ^ s8;
        keystream[9] = f3 ^ s9;
        keystream[10] = f1 ^ f3 ^ f4 ^ s10;
        keystream[11] = ~f4 ^ s11;

        tt = r2 + s13 ^ (-(r1 & 1) & s0);
        r2 = Integer.rotateLeft(r1 * MUL_CONST, 7);
        s2 = mulA(s12) ^ divA(s15) ^ s1;
        f0 = (s1 + r1) ^ r2;

        r1 = r2 + s14 ^ (-(tt & 1) & s1);
        r2 = Integer.rotateLeft(tt * MUL_CONST, 7);
        s3 = mulA(s13) ^ divA(s16) ^ s2;
        f1 = (s2 + r1) ^ r2;

        tt = r2 + s15 ^ (-(r1 & 1) & s2);
        r2 = Integer.rotateLeft(r1 * MUL_CONST, 7);
        s4 = mulA(s14) ^ divA(s17) ^ s3;
        f2 = (s3 + r1) ^ r2;

        r1 = r2 + s16 ^ (-(tt & 1) & s3);
        r2 = Integer.rotateLeft(tt * MUL_CONST, 7);
        s5 = mulA(s15) ^ divA(s18) ^ s4;
        f3 = (s4 + r1) ^ r2;

        f4 = f0;
        f0 = (f0 & f2) ^ f3;
        f2 ^= f0 ^ f1;
        f3 = (f3 | f4) ^ f1;
        f4 ^= f2;
        f1 = f3;
        f3 = (f3 | f4) ^ f0;
        f4 ^= f0 & f1;

        keystream[12] = f2 ^ s12;
        keystream[13] = f3 ^ s13;
        keystream[14] = f1 ^ f3 ^ f4 ^ s14;
        keystream[15] = ~f4 ^ s15;

        tt = r2 + s17 ^ (-(r1 & 1) & s4);
        r2 = Integer.rotateLeft(r1 * MUL_CONST, 7);
        s6 = mulA(s16) ^ divA(s19) ^ s5;
        f0 = (s5 + r1) ^ r2;

        r1 = r2 + s18 ^ (-(tt & 1) & s5);
        r2 = Integer.rotateLeft(tt * MUL_CONST, 7);
        s7 = mulA(s17) ^ divA(s0) ^ s6;
        f1 = (s6 + r1) ^ r2;

        tt = r2 + s19 ^ (-(r1 & 1) & s6);
        r2 = Integer.rotateLeft(r1 * MUL_CONST, 7);
        s8 = mulA(s18) ^ divA(s1) ^ s7;
        f2 = (s7 + r1) ^ r2;

        r1 = r2 + s0 ^ (-(tt & 1) & s7);
        r2 = Integer.rotateLeft(tt * MUL_CONST, 7);
        s9 = mulA(s19) ^ divA(s2) ^ s8;
        f3 = (s8 + r1) ^ r2;

        f4 = f0;
        f0 = (f0 & f2) ^ f3;
        f2 ^= f0 ^ f1;
        f3 = (f3 | f4) ^ f1;
        f4 ^= f2;
        f1 = f3;
        f3 = (f3 | f4) ^ f0;
        f4 ^= f0 & f1;

        keystream[16] = f2 ^ s16;
        keystream[17] = f3 ^ s17;
        keystream[18] = f1 ^ f3 ^ f4 ^ s18;
        keystream[19] = ~f4 ^ s19;

        state[0] = s0;
        state[1] = s1;
        state[2] = s2;
        state[3] = s3;
        state[4] = s4;
        state[5] = s5;
        state[6] = s6;
        state[7] = s7;
        state[8] = s8;
        state[9] = s9;

        register[0] = r1;
        register[1] = r2;

    }

    @Override
    public EncryptEngine startEncryption(byte[] key, byte[] iv) {
        return new AbstractStreamEncrypter(80) {

            private final int[] register = new int[2], state = scheduleIv(scheduleKey(key), iv, register), keystream = new int[20];

            @Override
            protected void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
                keystream(state, register, keystream);

                ciphertext.set(LAYOUT, cOffset + 0, plaintext.get(LAYOUT, pOffset + 0) ^ keystream[0]);
                ciphertext.set(LAYOUT, cOffset + 4, plaintext.get(LAYOUT, pOffset + 4) ^ keystream[1]);
                ciphertext.set(LAYOUT, cOffset + 8, plaintext.get(LAYOUT, pOffset + 8) ^ keystream[2]);
                ciphertext.set(LAYOUT, cOffset + 12, plaintext.get(LAYOUT, pOffset + 12) ^ keystream[3]);
                ciphertext.set(LAYOUT, cOffset + 16, plaintext.get(LAYOUT, pOffset + 16) ^ keystream[4]);
                ciphertext.set(LAYOUT, cOffset + 20, plaintext.get(LAYOUT, pOffset + 20) ^ keystream[5]);
                ciphertext.set(LAYOUT, cOffset + 24, plaintext.get(LAYOUT, pOffset + 24) ^ keystream[6]);
                ciphertext.set(LAYOUT, cOffset + 28, plaintext.get(LAYOUT, pOffset + 28) ^ keystream[7]);
                ciphertext.set(LAYOUT, cOffset + 32, plaintext.get(LAYOUT, pOffset + 32) ^ keystream[8]);
                ciphertext.set(LAYOUT, cOffset + 36, plaintext.get(LAYOUT, pOffset + 36) ^ keystream[9]);
                ciphertext.set(LAYOUT, cOffset + 40, plaintext.get(LAYOUT, pOffset + 40) ^ keystream[10]);
                ciphertext.set(LAYOUT, cOffset + 44, plaintext.get(LAYOUT, pOffset + 44) ^ keystream[11]);
                ciphertext.set(LAYOUT, cOffset + 48, plaintext.get(LAYOUT, pOffset + 48) ^ keystream[12]);
                ciphertext.set(LAYOUT, cOffset + 52, plaintext.get(LAYOUT, pOffset + 52) ^ keystream[13]);
                ciphertext.set(LAYOUT, cOffset + 56, plaintext.get(LAYOUT, pOffset + 56) ^ keystream[14]);
                ciphertext.set(LAYOUT, cOffset + 60, plaintext.get(LAYOUT, pOffset + 60) ^ keystream[15]);
                ciphertext.set(LAYOUT, cOffset + 64, plaintext.get(LAYOUT, pOffset + 64) ^ keystream[16]);
                ciphertext.set(LAYOUT, cOffset + 68, plaintext.get(LAYOUT, pOffset + 68) ^ keystream[17]);
                ciphertext.set(LAYOUT, cOffset + 72, plaintext.get(LAYOUT, pOffset + 72) ^ keystream[18]);
                ciphertext.set(LAYOUT, cOffset + 76, plaintext.get(LAYOUT, pOffset + 76) ^ keystream[19]);

            }

            @Override
            public Cipher getAlgorithm() {
                return SOSEMANUK;
            }
        };
    }

    @Override
    public int keyLength() {
        return 16;
    }

    @Override
    public int ivLength() {
        return 16;
    }
}
