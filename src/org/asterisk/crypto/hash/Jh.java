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
package org.asterisk.crypto.hash;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import org.asterisk.crypto.helper.AbstractDigestEngine;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.Digest;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum Jh implements Digest {

    JH_224 {
        @Override
        public Engine start() {
            return new JhEngine(new long[]{
                0x01c9bc143f7353b8L, 0x7abf4a2433c6629eL, 0x06c7d14af0c0aeb1L, 0xdc54e0cbc50a5ff7L,
                0xa267cacc1b4e1003L, 0xdd24b020d577637bL, 0xbd0666e8a99c4411L, 0xc5459e783829016bL,
                0xe67cacc970aacdfcL, 0x26bf0d6048c9f403L, 0x62e8ba9b4ed461a5L, 0x06312d0a65b4aca5L,
                0xf0cf492540f97f34L, 0x571e8016b5511b24L, 0xb9622a6567e4615eL, 0x9402a1fe741afd13L
            }) {
                @Override
                protected void getDigest(byte[] dest, int offset) {
                    Tools.store32BE((int) state[12], dest, offset + 0);
                    Tools.store64BE(state[13], dest, offset + 4);
                    Tools.store64BE(state[14], dest, offset + 12);
                    Tools.store64BE(state[15], dest, offset + 20);
                }

                @Override
                public Digest getAlgorithm() {
                    return JH_224;
                }

            };
        }

        @Override
        public int digestSize() {
            return 28;
        }

    }, JH_256 {
        @Override
        public Engine start() {
            return new JhEngine(new long[]{
                0x237aa53cf9d5f23fL, 0xfb8d8f32a03147fbL, 0x415822f0b0e9191cL, 0x191a75701c4e7a80L,
                0xc35ebc0e88141907L, 0x5bdc704a9a5daa90L, 0xbe7f60a8673f9612L, 0x989f2a96ae514ad5L,
                0x078f3f62e4c96653L, 0xaceeec4ddcabc86dL, 0x6e74f2b3715193baL, 0x5590c19dcb0315a9L,
                0x4dbc5ff2f95d6a3dL, 0xc7bad7aed703c4d5L, 0x3be95f7b5ae27890L, 0xc004e10bd1f8482aL
            }) {
                @Override
                protected void getDigest(byte[] dest, int offset) {
                    Tools.store64BE(state[12], dest, offset + 0);
                    Tools.store64BE(state[13], dest, offset + 8);
                    Tools.store64BE(state[14], dest, offset + 16);
                    Tools.store64BE(state[15], dest, offset + 24);
                }

                @Override
                public Digest getAlgorithm() {
                    return JH_256;
                }

            };
        }

        @Override
        public int digestSize() {
            return 32;
        }

    }, JH_384 {
        @Override
        public Engine start() {
            return new JhEngine(new long[]{
                0x5ebd709e830e5f6aL, 0x2584cc0b48ad7f98L, 0x736d03babcf1b1b7L, 0x72348802fbcd0aa3L,
                0x15bd2602a8b3d884L, 0x838cef49a6b5bba4L, 0x98c59d66b093423dL, 0x42693d20c145d151L,
                0x5027a0dfd144580cL, 0x1b140e8be9152d0eL, 0x21e1c2f2d9034c68L, 0xe0aa214f61661827L,
                0x11a2f8f71673f734L, 0x309d19ea2c3cc7bcL, 0x5de37797b169bc4eL, 0x7ea6b95240d2e794L
            }) {
                @Override
                protected void getDigest(byte[] dest, int offset) {
                    Tools.store64BE(state[10], dest, offset + 0);
                    Tools.store64BE(state[11], dest, offset + 8);
                    Tools.store64BE(state[12], dest, offset + 16);
                    Tools.store64BE(state[13], dest, offset + 24);
                    Tools.store64BE(state[14], dest, offset + 32);
                    Tools.store64BE(state[15], dest, offset + 40);
                }

                @Override
                public Digest getAlgorithm() {
                    return JH_384;
                }

            };
        }

        @Override
        public int digestSize() {
            return 48;
        }

    }, JH_512 {
        @Override
        public Engine start() {
            return new JhEngine(new long[]{
                0xccb6f358febed485L, 0xf09ee2cb7ad91aabL, 0xa9face3c42660321L, 0xc87ae817de554b26L,
                0x76de2910f5a2311eL, 0x7a16546a081ce03eL, 0x5fa281e0576b1d80L, 0x7af54a20aff6e285L,
                0x8135e569a618f8d7L, 0x64be5e32b29d85daL, 0x73c9a2ac978d75f4L, 0xe8d364478a63e32aL,
                0x5b6c309784725f75L, 0xd9bbfe3c20346d7fL, 0x4c5dcc116a005cb8L, 0x41d531bd76dbd0a4L
            }) {
                @Override
                protected void getDigest(byte[] dest, int offset) {
                    Tools.store64BE(state[8], dest, offset + 0);
                    Tools.store64BE(state[9], dest, offset + 8);
                    Tools.store64BE(state[10], dest, offset + 16);
                    Tools.store64BE(state[11], dest, offset + 24);
                    Tools.store64BE(state[12], dest, offset + 32);
                    Tools.store64BE(state[13], dest, offset + 40);
                    Tools.store64BE(state[14], dest, offset + 48);
                    Tools.store64BE(state[15], dest, offset + 56);
                }

                @Override
                public Digest getAlgorithm() {
                    return JH_384;
                }

            };
        }

        @Override
        public int digestSize() {
            return 64;
        }

    };

    private static final ValueLayout.OfLong LAYOUT = Tools.BIG_ENDIAN_64_BIT;

    private static final long[] C0 = {
        0x72d5dea2df15f867L, 0xea983ae05c45fa9cL, 0x03a35a5c9a190edbL, 0x10ba139202bf6b41L, 0x422d5a0df6cc7e90L, 0x976e6c039ee0b81aL,
        0x4a8e8537db03302fL, 0xc5f4158fbdc75ec4L, 0x8ef48f33a9a36315L, 0xce2935434efe983dL, 0xa7050667ee34626aL, 0x0d550aa54af8a4c0L,
        0xfc9f1fec4054207aL, 0x5bdf7228bdfe6e28L, 0x705f6937b324314aL, 0x7d29e8a3927694f2L, 0xa4e7ba31b470bfffL, 0xe5c905fdf7ae090fL,
        0x88401d63a06cf615L, 0xa4d5a456bd4fca00L, 0xa3da8cf2cb0ee116L, 0x32595ba18ddd19d3L, 0x1fb179eaa9282174L, 0xf735c1af98a4d842L,
        0xa7403b1f1c2747f3L, 0x8d9b0c492b49ebdaL, 0xa0b8a2f436103b53L, 0xe3bb3b99f387947bL, 0xf861e2f2108d512aL, 0x330a5bca8829a175L,
        0xeaa8d4f7be1a3921L, 0xb51d3ea6aff2c908L, 0x2f9833b3b1bc765eL, 0xfdc14e0df453c969L, 0xd2c9f2e3009bd20cL, 0x4bc59e7bb5f17992L,
        0xb17681d913326cceL, 0x38df58074e5e6565L, 0x65a0ee39d1f73883L, 0x8ba0df15762592d9L, 0xaa25ce93bd0269d8L, 0x35b49831db411570L
    };

    private static final long[] C1 = {
        0x7b84150ab7231557L, 0x03c5d29966b2999aL, 0x403fb20a87c14410L, 0xdc786515f7bb27d0L, 0xdd629f9c92c097ceL, 0x2105457e446ceca8L,
        0x2a678d2dfb9f6a95L, 0x75446fa78f11bb80L, 0xaa5f5624d5b7f989L, 0x533af974739a4ba7L, 0x8b0b28be6eb91727L, 0x91e3e79f978ef19eL,
        0xe3e41a00cef4c984L, 0x78f57fe20fa5c4b2L, 0x5e8628f11dd6e465L, 0xddcb7a099b30d9c1L, 0x0d324405def8bc48L, 0x947034124290f134L,
        0x47c1444b8752afffL, 0xda9d844bc83e18aeL, 0x33e906589a94999aL, 0x509a1cc0aaa5b446L, 0xe9bdf7353b3651eeL, 0x78edec209e6b6779L,
        0x5940f034b72d769aL, 0x5ba2d74968f3700dL, 0x0ca8079e753eec5aL, 0x75daf4d6726b1c5dL, 0xe3db643359dd75fcL, 0x7f34194db416535cL,
        0x5cf47e094c232751L, 0x83593d98916b3c56L, 0x2bd666a5efc4e62aL, 0xa77d5ac406585826L, 0x5faace30b7d40c30L, 0xff51e66e048668d3L,
        0x3c175284f805a262L, 0xf2fc7c89fc86508eL, 0xf75ee937e42c3abdL, 0x3c85f7f612dc42beL, 0x5af643fd1a7308f9L, 0xea1e0fbbedcd549bL
    };

    private static final long[] C2 = {
        0x81abd6904d5a87f6L, 0x660296b4f2bb538aL, 0x1c051980849e951dL, 0x0a2c813937aa7850L, 0x185ca70bc72b44acL, 0xeef103bb5d8e61faL,
        0x8afe7381f8b8696cL, 0x52de75b7aee488bcL, 0xb6f1ed207c5ae0fdL, 0xd0f51f596f4e8186L, 0x47740726c680103fL, 0x8676728150608dd4L,
        0x4fd794f59dfa95d8L, 0x05897cefee49d32eL, 0xc71b770451b920e7L, 0x1d1b30fb5bdc1be0L, 0x3baefc3253bbd339L, 0xa271b701e344ed95L,
        0x7ebb4af1e20ac630L, 0x7357ce453064d1adL, 0x1f60b220c26f847bL, 0x9f3d6367e4046bbaL, 0x1d57ac5a7550d376L, 0x41836315ea3adba8L,
        0xe73e4e6cd2214ffdL, 0x7d3baed07a8d5584L, 0x9168949256e8884fL, 0x64aeac28dc34b36dL, 0x1cacbcf143ce3fa2L, 0x923b94c30e794d1eL,
        0x26a32453ba323cd2L, 0x4cf87ca17286604dL, 0x06f4b6e8bec1d436L, 0x7ec1141606e0fa16L, 0x742a5116f2e03298L, 0x9b234d57e6966731L,
        0xf42bcbb378471547L, 0x31702e44d00bca86L, 0x2197b2260113f86fL, 0xd8a7ec7cab27b07eL, 0xc05fefda174a19a5L, 0x9ad063a151974072L
    };
    private static final long[] C3 = {
        0x4e9f4fc5c3d12b40L, 0xb556141a88dba231L, 0x6f33ebad5ee7cddcL, 0x3f1abfd2410091d3L, 0xd1df65d663c6fc23L, 0xfd9697b294838197L,
        0x8ac77246c07f4214L, 0x82b8001e98a6a3f4L, 0x36cae95a06422c36L, 0x0e9dad81afd85a9fL, 0xe0a07e6fc67e487bL, 0x7e9e5a41f3e5b062L,
        0x552e7e1124c354a5L, 0x447e9385eb28597fL, 0x74fe43e823d4878aL, 0xda24494ff29c82bfL, 0x459fc3c1e0298ba0L, 0xe93b8e364f2f984aL,
        0x4670b6c5cc6e8ce6L, 0xe8a6ce68145c2567L, 0xd1ceac7fa0d18518L, 0xf6ca19ab0b56ee7eL, 0x3a46c2fea37d7001L, 0xfac33b4d32832c83L,
        0xb8fd8d39dc5759efL, 0xf5a5e9f0e4f88e65L, 0x5bb05c55f8babc4cL, 0x6c34a550b828db71L, 0x67bbd13c02e843b0L, 0x797475d7b6eeaf3fL,
        0x44a3174a6da6d5adL, 0x46e23ecc086ec7f6L, 0x74ee8215bcef2163L, 0x7e90af3d28639d3fL, 0x0deb30d8e3cef89aL, 0xcce6a6f3170a7505L,
        0xff46548223936a48L, 0xf04009a23078474eL, 0xa344edd1ef9fdee7L, 0x538d7ddaaa3ea8deL, 0x974d66334cfd216aL, 0xf6759dbf91476fe2L
    };

    public static void compress(long[] state, long[] data) {
        long x0 = state[0] ^ data[0], x1 = state[1] ^ data[1], x2 = state[2] ^ data[2], x3 = state[3] ^ data[3];
        long x4 = state[4] ^ data[4], x5 = state[5] ^ data[5], x6 = state[6] ^ data[6], x7 = state[7] ^ data[7];
        long x8 = state[8], x9 = state[9], x10 = state[10], x11 = state[11], x12 = state[12], x13 = state[13], x14 = state[14], x15 = state[15];

        long t;

        for (int r = 0; r < 42; r += 7) {
            t = C0[r + 0];

            x12 = ~x12;
            x0 ^= t & ~x8;
            t ^= x0 & x4;
            x0 ^= x8 & x12;
            x12 ^= ~x4 & x8;
            x4 ^= x0 & x8;
            x8 ^= x0 & ~x12;
            x0 ^= x4 | x12;
            x12 ^= x4 & x8;
            x4 ^= t & x0;
            x8 ^= t;

            t = C1[r + 0];

            x13 = ~x13;
            x1 ^= t & ~x9;
            t ^= x1 & x5;
            x1 ^= x9 & x13;
            x13 ^= ~x5 & x9;
            x5 ^= x1 & x9;
            x9 ^= x1 & ~x13;
            x1 ^= x5 | x13;
            x13 ^= x5 & x9;
            x5 ^= t & x1;
            x9 ^= t;

            t = C2[r + 0];

            x14 = ~x14;
            x2 ^= t & ~x10;
            t ^= x2 & x6;
            x2 ^= x10 & x14;
            x14 ^= ~x6 & x10;
            x6 ^= x2 & x10;
            x10 ^= x2 & ~x14;
            x2 ^= x6 | x14;
            x14 ^= x6 & x10;
            x6 ^= t & x2;
            x10 ^= t;

            t = C3[r + 0];

            x15 = ~x15;
            x3 ^= t & ~x11;
            t ^= x3 & x7;
            x3 ^= x11 & x15;
            x15 ^= ~x7 & x11;
            x7 ^= x3 & x11;
            x11 ^= x3 & ~x15;
            x3 ^= x7 | x15;
            x15 ^= x7 & x11;
            x7 ^= t & x3;
            x11 ^= t;

            x2 ^= x4;
            x6 ^= x8;
            x10 ^= x12 ^ x0;
            x14 ^= x0;
            x0 ^= x6;
            x2 ^= x10;
            x8 ^= x14 ^ x2;
            x12 ^= x2;

            x3 ^= x5;
            x7 ^= x9;
            x11 ^= x13 ^ x1;
            x15 ^= x1;
            x1 ^= x7;
            x3 ^= x11;
            x9 ^= x15 ^ x3;
            x13 ^= x3;

            x2 = ((x2 & 0xaaaaaaaaaaaaaaaaL) >>> 1) | ((x2 & 0x5555555555555555L) << 1);
            x3 = ((x3 & 0xaaaaaaaaaaaaaaaaL) >>> 1) | ((x3 & 0x5555555555555555L) << 1);

            x6 = ((x6 & 0xaaaaaaaaaaaaaaaaL) >>> 1) | ((x6 & 0x5555555555555555L) << 1);
            x7 = ((x7 & 0xaaaaaaaaaaaaaaaaL) >>> 1) | ((x7 & 0x5555555555555555L) << 1);

            x10 = ((x10 & 0xaaaaaaaaaaaaaaaaL) >>> 1) | ((x10 & 0x5555555555555555L) << 1);
            x11 = ((x11 & 0xaaaaaaaaaaaaaaaaL) >>> 1) | ((x10 & 0x5555555555555555L) << 1);

            x14 = ((x14 & 0xaaaaaaaaaaaaaaaaL) >>> 1) | ((x14 & 0x5555555555555555L) << 1);
            x15 = ((x15 & 0xaaaaaaaaaaaaaaaaL) >>> 1) | ((x15 & 0x5555555555555555L) << 1);

            t = C0[r + 1];

            x12 = ~x12;
            x0 ^= t & ~x8;
            t ^= x0 & x4;
            x0 ^= x8 & x12;
            x12 ^= ~x4 & x8;
            x4 ^= x0 & x8;
            x8 ^= x0 & ~x12;
            x0 ^= x4 | x12;
            x12 ^= x4 & x8;
            x4 ^= t & x0;
            x8 ^= t;

            t = C1[r + 1];

            x13 = ~x13;
            x1 ^= t & ~x9;
            t ^= x1 & x5;
            x1 ^= x9 & x13;
            x13 ^= ~x5 & x9;
            x5 ^= x1 & x9;
            x9 ^= x1 & ~x13;
            x1 ^= x5 | x13;
            x13 ^= x5 & x9;
            x5 ^= t & x1;
            x9 ^= t;

            t = C2[r + 1];

            x14 = ~x14;
            x2 ^= t & ~x10;
            t ^= x2 & x6;
            x2 ^= x10 & x14;
            x14 ^= ~x6 & x10;
            x6 ^= x2 & x10;
            x10 ^= x2 & ~x14;
            x2 ^= x6 | x14;
            x14 ^= x6 & x10;
            x6 ^= t & x2;
            x10 ^= t;

            t = C3[r + 1];

            x15 = ~x15;
            x3 ^= t & ~x11;
            t ^= x3 & x7;
            x3 ^= x11 & x15;
            x15 ^= ~x7 & x11;
            x7 ^= x3 & x11;
            x11 ^= x3 & ~x15;
            x3 ^= x7 | x15;
            x15 ^= x7 & x11;
            x7 ^= t & x3;
            x11 ^= t;

            x2 ^= x4;
            x6 ^= x8;
            x10 ^= x12 ^ x0;
            x14 ^= x0;
            x0 ^= x6;
            x2 ^= x10;
            x8 ^= x14 ^ x2;
            x12 ^= x2;

            x3 ^= x5;
            x7 ^= x9;
            x11 ^= x13 ^ x1;
            x15 ^= x1;
            x1 ^= x7;
            x3 ^= x11;
            x9 ^= x15 ^ x3;
            x13 ^= x3;

            x2 = ((x2 & 0xccccccccccccccccL) >>> 2) | ((x2 & 0x3333333333333333L) << 2);
            x3 = ((x3 & 0xccccccccccccccccL) >>> 2) | ((x3 & 0x3333333333333333L) << 2);

            x6 = ((x6 & 0xccccccccccccccccL) >>> 2) | ((x6 & 0x3333333333333333L) << 2);
            x7 = ((x7 & 0xccccccccccccccccL) >>> 2) | ((x7 & 0x3333333333333333L) << 2);

            x10 = ((x10 & 0xccccccccccccccccL) >>> 2) | ((x10 & 0x3333333333333333L) << 2);
            x11 = ((x11 & 0xccccccccccccccccL) >>> 2) | ((x10 & 0x3333333333333333L) << 2);

            x14 = ((x14 & 0xccccccccccccccccL) >>> 2) | ((x14 & 0x3333333333333333L) << 2);
            x15 = ((x15 & 0xccccccccccccccccL) >>> 2) | ((x15 & 0x3333333333333333L) << 2);

            t = C0[r + 2];

            x12 = ~x12;
            x0 ^= t & ~x8;
            t ^= x0 & x4;
            x0 ^= x8 & x12;
            x12 ^= ~x4 & x8;
            x4 ^= x0 & x8;
            x8 ^= x0 & ~x12;
            x0 ^= x4 | x12;
            x12 ^= x4 & x8;
            x4 ^= t & x0;
            x8 ^= t;

            t = C1[r + 2];

            x13 = ~x13;
            x1 ^= t & ~x9;
            t ^= x1 & x5;
            x1 ^= x9 & x13;
            x13 ^= ~x5 & x9;
            x5 ^= x1 & x9;
            x9 ^= x1 & ~x13;
            x1 ^= x5 | x13;
            x13 ^= x5 & x9;
            x5 ^= t & x1;
            x9 ^= t;

            t = C2[r + 2];

            x14 = ~x14;
            x2 ^= t & ~x10;
            t ^= x2 & x6;
            x2 ^= x10 & x14;
            x14 ^= ~x6 & x10;
            x6 ^= x2 & x10;
            x10 ^= x2 & ~x14;
            x2 ^= x6 | x14;
            x14 ^= x6 & x10;
            x6 ^= t & x2;
            x10 ^= t;

            t = C3[r + 2];

            x15 = ~x15;
            x3 ^= t & ~x11;
            t ^= x3 & x7;
            x3 ^= x11 & x15;
            x15 ^= ~x7 & x11;
            x7 ^= x3 & x11;
            x11 ^= x3 & ~x15;
            x3 ^= x7 | x15;
            x15 ^= x7 & x11;
            x7 ^= t & x3;
            x11 ^= t;

            x2 ^= x4;
            x6 ^= x8;
            x10 ^= x12 ^ x0;
            x14 ^= x0;
            x0 ^= x6;
            x2 ^= x10;
            x8 ^= x14 ^ x2;
            x12 ^= x2;

            x3 ^= x5;
            x7 ^= x9;
            x11 ^= x13 ^ x1;
            x15 ^= x1;
            x1 ^= x7;
            x3 ^= x11;
            x9 ^= x15 ^ x3;
            x13 ^= x3;

            x2 = ((x2 & 0xf0f0f0f0f0f0f0f0L) >>> 4) | ((x2 & 0x0f0f0f0f0f0f0f0fL) << 4);
            x3 = ((x3 & 0xf0f0f0f0f0f0f0f0L) >>> 4) | ((x3 & 0x0f0f0f0f0f0f0f0fL) << 4);

            x6 = ((x6 & 0xf0f0f0f0f0f0f0f0L) >>> 4) | ((x6 & 0x0f0f0f0f0f0f0f0fL) << 4);
            x7 = ((x7 & 0xf0f0f0f0f0f0f0f0L) >>> 4) | ((x7 & 0x0f0f0f0f0f0f0f0fL) << 4);

            x10 = ((x10 & 0xf0f0f0f0f0f0f0f0L) >>> 4) | ((x10 & 0x0f0f0f0f0f0f0f0fL) << 4);
            x11 = ((x11 & 0xf0f0f0f0f0f0f0f0L) >>> 4) | ((x10 & 0x0f0f0f0f0f0f0f0fL) << 4);

            x14 = ((x14 & 0xf0f0f0f0f0f0f0f0L) >>> 4) | ((x14 & 0x0f0f0f0f0f0f0f0fL) << 4);
            x15 = ((x15 & 0xf0f0f0f0f0f0f0f0L) >>> 4) | ((x15 & 0x0f0f0f0f0f0f0f0fL) << 4);

            t = C0[r + 3];

            x12 = ~x12;
            x0 ^= t & ~x8;
            t ^= x0 & x4;
            x0 ^= x8 & x12;
            x12 ^= ~x4 & x8;
            x4 ^= x0 & x8;
            x8 ^= x0 & ~x12;
            x0 ^= x4 | x12;
            x12 ^= x4 & x8;
            x4 ^= t & x0;
            x8 ^= t;

            t = C1[r + 3];

            x13 = ~x13;
            x1 ^= t & ~x9;
            t ^= x1 & x5;
            x1 ^= x9 & x13;
            x13 ^= ~x5 & x9;
            x5 ^= x1 & x9;
            x9 ^= x1 & ~x13;
            x1 ^= x5 | x13;
            x13 ^= x5 & x9;
            x5 ^= t & x1;
            x9 ^= t;

            t = C2[r + 3];

            x14 = ~x14;
            x2 ^= t & ~x10;
            t ^= x2 & x6;
            x2 ^= x10 & x14;
            x14 ^= ~x6 & x10;
            x6 ^= x2 & x10;
            x10 ^= x2 & ~x14;
            x2 ^= x6 | x14;
            x14 ^= x6 & x10;
            x6 ^= t & x2;
            x10 ^= t;

            t = C3[r + 3];

            x15 = ~x15;
            x3 ^= t & ~x11;
            t ^= x3 & x7;
            x3 ^= x11 & x15;
            x15 ^= ~x7 & x11;
            x7 ^= x3 & x11;
            x11 ^= x3 & ~x15;
            x3 ^= x7 | x15;
            x15 ^= x7 & x11;
            x7 ^= t & x3;
            x11 ^= t;

            x2 ^= x4;
            x6 ^= x8;
            x10 ^= x12 ^ x0;
            x14 ^= x0;
            x0 ^= x6;
            x2 ^= x10;
            x8 ^= x14 ^ x2;
            x12 ^= x2;

            x3 ^= x5;
            x7 ^= x9;
            x11 ^= x13 ^ x1;
            x15 ^= x1;
            x1 ^= x7;
            x3 ^= x11;
            x9 ^= x15 ^ x3;
            x13 ^= x3;

            x2 = ((x2 & 0xff00ff00ff00ff00L) >>> 8) | ((x2 & 0x00ff00ff00ff00ffL) << 8);
            x3 = ((x3 & 0xff00ff00ff00ff00L) >>> 8) | ((x3 & 0x00ff00ff00ff00ffL) << 8);

            x6 = ((x6 & 0xff00ff00ff00ff00L) >>> 8) | ((x6 & 0x00ff00ff00ff00ffL) << 8);
            x7 = ((x7 & 0xff00ff00ff00ff00L) >>> 8) | ((x7 & 0x00ff00ff00ff00ffL) << 8);

            x10 = ((x10 & 0xff00ff00ff00ff00L) >>> 8) | ((x10 & 0x00ff00ff00ff00ffL) << 8);
            x11 = ((x11 & 0xff00ff00ff00ff00L) >>> 8) | ((x10 & 0x00ff00ff00ff00ffL) << 8);

            x14 = ((x14 & 0xff00ff00ff00ff00L) >>> 8) | ((x14 & 0x00ff00ff00ff00ffL) << 8);
            x15 = ((x15 & 0xff00ff00ff00ff00L) >>> 8) | ((x15 & 0x00ff00ff00ff00ffL) << 8);

            t = C0[r + 4];

            x12 = ~x12;
            x0 ^= t & ~x8;
            t ^= x0 & x4;
            x0 ^= x8 & x12;
            x12 ^= ~x4 & x8;
            x4 ^= x0 & x8;
            x8 ^= x0 & ~x12;
            x0 ^= x4 | x12;
            x12 ^= x4 & x8;
            x4 ^= t & x0;
            x8 ^= t;

            t = C1[r + 4];

            x13 = ~x13;
            x1 ^= t & ~x9;
            t ^= x1 & x5;
            x1 ^= x9 & x13;
            x13 ^= ~x5 & x9;
            x5 ^= x1 & x9;
            x9 ^= x1 & ~x13;
            x1 ^= x5 | x13;
            x13 ^= x5 & x9;
            x5 ^= t & x1;
            x9 ^= t;

            t = C2[r + 4];

            x14 = ~x14;
            x2 ^= t & ~x10;
            t ^= x2 & x6;
            x2 ^= x10 & x14;
            x14 ^= ~x6 & x10;
            x6 ^= x2 & x10;
            x10 ^= x2 & ~x14;
            x2 ^= x6 | x14;
            x14 ^= x6 & x10;
            x6 ^= t & x2;
            x10 ^= t;

            t = C3[r + 4];

            x15 = ~x15;
            x3 ^= t & ~x11;
            t ^= x3 & x7;
            x3 ^= x11 & x15;
            x15 ^= ~x7 & x11;
            x7 ^= x3 & x11;
            x11 ^= x3 & ~x15;
            x3 ^= x7 | x15;
            x15 ^= x7 & x11;
            x7 ^= t & x3;
            x11 ^= t;

            x2 ^= x4;
            x6 ^= x8;
            x10 ^= x12 ^ x0;
            x14 ^= x0;
            x0 ^= x6;
            x2 ^= x10;
            x8 ^= x14 ^ x2;
            x12 ^= x2;

            x3 ^= x5;
            x7 ^= x9;
            x11 ^= x13 ^ x1;
            x15 ^= x1;
            x1 ^= x7;
            x3 ^= x11;
            x9 ^= x15 ^ x3;
            x13 ^= x3;

            x2 = ((x2 & 0xffff0000ffff0000L) >>> 16) | ((x2 & 0x0000ffff0000ffffL) << 16);
            x3 = ((x3 & 0xffff0000ffff0000L) >>> 16) | ((x3 & 0x0000ffff0000ffffL) << 16);

            x6 = ((x6 & 0xffff0000ffff0000L) >>> 16) | ((x6 & 0x0000ffff0000ffffL) << 16);
            x7 = ((x7 & 0xffff0000ffff0000L) >>> 16) | ((x7 & 0x0000ffff0000ffffL) << 16);

            x10 = ((x10 & 0xffff0000ffff0000L) >>> 16) | ((x10 & 0x0000ffff0000ffffL) << 16);
            x11 = ((x11 & 0xffff0000ffff0000L) >>> 16) | ((x10 & 0x0000ffff0000ffffL) << 16);

            x14 = ((x14 & 0xffff0000ffff0000L) >>> 16) | ((x14 & 0x0000ffff0000ffffL) << 16);
            x15 = ((x15 & 0xffff0000ffff0000L) >>> 16) | ((x15 & 0x0000ffff0000ffffL) << 16);

            t = C0[r + 5];

            x12 = ~x12;
            x0 ^= t & ~x8;
            t ^= x0 & x4;
            x0 ^= x8 & x12;
            x12 ^= ~x4 & x8;
            x4 ^= x0 & x8;
            x8 ^= x0 & ~x12;
            x0 ^= x4 | x12;
            x12 ^= x4 & x8;
            x4 ^= t & x0;
            x8 ^= t;

            t = C1[r + 5];

            x13 = ~x13;
            x1 ^= t & ~x9;
            t ^= x1 & x5;
            x1 ^= x9 & x13;
            x13 ^= ~x5 & x9;
            x5 ^= x1 & x9;
            x9 ^= x1 & ~x13;
            x1 ^= x5 | x13;
            x13 ^= x5 & x9;
            x5 ^= t & x1;
            x9 ^= t;

            t = C2[r + 5];

            x14 = ~x14;
            x2 ^= t & ~x10;
            t ^= x2 & x6;
            x2 ^= x10 & x14;
            x14 ^= ~x6 & x10;
            x6 ^= x2 & x10;
            x10 ^= x2 & ~x14;
            x2 ^= x6 | x14;
            x14 ^= x6 & x10;
            x6 ^= t & x2;
            x10 ^= t;

            t = C3[r + 5];

            x15 = ~x15;
            x3 ^= t & ~x11;
            t ^= x3 & x7;
            x3 ^= x11 & x15;
            x15 ^= ~x7 & x11;
            x7 ^= x3 & x11;
            x11 ^= x3 & ~x15;
            x3 ^= x7 | x15;
            x15 ^= x7 & x11;
            x7 ^= t & x3;
            x11 ^= t;

            x2 ^= x4;
            x6 ^= x8;
            x10 ^= x12 ^ x0;
            x14 ^= x0;
            x0 ^= x6;
            x2 ^= x10;
            x8 ^= x14 ^ x2;
            x12 ^= x2;

            x3 ^= x5;
            x7 ^= x9;
            x11 ^= x13 ^ x1;
            x15 ^= x1;
            x1 ^= x7;
            x3 ^= x11;
            x9 ^= x15 ^ x3;
            x13 ^= x3;

            x2 = (x2 >>> 32) | (x2 << 32);
            x3 = (x3 >>> 32) | (x3 << 32);

            x6 = (x6 >>> 32) | (x6 << 32);
            x7 = (x7 >>> 32) | (x7 << 32);

            x10 = (x10 >>> 32) | (x10 << 32);
            x11 = (x11 >>> 32) | (x10 << 32);

            x14 = (x14 >>> 32) | (x14 << 32);
            x15 = (x15 >>> 32) | (x15 << 32);

            t = C0[r + 6];

            x12 = ~x12;
            x0 ^= t & ~x8;
            t ^= x0 & x4;
            x0 ^= x8 & x12;
            x12 ^= ~x4 & x8;
            x4 ^= x0 & x8;
            x8 ^= x0 & ~x12;
            x0 ^= x4 | x12;
            x12 ^= x4 & x8;
            x4 ^= t & x0;
            x8 ^= t;

            t = C1[r + 6];

            x13 = ~x13;
            x1 ^= t & ~x9;
            t ^= x1 & x5;
            x1 ^= x9 & x13;
            x13 ^= ~x5 & x9;
            x5 ^= x1 & x9;
            x9 ^= x1 & ~x13;
            x1 ^= x5 | x13;
            x13 ^= x5 & x9;
            x5 ^= t & x1;
            x9 ^= t;

            t = C2[r + 6];

            x14 = ~x14;
            x2 ^= t & ~x10;
            t ^= x2 & x6;
            x2 ^= x10 & x14;
            x14 ^= ~x6 & x10;
            x6 ^= x2 & x10;
            x10 ^= x2 & ~x14;
            x2 ^= x6 | x14;
            x14 ^= x6 & x10;
            x6 ^= t & x2;
            x10 ^= t;

            t = C3[r + 6];

            x15 = ~x15;
            x3 ^= t & ~x11;
            t ^= x3 & x7;
            x3 ^= x11 & x15;
            x15 ^= ~x7 & x11;
            x7 ^= x3 & x11;
            x11 ^= x3 & ~x15;
            x3 ^= x7 | x15;
            x15 ^= x7 & x11;
            x7 ^= t & x3;
            x11 ^= t;

            x2 ^= x4;
            x6 ^= x8;
            x10 ^= x12 ^ x0;
            x14 ^= x0;
            x0 ^= x6;
            x2 ^= x10;
            x8 ^= x14 ^ x2;
            x12 ^= x2;

            x3 ^= x5;
            x7 ^= x9;
            x11 ^= x13 ^ x1;
            x15 ^= x1;
            x1 ^= x7;
            x3 ^= x11;
            x9 ^= x15 ^ x3;
            x13 ^= x3;

            t = x2;
            x2 = x3;
            x3 = t;

            t = x6;
            x6 = x7;
            x7 = t;

            t = x10;
            x10 = x11;
            x11 = t;

            t = x14;
            x14 = x15;
            x15 = t;
        }

        state[0] = x0;
        state[1] = x1;
        state[2] = x2;
        state[3] = x3;
        state[4] = x4;
        state[5] = x5;
        state[6] = x6;
        state[7] = x7;

        state[8] = x8 ^ data[0];
        state[9] = x9 ^ data[1];
        state[10] = x10 ^ data[2];
        state[11] = x11 ^ data[3];
        state[12] = x12 ^ data[4];
        state[13] = x13 ^ data[5];
        state[14] = x14 ^ data[6];
        state[15] = x15 ^ data[7];
    }

    @Override
    public int blockSize() {
        return 64;
    }

    private abstract static class JhEngine extends AbstractDigestEngine {

        protected final long[] state;
        private final long[] data = new long[8];
        private long counter = 0;

        private JhEngine(long[] state) {
            super(64);
            this.state = state;
        }

        @Override
        protected void ingestOneBlock(MemorySegment input, long offset) {
            data[0] = input.get(LAYOUT, offset + 0);
            data[1] = input.get(LAYOUT, offset + 8);
            data[2] = input.get(LAYOUT, offset + 16);
            data[3] = input.get(LAYOUT, offset + 24);
            data[4] = input.get(LAYOUT, offset + 32);
            data[5] = input.get(LAYOUT, offset + 40);
            data[6] = input.get(LAYOUT, offset + 48);
            data[7] = input.get(LAYOUT, offset + 56);
            compress(state, data);

            counter += 64;
        }

        @Override
        protected void ingestLastBlock(MemorySegment input, int length) {
            if (length == 64) {
                ingestOneBlock(input, 0);
                length = 0;
            }
            Tools.ozpad(input, length);
            data[0] = input.get(LAYOUT, 0);
            data[1] = input.get(LAYOUT, 8);
            data[2] = input.get(LAYOUT, 16);
            data[3] = input.get(LAYOUT, 24);
            data[4] = input.get(LAYOUT, 32);
            data[5] = input.get(LAYOUT, 40);
            data[6] = 0;
            data[7] = counter + length;
            compress(state, data);
        }

    }

}
