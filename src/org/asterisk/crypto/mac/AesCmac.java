/*
 * Copyright (C) 2022 Sayantan Chakraborty
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
package org.asterisk.crypto.mac;

import java.lang.foreign.MemorySegment;
import java.util.function.Function;
import org.asterisk.crypto.helper.GfHelper;
import org.asterisk.crypto.helper.AbstractMacEngine;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.interfaces.Mac;
import org.asterisk.crypto.lowlevel.AesEncApi;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum AesCmac implements Mac {

    AES_128_CMAC(AesEncApi.Aes128EncApi::new) {
        @Override
        public int keyLength() {
            return 16;
        }

    }, AES_192_CMAC(AesEncApi.Aes192EncApi::new) {
        @Override
        public int keyLength() {
            return 24;
        }

    }, AES_256_CMAC(AesEncApi.Aes256EncApi::new) {
        @Override
        public int keyLength() {
            return 32;
        }

    };

    private final Function<byte[], AesEncApi> constructor;

    private AesCmac(Function<byte[], AesEncApi> constructor) {
        this.constructor = constructor;
    }

    @Override
    public Engine start(byte[] key) {
        return new AbstractMacEngine(16) {

            private final int[] checksum = new int[4], xorKey = {
                Tools.load32BE(key, 0), Tools.load32BE(key, 4), Tools.load32BE(key, 8), Tools.load32BE(key, 12)
            };

            private final AesEncApi aes = constructor.apply(key);

            {
                GfHelper.x2(xorKey);
            }

            @Override
            protected void ingestOneBlock(MemorySegment input, long offset) {
                checksum[0] ^= input.get(Tools.BIG_ENDIAN_32_BIT, offset + 0);
                checksum[1] ^= input.get(Tools.BIG_ENDIAN_32_BIT, offset + 4);
                checksum[2] ^= input.get(Tools.BIG_ENDIAN_32_BIT, offset + 8);
                checksum[3] ^= input.get(Tools.BIG_ENDIAN_32_BIT, offset + 12);

                aes.encryptBlock(checksum, 0, checksum, 0);

            }

            @Override
            protected void ingestLastBlock(MemorySegment input, int length) {
                if (length != 16) {
                    Tools.ozpad(input, length);
                    GfHelper.x2(xorKey);
                }

                checksum[0] ^= input.get(Tools.BIG_ENDIAN_32_BIT, 0) ^ xorKey[0];
                checksum[1] ^= input.get(Tools.BIG_ENDIAN_32_BIT, 4) ^ xorKey[1];
                checksum[2] ^= input.get(Tools.BIG_ENDIAN_32_BIT, 8) ^ xorKey[2];
                checksum[3] ^= input.get(Tools.BIG_ENDIAN_32_BIT, 12) ^ xorKey[3];

                aes.encryptBlock(checksum, 0, checksum, 0);

            }

            @Override
            protected void getTag(byte[] buffer) {
                Tools.store32BE(checksum[0], buffer, 0);
                Tools.store32BE(checksum[1], buffer, 4);
                Tools.store32BE(checksum[2], buffer, 8);
                Tools.store32BE(checksum[3], buffer, 12);

            }

            @Override
            public Mac getAlgorithm() {
                return AesCmac.this;
            }
        };
    }

    @Override
    public int tagLength() {
        return 16;
    }

}
