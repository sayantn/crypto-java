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
import java.nio.ByteBuffer;
import org.asterisk.crypto.interfaces.Digest;
import org.asterisk.crypto.interfaces.Mac;

/**
 *
 * @author Sayantan Chakraborty
 */
public class Hmac implements Mac {

    public static Hmac hmac(Digest hash) {
        return new Hmac(hash);
    }

    private final Digest hash;

    private Hmac(Digest hash) {
        this.hash = hash;
    }

    @Override
    public Engine start(byte[] key) {
        int len = key.length;
        byte[] k = new byte[hash.blockSize()];

        if (len != k.length) {
            var eng = hash.start();
            eng.ingest(key);
            eng.digestTo(k);
            len = hash.digestSize();

            while (len < k.length) {
                k[len++] = 0;
            }
        } else {
            System.arraycopy(key, 0, k, 0, len);
        }

        return new Engine() {

            private final Digest.Engine inner = hash.start();

            {
                for (int i = 0; i < k.length; i++) {
                    k[i] ^= 0x36;
                }
                inner.ingest(k);
            }

            @Override
            public void authenticateTo(byte[] tag, int offset, int length) {
                byte[] temp = new byte[hash.digestSize()];
                inner.digestTo(temp);
                var outer = hash.start();
                for (int i = 0; i < k.length; i++) {
                    k[i] ^= 0x6a;
                }
                outer.ingest(k);
                outer.ingest(temp);
                outer.digestTo(temp);

                System.arraycopy(temp, 0, tag, offset, length);
            }

            @Override
            public Mac getAlgorithm() {
                return Hmac.this;
            }

            @Override
            public void ingest(MemorySegment input) {
                inner.ingest(input);
            }

            @Override
            public void ingest(byte[] input, int offset, int length) {
                inner.ingest(input, offset, length);
            }

            @Override
            public void ingest(byte[] input) {
                inner.ingest(input);
            }

            @Override
            public void ingest(ByteBuffer buffer) {
                inner.ingest(buffer);
            }
        };
    }

    @Override
    public int tagLength() {
        return hash.digestSize();
    }

    @Override
    public int keyLength() {
        return hash.blockSize();
    }

}
