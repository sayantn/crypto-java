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
import org.asterisk.crypto.interfaces.Digest;

import static org.asterisk.crypto.helper.Tools.store64BE;
import static org.asterisk.crypto.lowlevel.AsconP.ascon_p;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum AsconHash implements Digest {

    ASCON_HASH {
        @Override
        public Engine start() {
            return new AbstractDigestEngine(8) {

                private final long[] state = {
                    0xee9398aadb67f03dL,
                    0x8bb21831c60f1002L,
                    0xb48a92db98d5da62L,
                    0x43189921b8f8e3e8L,
                    0x348fa5c9d525e140L
                };

                @Override
                protected void ingestOneBlock(MemorySegment input, long offset) {
                    state[0] ^= input.get(LAYOUT, offset);
                    ascon_p(state, 12);
                }

                @Override
                protected void ingestLastBlock(MemorySegment input, int length) {
                    if (length == 8) {
                        ingestOneBlock(input, length);
                        length = 0;
                    }
                    Tools.ozpad(input, length);
                    state[0] ^= input.get(LAYOUT, 0);
                }

                @Override
                protected void getDigest(byte[] output, int offset) {
                    ascon_p(state, 12);
                    store64BE(state[0], output, offset + 0);
                    ascon_p(state, 12);
                    store64BE(state[1], output, offset + 8);
                    ascon_p(state, 12);
                    store64BE(state[2], output, offset + 16);
                    ascon_p(state, 12);
                    store64BE(state[3], output, offset + 24);
                }

                @Override
                public Digest getAlgorithm() {
                    return ASCON_HASH;
                }
            };
        }

    }, ASCON_HASHa {
        @Override
        public Engine start() {
            return new AbstractDigestEngine(8) {

                private final long[] state = {
                    0x01470194fc6528a6L,
                    0x738ec38ac0adffa7L,
                    0x2ec8e3296c76384cL,
                    0xd6f6a54d7f52377dL,
                    0xa13c42a223be8d87L
                };

                @Override
                protected void ingestOneBlock(MemorySegment input, long offset) {
                    state[0] ^= input.get(LAYOUT, offset);
                    ascon_p(state, 8);
                }

                @Override
                protected void ingestLastBlock(MemorySegment input, int length) {
                    if (length == 8) {
                        ingestOneBlock(input, length);
                        length = 0;
                    }
                    Tools.ozpad(input, length);
                    state[0] ^= input.get(LAYOUT, 0);
                }

                @Override
                protected void getDigest(byte[] output, int offset) {
                    ascon_p(state, 12);
                    store64BE(state[0], output, offset + 0);
                    ascon_p(state, 12);
                    store64BE(state[1], output, offset + 8);
                    ascon_p(state, 12);
                    store64BE(state[2], output, offset + 16);
                    ascon_p(state, 12);
                    store64BE(state[3], output, offset + 24);
                }

                @Override
                public Digest getAlgorithm() {
                    return ASCON_HASHa;
                }
            };
        }

    };

    private static final ValueLayout.OfLong LAYOUT = Tools.BIG_ENDIAN_64_BIT;

    @Override
    public int digestSize() {
        return 32;
    }

    @Override
    public int blockSize() {
        return 8;
    }

}
