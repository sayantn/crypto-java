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
import org.asterisk.crypto.helper.AbstractXofEngine;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.interfaces.Xof;

import static org.asterisk.crypto.helper.Tools.store64BE;
import static org.asterisk.crypto.lowlevel.AsconP.ascon_p;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum AsconXof implements Xof {

    ASCON_XOF {
        @Override
        public Engine start() {
            return new AbstractXofEngine(8, 8) {

                private final long[] state = {
                    0xb57e273b814cd415L,
                    0x2b51042562ae2420L,
                    0x66a3a7768ddf2218L,
                    0x5aad0a7a8153650cL,
                    0x4f3e0e32539493b6L
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
                protected void digestOneBlock(byte[] output, int offset) {
                    ascon_p(state, 12);
                    store64BE(state[0], output, offset);
                }

                @Override
                public Xof getAlgorithm() {
                    return ASCON_XOF;
                }

            };
        }

    }, ASCON_XOFa {
        @Override
        public Engine start() {
            return new AbstractXofEngine(8, 8) {

                private final long[] state = {
                    0x44906568b77b9832L,
                    0xcd8d6cae53455532L,
                    0xf7b5212756422129L,
                    0x246885e1de0d225bL,
                    0xa8cd5ce33449973fL
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
                protected void digestOneBlock(byte[] output, int offset) {
                    ascon_p(state, 12);
                    store64BE(state[0], output, offset);
                }

                @Override
                public Xof getAlgorithm() {
                    return ASCON_XOFa;
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
