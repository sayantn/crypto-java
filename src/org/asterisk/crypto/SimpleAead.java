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
package org.asterisk.crypto;

import java.lang.foreign.MemorySegment;
import javax.crypto.AEADBadTagException;

/**
 *
 * @author Sayantan Chakraborty
 */
public interface SimpleAead {

    default int encrypt(byte[] key, byte[] iv, byte[] aad, byte[] plaintext, byte[] ciphertext, byte[] tag) {
        return (int) encrypt(key, iv, MemorySegment.ofArray(aad), MemorySegment.ofArray(plaintext), MemorySegment.ofArray(ciphertext), tag, 0, tagLength());
    }

    default int decrypt(byte[] key, byte[] iv, byte[] aad, byte[] ciphertext, byte[] plaintext, byte[] tag) throws AEADBadTagException {
        return (int) decrypt(key, iv, MemorySegment.ofArray(aad), MemorySegment.ofArray(ciphertext), MemorySegment.ofArray(plaintext), tag, 0, tagLength());
    }

    long encrypt(byte[] key, byte[] iv, MemorySegment aad, MemorySegment plaintext, MemorySegment ciphertext, byte[] tag, int tOffset, int tLength);

    long decrypt(byte[] key, byte[] iv, MemorySegment aad, MemorySegment ciphertext, MemorySegment plaintext, byte[] tag, int tOffset, int tLength) throws AEADBadTagException;

    int keyLength();

    int ivLength();

    int tagLength();

}
