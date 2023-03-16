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

/**
 * This package and its subpackages contains very efficient pure-Java
 * implementations of some secure cryptographic algorithms.
 * The implementations are focused on speed. Unlike many other crypto libraries,
 * they don't use byte[] to represent binary data.
 * They use the classes in {@link java.lang.foreign} package. What these classes
 * have is
 * <ul>
 * <li>The capability to represent arbitrary data, even data that is not native
 * to this JVM. Using {@link java.nio.channels.FileChannel FileChannels}
 * one can also represent disk-residing data in these types. This gives a huge
 * amount of flexibility to users, without compromising
 * the major use case in-memory byte[] sequences (using
 * {@link java.lang.foreign.MemorySegment#ofArray(byte[])}).</li>
 * <li>These facilitate very fast loading to and unloading from 32- and 64- bit
 * words, which is very useful for crypto implementations</li>
 * <li>Java byte[] type is not like slices in other languages, so to minimize
 * copying, we often carry around offset and length fields
 * with the array itself. This is much easier with MemorySegments, which have
 * the {@link java.lang.foreign.MemorySegment#asSlice(long, long) asSlice}
 * method.</li>
 * <li>They can represent sequences that are too big to be held by a byte[].
 * They can have as much as Long.MAX_VALUE bytes of content.
 * which is around 8 exabytes of data, so this is pretty future-proof</li>
 * </ul>
 * <p>
 * The main interface classes define the contract of using them(i.e. the order
 * in which certain method calls must appear). But
 * the method names are pretty self-explanatory. The actual implementation
 * classes contain little-to-no documentation, only
 * highlighting the source of the algorithm
 */
package org.asterisk.crypto;
