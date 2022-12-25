/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.stream;

import java.lang.foreign.MemorySegment;
import org.asterisk.crypto.helper.AbstractStreamEncrypter;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.interfaces.Cipher;
import org.asterisk.crypto.interfaces.StreamCipher;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum Zuc implements StreamCipher {

    ZUC;

    private static final int[] S0 = {
        0x3e000000, 0x72000000, 0x5b000000, 0x47000000, 0xca000000, 0xe0000000, 0x00000000, 0x33000000,
        0x04000000, 0xd1000000, 0x54000000, 0x98000000, 0x09000000, 0xb9000000, 0x6d000000, 0xcb000000,
        0x7b000000, 0x1b000000, 0xf9000000, 0x32000000, 0xaf000000, 0x9d000000, 0x6a000000, 0xa5000000,
        0xb8000000, 0x2d000000, 0xfc000000, 0x1d000000, 0x08000000, 0x53000000, 0x03000000, 0x90000000,
        0x4d000000, 0x4e000000, 0x84000000, 0x99000000, 0xe4000000, 0xce000000, 0xd9000000, 0x91000000,
        0xdd000000, 0xb6000000, 0x85000000, 0x48000000, 0x8b000000, 0x29000000, 0x6e000000, 0xac000000,
        0xcd000000, 0xc1000000, 0xf8000000, 0x1e000000, 0x73000000, 0x43000000, 0x69000000, 0xc6000000,
        0xb5000000, 0xbd000000, 0xfd000000, 0x39000000, 0x63000000, 0x20000000, 0xd4000000, 0x38000000,
        0x76000000, 0x7d000000, 0xb2000000, 0xa7000000, 0xcf000000, 0xed000000, 0x57000000, 0xc5000000,
        0xf3000000, 0x2c000000, 0xbb000000, 0x14000000, 0x21000000, 0x06000000, 0x55000000, 0x9b000000,
        0xe3000000, 0xef000000, 0x5e000000, 0x31000000, 0x4f000000, 0x7f000000, 0x5a000000, 0xa4000000,
        0x0d000000, 0x82000000, 0x51000000, 0x49000000, 0x5f000000, 0xba000000, 0x58000000, 0x1c000000,
        0x4a000000, 0x16000000, 0xd5000000, 0x17000000, 0xa8000000, 0x92000000, 0x24000000, 0x1f000000,
        0x8c000000, 0xff000000, 0xd8000000, 0xae000000, 0x2e000000, 0x01000000, 0xd3000000, 0xad000000,
        0x3b000000, 0x4b000000, 0xda000000, 0x46000000, 0xeb000000, 0xc9000000, 0xde000000, 0x9a000000,
        0x8f000000, 0x87000000, 0xd7000000, 0x3a000000, 0x80000000, 0x6f000000, 0x2f000000, 0xc8000000,
        0xb1000000, 0xb4000000, 0x37000000, 0xf7000000, 0x0a000000, 0x22000000, 0x13000000, 0x28000000,
        0x7c000000, 0xcc000000, 0x3c000000, 0x89000000, 0xc7000000, 0xc3000000, 0x96000000, 0x56000000,
        0x07000000, 0xbf000000, 0x7e000000, 0xf0000000, 0x0b000000, 0x2b000000, 0x97000000, 0x52000000,
        0x35000000, 0x41000000, 0x79000000, 0x61000000, 0xa6000000, 0x4c000000, 0x10000000, 0xfe000000,
        0xbc000000, 0x26000000, 0x95000000, 0x88000000, 0x8a000000, 0xb0000000, 0xa3000000, 0xfb000000,
        0xc0000000, 0x18000000, 0x94000000, 0xf2000000, 0xe1000000, 0xe5000000, 0xe9000000, 0x5d000000,
        0xd0000000, 0xdc000000, 0x11000000, 0x66000000, 0x64000000, 0x5c000000, 0xec000000, 0x59000000,
        0x42000000, 0x75000000, 0x12000000, 0xf5000000, 0x74000000, 0x9c000000, 0xaa000000, 0x23000000,
        0x0e000000, 0x86000000, 0xab000000, 0xbe000000, 0x2a000000, 0x02000000, 0xe7000000, 0x67000000,
        0xe6000000, 0x44000000, 0xa2000000, 0x6c000000, 0xc2000000, 0x93000000, 0x9f000000, 0xf1000000,
        0xf6000000, 0xfa000000, 0x36000000, 0xd2000000, 0x50000000, 0x68000000, 0x9e000000, 0x62000000,
        0x71000000, 0x15000000, 0x3d000000, 0xd6000000, 0x40000000, 0xc4000000, 0xe2000000, 0x0f000000,
        0x8e000000, 0x83000000, 0x77000000, 0x6b000000, 0x25000000, 0x05000000, 0x3f000000, 0x0c000000,
        0x30000000, 0xea000000, 0x70000000, 0xb7000000, 0xa1000000, 0xe8000000, 0xa9000000, 0x65000000,
        0x8d000000, 0x27000000, 0x1a000000, 0xdb000000, 0x81000000, 0xb3000000, 0xa0000000, 0xf4000000,
        0x45000000, 0x7a000000, 0x19000000, 0xdf000000, 0xee000000, 0x78000000, 0x34000000, 0x60000000
    }, S1 = {
        0x00550000, 0x00c20000, 0x00630000, 0x00710000, 0x003b0000, 0x00c80000, 0x00470000, 0x00860000,
        0x009f0000, 0x003c0000, 0x00da0000, 0x005b0000, 0x00290000, 0x00aa0000, 0x00fd0000, 0x00770000,
        0x008c0000, 0x00c50000, 0x00940000, 0x000c0000, 0x00a60000, 0x001a0000, 0x00130000, 0x00000000,
        0x00e30000, 0x00a80000, 0x00160000, 0x00720000, 0x00400000, 0x00f90000, 0x00f80000, 0x00420000,
        0x00440000, 0x00260000, 0x00680000, 0x00960000, 0x00810000, 0x00d90000, 0x00450000, 0x003e0000,
        0x00100000, 0x00760000, 0x00c60000, 0x00a70000, 0x008b0000, 0x00390000, 0x00430000, 0x00e10000,
        0x003a0000, 0x00b50000, 0x00560000, 0x002a0000, 0x00c00000, 0x006d0000, 0x00b30000, 0x00050000,
        0x00220000, 0x00660000, 0x00bf0000, 0x00dc0000, 0x000b0000, 0x00fa0000, 0x00620000, 0x00480000,
        0x00dd0000, 0x00200000, 0x00110000, 0x00060000, 0x00360000, 0x00c90000, 0x00c10000, 0x00cf0000,
        0x00f60000, 0x00270000, 0x00520000, 0x00bb0000, 0x00690000, 0x00f50000, 0x00d40000, 0x00870000,
        0x007f0000, 0x00840000, 0x004c0000, 0x00d20000, 0x009c0000, 0x00570000, 0x00a40000, 0x00bc0000,
        0x004f0000, 0x009a0000, 0x00df0000, 0x00fe0000, 0x00d60000, 0x008d0000, 0x007a0000, 0x00eb0000,
        0x002b0000, 0x00530000, 0x00d80000, 0x005c0000, 0x00a10000, 0x00140000, 0x00170000, 0x00fb0000,
        0x00230000, 0x00d50000, 0x007d0000, 0x00300000, 0x00670000, 0x00730000, 0x00080000, 0x00090000,
        0x00ee0000, 0x00b70000, 0x00700000, 0x003f0000, 0x00610000, 0x00b20000, 0x00190000, 0x008e0000,
        0x004e0000, 0x00e50000, 0x004b0000, 0x00930000, 0x008f0000, 0x005d0000, 0x00db0000, 0x00a90000,
        0x00ad0000, 0x00f10000, 0x00ae0000, 0x002e0000, 0x00cb0000, 0x000d0000, 0x00fc0000, 0x00f40000,
        0x002d0000, 0x00460000, 0x006e0000, 0x001d0000, 0x00970000, 0x00e80000, 0x00d10000, 0x00e90000,
        0x004d0000, 0x00370000, 0x00a50000, 0x00750000, 0x005e0000, 0x00830000, 0x009e0000, 0x00ab0000,
        0x00820000, 0x009d0000, 0x00b90000, 0x001c0000, 0x00e00000, 0x00cd0000, 0x00490000, 0x00890000,
        0x00010000, 0x00b60000, 0x00bd0000, 0x00580000, 0x00240000, 0x00a20000, 0x005f0000, 0x00380000,
        0x00780000, 0x00990000, 0x00150000, 0x00900000, 0x00500000, 0x00b80000, 0x00950000, 0x00e40000,
        0x00d00000, 0x00910000, 0x00c70000, 0x00ce0000, 0x00ed0000, 0x000f0000, 0x00b40000, 0x006f0000,
        0x00a00000, 0x00cc0000, 0x00f00000, 0x00020000, 0x004a0000, 0x00790000, 0x00c30000, 0x00de0000,
        0x00a30000, 0x00ef0000, 0x00ea0000, 0x00510000, 0x00e60000, 0x006b0000, 0x00180000, 0x00ec0000,
        0x001b0000, 0x002c0000, 0x00800000, 0x00f70000, 0x00740000, 0x00e70000, 0x00ff0000, 0x00210000,
        0x005a0000, 0x006a0000, 0x00540000, 0x001e0000, 0x00410000, 0x00310000, 0x00920000, 0x00350000,
        0x00c40000, 0x00330000, 0x00070000, 0x000a0000, 0x00ba0000, 0x007e0000, 0x000e0000, 0x00340000,
        0x00880000, 0x00b10000, 0x00980000, 0x007c0000, 0x00f30000, 0x003d0000, 0x00600000, 0x006c0000,
        0x007b0000, 0x00ca0000, 0x00d30000, 0x001f0000, 0x00320000, 0x00650000, 0x00040000, 0x00280000,
        0x00640000, 0x00be0000, 0x00850000, 0x009b0000, 0x002f0000, 0x00590000, 0x008a0000, 0x00d70000,
        0x00b00000, 0x00250000, 0x00ac0000, 0x00af0000, 0x00120000, 0x00030000, 0x00e20000, 0x00f20000
    }, S2 = {
        0x00003e00, 0x00007200, 0x00005b00, 0x00004700, 0x0000ca00, 0x0000e000, 0x00000000, 0x00003300,
        0x00000400, 0x0000d100, 0x00005400, 0x00009800, 0x00000900, 0x0000b900, 0x00006d00, 0x0000cb00,
        0x00007b00, 0x00001b00, 0x0000f900, 0x00003200, 0x0000af00, 0x00009d00, 0x00006a00, 0x0000a500,
        0x0000b800, 0x00002d00, 0x0000fc00, 0x00001d00, 0x00000800, 0x00005300, 0x00000300, 0x00009000,
        0x00004d00, 0x00004e00, 0x00008400, 0x00009900, 0x0000e400, 0x0000ce00, 0x0000d900, 0x00009100,
        0x0000dd00, 0x0000b600, 0x00008500, 0x00004800, 0x00008b00, 0x00002900, 0x00006e00, 0x0000ac00,
        0x0000cd00, 0x0000c100, 0x0000f800, 0x00001e00, 0x00007300, 0x00004300, 0x00006900, 0x0000c600,
        0x0000b500, 0x0000bd00, 0x0000fd00, 0x00003900, 0x00006300, 0x00002000, 0x0000d400, 0x00003800,
        0x00007600, 0x00007d00, 0x0000b200, 0x0000a700, 0x0000cf00, 0x0000ed00, 0x00005700, 0x0000c500,
        0x0000f300, 0x00002c00, 0x0000bb00, 0x00001400, 0x00002100, 0x00000600, 0x00005500, 0x00009b00,
        0x0000e300, 0x0000ef00, 0x00005e00, 0x00003100, 0x00004f00, 0x00007f00, 0x00005a00, 0x0000a400,
        0x00000d00, 0x00008200, 0x00005100, 0x00004900, 0x00005f00, 0x0000ba00, 0x00005800, 0x00001c00,
        0x00004a00, 0x00001600, 0x0000d500, 0x00001700, 0x0000a800, 0x00009200, 0x00002400, 0x00001f00,
        0x00008c00, 0x0000ff00, 0x0000d800, 0x0000ae00, 0x00002e00, 0x00000100, 0x0000d300, 0x0000ad00,
        0x00003b00, 0x00004b00, 0x0000da00, 0x00004600, 0x0000eb00, 0x0000c900, 0x0000de00, 0x00009a00,
        0x00008f00, 0x00008700, 0x0000d700, 0x00003a00, 0x00008000, 0x00006f00, 0x00002f00, 0x0000c800,
        0x0000b100, 0x0000b400, 0x00003700, 0x0000f700, 0x00000a00, 0x00002200, 0x00001300, 0x00002800,
        0x00007c00, 0x0000cc00, 0x00003c00, 0x00008900, 0x0000c700, 0x0000c300, 0x00009600, 0x00005600,
        0x00000700, 0x0000bf00, 0x00007e00, 0x0000f000, 0x00000b00, 0x00002b00, 0x00009700, 0x00005200,
        0x00003500, 0x00004100, 0x00007900, 0x00006100, 0x0000a600, 0x00004c00, 0x00001000, 0x0000fe00,
        0x0000bc00, 0x00002600, 0x00009500, 0x00008800, 0x00008a00, 0x0000b000, 0x0000a300, 0x0000fb00,
        0x0000c000, 0x00001800, 0x00009400, 0x0000f200, 0x0000e100, 0x0000e500, 0x0000e900, 0x00005d00,
        0x0000d000, 0x0000dc00, 0x00001100, 0x00006600, 0x00006400, 0x00005c00, 0x0000ec00, 0x00005900,
        0x00004200, 0x00007500, 0x00001200, 0x0000f500, 0x00007400, 0x00009c00, 0x0000aa00, 0x00002300,
        0x00000e00, 0x00008600, 0x0000ab00, 0x0000be00, 0x00002a00, 0x00000200, 0x0000e700, 0x00006700,
        0x0000e600, 0x00004400, 0x0000a200, 0x00006c00, 0x0000c200, 0x00009300, 0x00009f00, 0x0000f100,
        0x0000f600, 0x0000fa00, 0x00003600, 0x0000d200, 0x00005000, 0x00006800, 0x00009e00, 0x00006200,
        0x00007100, 0x00001500, 0x00003d00, 0x0000d600, 0x00004000, 0x0000c400, 0x0000e200, 0x00000f00,
        0x00008e00, 0x00008300, 0x00007700, 0x00006b00, 0x00002500, 0x00000500, 0x00003f00, 0x00000c00,
        0x00003000, 0x0000ea00, 0x00007000, 0x0000b700, 0x0000a100, 0x0000e800, 0x0000a900, 0x00006500,
        0x00008d00, 0x00002700, 0x00001a00, 0x0000db00, 0x00008100, 0x0000b300, 0x0000a000, 0x0000f400,
        0x00004500, 0x00007a00, 0x00001900, 0x0000df00, 0x0000ee00, 0x00007800, 0x00003400, 0x00006000
    }, S3 = {
        0x00000055, 0x000000c2, 0x00000063, 0x00000071, 0x0000003b, 0x000000c8, 0x00000047, 0x00000086,
        0x0000009f, 0x0000003c, 0x000000da, 0x0000005b, 0x00000029, 0x000000aa, 0x000000fd, 0x00000077,
        0x0000008c, 0x000000c5, 0x00000094, 0x0000000c, 0x000000a6, 0x0000001a, 0x00000013, 0x00000000,
        0x000000e3, 0x000000a8, 0x00000016, 0x00000072, 0x00000040, 0x000000f9, 0x000000f8, 0x00000042,
        0x00000044, 0x00000026, 0x00000068, 0x00000096, 0x00000081, 0x000000d9, 0x00000045, 0x0000003e,
        0x00000010, 0x00000076, 0x000000c6, 0x000000a7, 0x0000008b, 0x00000039, 0x00000043, 0x000000e1,
        0x0000003a, 0x000000b5, 0x00000056, 0x0000002a, 0x000000c0, 0x0000006d, 0x000000b3, 0x00000005,
        0x00000022, 0x00000066, 0x000000bf, 0x000000dc, 0x0000000b, 0x000000fa, 0x00000062, 0x00000048,
        0x000000dd, 0x00000020, 0x00000011, 0x00000006, 0x00000036, 0x000000c9, 0x000000c1, 0x000000cf,
        0x000000f6, 0x00000027, 0x00000052, 0x000000bb, 0x00000069, 0x000000f5, 0x000000d4, 0x00000087,
        0x0000007f, 0x00000084, 0x0000004c, 0x000000d2, 0x0000009c, 0x00000057, 0x000000a4, 0x000000bc,
        0x0000004f, 0x0000009a, 0x000000df, 0x000000fe, 0x000000d6, 0x0000008d, 0x0000007a, 0x000000eb,
        0x0000002b, 0x00000053, 0x000000d8, 0x0000005c, 0x000000a1, 0x00000014, 0x00000017, 0x000000fb,
        0x00000023, 0x000000d5, 0x0000007d, 0x00000030, 0x00000067, 0x00000073, 0x00000008, 0x00000009,
        0x000000ee, 0x000000b7, 0x00000070, 0x0000003f, 0x00000061, 0x000000b2, 0x00000019, 0x0000008e,
        0x0000004e, 0x000000e5, 0x0000004b, 0x00000093, 0x0000008f, 0x0000005d, 0x000000db, 0x000000a9,
        0x000000ad, 0x000000f1, 0x000000ae, 0x0000002e, 0x000000cb, 0x0000000d, 0x000000fc, 0x000000f4,
        0x0000002d, 0x00000046, 0x0000006e, 0x0000001d, 0x00000097, 0x000000e8, 0x000000d1, 0x000000e9,
        0x0000004d, 0x00000037, 0x000000a5, 0x00000075, 0x0000005e, 0x00000083, 0x0000009e, 0x000000ab,
        0x00000082, 0x0000009d, 0x000000b9, 0x0000001c, 0x000000e0, 0x000000cd, 0x00000049, 0x00000089,
        0x00000001, 0x000000b6, 0x000000bd, 0x00000058, 0x00000024, 0x000000a2, 0x0000005f, 0x00000038,
        0x00000078, 0x00000099, 0x00000015, 0x00000090, 0x00000050, 0x000000b8, 0x00000095, 0x000000e4,
        0x000000d0, 0x00000091, 0x000000c7, 0x000000ce, 0x000000ed, 0x0000000f, 0x000000b4, 0x0000006f,
        0x000000a0, 0x000000cc, 0x000000f0, 0x00000002, 0x0000004a, 0x00000079, 0x000000c3, 0x000000de,
        0x000000a3, 0x000000ef, 0x000000ea, 0x00000051, 0x000000e6, 0x0000006b, 0x00000018, 0x000000ec,
        0x0000001b, 0x0000002c, 0x00000080, 0x000000f7, 0x00000074, 0x000000e7, 0x000000ff, 0x00000021,
        0x0000005a, 0x0000006a, 0x00000054, 0x0000001e, 0x00000041, 0x00000031, 0x00000092, 0x00000035,
        0x000000c4, 0x00000033, 0x00000007, 0x0000000a, 0x000000ba, 0x0000007e, 0x0000000e, 0x00000034,
        0x00000088, 0x000000b1, 0x00000098, 0x0000007c, 0x000000f3, 0x0000003d, 0x00000060, 0x0000006c,
        0x0000007b, 0x000000ca, 0x000000d3, 0x0000001f, 0x00000032, 0x00000065, 0x00000004, 0x00000028,
        0x00000064, 0x000000be, 0x00000085, 0x0000009b, 0x0000002f, 0x00000059, 0x0000008a, 0x000000d7,
        0x000000b0, 0x00000025, 0x000000ac, 0x000000af, 0x00000012, 0x00000003, 0x000000e2, 0x000000f2
    };

    private static final int[] CONST = {
        0x44d700, 0x26bc00, 0x626b00, 0x135e00, 0x578900, 0x35e200, 0x713500, 0x09af00,
        0x4d7800, 0x2f1300, 0x6bc400, 0x1af100, 0x5e2600, 0x3c4d00, 0x789a00, 0x47ac00
    };

    private static int addM(int a, int b) {
        int w = a + b;
        return (w & 0x7fffffff) + (w >>> 31);
    }

    private static int mulByPow2(int a, int i) {
        return ((a << i) & 0x7fffffff) | (a >>> (31 - i));
    }

    private static int feedback(int s0, int s4, int s10, int s13, int s15) {
        int f = s0;

        f = addM(f, mulByPow2(s0, 8));
        f = addM(f, mulByPow2(s4, 20));
        f = addM(f, mulByPow2(s10, 21));
        f = addM(f, mulByPow2(s13, 17));
        f = addM(f, mulByPow2(s15, 15));

        return f;
    }

    private static int feedback(int s0, int s4, int s10, int s13, int s15, int u) {
        int f = s0;

        f = addM(f, mulByPow2(s0, 8));
        f = addM(f, mulByPow2(s4, 20));
        f = addM(f, mulByPow2(s10, 21));
        f = addM(f, mulByPow2(s13, 17));
        f = addM(f, mulByPow2(s15, 15));

        return addM(f, u);
    }

    private static int l1(int x) {
        return x ^ Integer.rotateLeft(x, 2) ^ Integer.rotateLeft(x, 10) ^ Integer.rotateLeft(x, 18) ^ Integer.rotateLeft(x, 24);
    }

    private static int l2(int x) {
        return x ^ Integer.rotateRight(x, 2) ^ Integer.rotateRight(x, 10) ^ Integer.rotateRight(x, 18) ^ Integer.rotateRight(x, 24);
    }

    private static int s(int x) {
        return S0[x >>> 24] | S1[(x >>> 16) & 0xff] | S2[(x >>> 8) & 0xff] | S3[x & 0xff];
    }

    private static int[] init(int[] register, byte[] key, byte[] iv) {
        int[] state = new int[32];

        for (int i = 0; i < 16; i++) {
            state[i] = ((key[i] & 0xff) << 23) | CONST[i] | (iv[i] & 0xff);
        }

        int w1, w2, u, r1 = 0, r2 = 0;

        u = (((state[15] & 0xffff0000) << 1) ^ (state[14] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[11] << 16) | (state[9] >>> 15));
        w2 = r2 ^ (state[7] << 16) ^ (state[5] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[16] = feedback(state[0], state[4], state[10], state[13], state[15], u >>> 1);

        u = (((state[16] & 0xffff0000) << 1) ^ (state[15] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[12] << 16) | (state[10] >>> 15));
        w2 = r2 ^ (state[8] << 16) ^ (state[6] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[17] = feedback(state[1], state[5], state[11], state[14], state[16], u >>> 1);

        u = (((state[17] & 0xffff0000) << 1) ^ (state[16] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[13] << 16) | (state[11] >>> 15));
        w2 = r2 ^ (state[9] << 16) ^ (state[7] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[18] = feedback(state[2], state[6], state[12], state[15], state[17], u >>> 1);

        u = (((state[18] & 0xffff0000) << 1) ^ (state[17] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[14] << 16) | (state[12] >>> 15));
        w2 = r2 ^ (state[10] << 16) ^ (state[8] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[19] = feedback(state[3], state[7], state[13], state[16], state[18], u >>> 1);

        u = (((state[19] & 0xffff0000) << 1) ^ (state[18] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[15] << 16) | (state[13] >>> 15));
        w2 = r2 ^ (state[11] << 16) ^ (state[9] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[20] = feedback(state[4], state[8], state[14], state[17], state[19], u >>> 1);

        u = (((state[20] & 0xffff0000) << 1) ^ (state[19] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[16] << 16) | (state[14] >>> 15));
        w2 = r2 ^ (state[12] << 16) ^ (state[10] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[21] = feedback(state[5], state[9], state[15], state[18], state[20], u >>> 1);

        u = (((state[21] & 0xffff0000) << 1) ^ (state[20] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[17] << 16) | (state[15] >>> 15));
        w2 = r2 ^ (state[13] << 16) ^ (state[11] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[22] = feedback(state[6], state[10], state[16], state[19], state[21], u >>> 1);

        u = (((state[22] & 0xffff0000) << 1) ^ (state[21] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[18] << 16) | (state[16] >>> 15));
        w2 = r2 ^ (state[14] << 16) ^ (state[12] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[23] = feedback(state[7], state[11], state[17], state[20], state[22], u >>> 1);

        u = (((state[23] & 0xffff0000) << 1) ^ (state[22] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[19] << 16) | (state[17] >>> 15));
        w2 = r2 ^ (state[15] << 16) ^ (state[13] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[24] = feedback(state[8], state[12], state[18], state[21], state[23], u >>> 1);

        u = (((state[24] & 0xffff0000) << 1) ^ (state[23] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[20] << 16) | (state[18] >>> 15));
        w2 = r2 ^ (state[16] << 16) ^ (state[14] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[25] = feedback(state[9], state[13], state[19], state[22], state[24], u >>> 1);

        u = (((state[25] & 0xffff0000) << 1) ^ (state[24] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[21] << 16) | (state[19] >>> 15));
        w2 = r2 ^ (state[17] << 16) ^ (state[15] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[26] = feedback(state[10], state[14], state[20], state[23], state[25], u >>> 1);

        u = (((state[26] & 0xffff0000) << 1) ^ (state[25] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[22] << 16) | (state[20] >>> 15));
        w2 = r2 ^ (state[18] << 16) ^ (state[16] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[27] = feedback(state[11], state[15], state[21], state[24], state[26], u >>> 1);

        u = (((state[27] & 0xffff0000) << 1) ^ (state[26] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[23] << 16) | (state[21] >>> 15));
        w2 = r2 ^ (state[19] << 16) ^ (state[17] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[28] = feedback(state[12], state[16], state[22], state[25], state[27], u >>> 1);

        u = (((state[28] & 0xffff0000) << 1) ^ (state[27] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[24] << 16) | (state[22] >>> 15));
        w2 = r2 ^ (state[20] << 16) ^ (state[18] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[29] = feedback(state[13], state[17], state[23], state[26], state[28], u >>> 1);

        u = (((state[29] & 0xffff0000) << 1) ^ (state[28] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[25] << 16) | (state[23] >>> 15));
        w2 = r2 ^ (state[21] << 16) ^ (state[19] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[30] = feedback(state[14], state[18], state[24], state[27], state[29], u >>> 1);

        u = (((state[30] & 0xffff0000) << 1) ^ (state[29] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[26] << 16) | (state[24] >>> 15));
        w2 = r2 ^ (state[22] << 16) ^ (state[20] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[31] = feedback(state[15], state[19], state[25], state[28], state[30], u >>> 1);

        u = (((state[31] & 0xffff0000) << 1) ^ (state[30] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[27] << 16) | (state[25] >>> 15));
        w2 = r2 ^ (state[23] << 16) ^ (state[21] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[0] = feedback(state[16], state[20], state[26], state[29], state[31], u >>> 1);

        u = (((state[0] & 0xffff0000) << 1) ^ (state[31] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[28] << 16) | (state[26] >>> 15));
        w2 = r2 ^ (state[24] << 16) ^ (state[22] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[1] = feedback(state[17], state[21], state[27], state[30], state[0], u >>> 1);

        u = (((state[1] & 0xffff0000) << 1) ^ (state[0] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[29] << 16) | (state[27] >>> 15));
        w2 = r2 ^ (state[25] << 16) ^ (state[23] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[2] = feedback(state[18], state[22], state[28], state[31], state[1], u >>> 1);

        u = (((state[2] & 0xffff0000) << 1) ^ (state[1] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[30] << 16) | (state[28] >>> 15));
        w2 = r2 ^ (state[26] << 16) ^ (state[24] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[3] = feedback(state[19], state[23], state[29], state[0], state[2], u >>> 1);

        u = (((state[3] & 0xffff0000) << 1) ^ (state[2] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[31] << 16) | (state[29] >>> 15));
        w2 = r2 ^ (state[27] << 16) ^ (state[25] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[4] = feedback(state[20], state[24], state[30], state[1], state[3], u >>> 1);

        u = (((state[4] & 0xffff0000) << 1) ^ (state[3] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[0] << 16) | (state[30] >>> 15));
        w2 = r2 ^ (state[28] << 16) ^ (state[26] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[5] = feedback(state[21], state[25], state[31], state[2], state[4], u >>> 1);

        u = (((state[5] & 0xffff0000) << 1) ^ (state[4] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[1] << 16) | (state[31] >>> 15));
        w2 = r2 ^ (state[29] << 16) ^ (state[27] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[6] = feedback(state[22], state[26], state[0], state[3], state[5], u >>> 1);

        u = (((state[6] & 0xffff0000) << 1) ^ (state[5] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[2] << 16) | (state[0] >>> 15));
        w2 = r2 ^ (state[30] << 16) ^ (state[28] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[7] = feedback(state[23], state[27], state[1], state[4], state[6], u >>> 1);

        u = (((state[7] & 0xffff0000) << 1) ^ (state[6] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[3] << 16) | (state[1] >>> 15));
        w2 = r2 ^ (state[31] << 16) ^ (state[29] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[8] = feedback(state[24], state[28], state[2], state[5], state[7], u >>> 1);

        u = (((state[8] & 0xffff0000) << 1) ^ (state[7] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[4] << 16) | (state[2] >>> 15));
        w2 = r2 ^ (state[0] << 16) ^ (state[30] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[9] = feedback(state[25], state[29], state[3], state[6], state[8], u >>> 1);

        u = (((state[9] & 0xffff0000) << 1) ^ (state[8] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[5] << 16) | (state[3] >>> 15));
        w2 = r2 ^ (state[1] << 16) ^ (state[31] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[10] = feedback(state[26], state[30], state[4], state[7], state[9], u >>> 1);

        u = (((state[10] & 0xffff0000) << 1) ^ (state[9] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[6] << 16) | (state[4] >>> 15));
        w2 = r2 ^ (state[2] << 16) ^ (state[0] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[11] = feedback(state[27], state[31], state[5], state[8], state[10], u >>> 1);

        u = (((state[11] & 0xffff0000) << 1) ^ (state[10] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[7] << 16) | (state[5] >>> 15));
        w2 = r2 ^ (state[3] << 16) ^ (state[1] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[12] = feedback(state[28], state[0], state[6], state[9], state[11], u >>> 1);

        u = (((state[12] & 0xffff0000) << 1) ^ (state[11] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[8] << 16) | (state[6] >>> 15));
        w2 = r2 ^ (state[4] << 16) ^ (state[2] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[13] = feedback(state[29], state[1], state[7], state[10], state[12], u >>> 1);

        u = (((state[13] & 0xffff0000) << 1) ^ (state[12] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[9] << 16) | (state[7] >>> 15));
        w2 = r2 ^ (state[5] << 16) ^ (state[3] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[14] = feedback(state[30], state[2], state[8], state[11], state[13], u >>> 1);

        u = (((state[14] & 0xffff0000) << 1) ^ (state[13] & 0xffff) ^ r1) + r2;

        w1 = r1 + ((state[10] << 16) | (state[8] >>> 15));
        w2 = r2 ^ (state[6] << 16) ^ (state[4] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[15] = feedback(state[31], state[3], state[9], state[12], state[14], u >>> 1);

        //discarding
        w1 = r1 + ((state[11] << 16) | (state[9] >>> 15));
        w2 = r2 ^ (state[7] << 16) ^ (state[5] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[16] = feedback(state[0], state[4], state[10], state[13], state[15]);

        System.arraycopy(state, 1, state, 0, 16);

        register[0] = r1;
        register[1] = r2;

        return state;
    }

    private static void keystream(int[] state, int[] register, int[] keystream) {
        int w1, w2, r1 = register[0], r2 = register[1];

        keystream[0] = ((((state[15] & 0xffff0000) << 1) ^ (state[14] & 0xffff) ^ r1) + r2) ^ (state[2] << 16) ^ (state[0] >>> 15);

        w1 = r1 + ((state[11] << 16) | (state[9] >>> 15));
        w2 = r2 ^ (state[7] << 16) ^ (state[5] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[16] = feedback(state[0], state[4], state[10], state[13], state[15]);

        keystream[1] = ((((state[16] & 0xffff0000) << 1) ^ (state[15] & 0xffff) ^ r1) + r2) ^ (state[3] << 16) ^ (state[1] >>> 15);

        w1 = r1 + ((state[12] << 16) | (state[10] >>> 15));
        w2 = r2 ^ (state[8] << 16) ^ (state[6] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[17] = feedback(state[1], state[5], state[11], state[14], state[16]);

        keystream[2] = ((((state[17] & 0xffff0000) << 1) ^ (state[16] & 0xffff) ^ r1) + r2) ^ (state[4] << 16) ^ (state[2] >>> 15);

        w1 = r1 + ((state[13] << 16) | (state[11] >>> 15));
        w2 = r2 ^ (state[9] << 16) ^ (state[7] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[18] = feedback(state[2], state[6], state[12], state[15], state[17]);

        keystream[3] = ((((state[18] & 0xffff0000) << 1) ^ (state[17] & 0xffff) ^ r1) + r2) ^ (state[5] << 16) ^ (state[3] >>> 15);

        w1 = r1 + ((state[14] << 16) | (state[12] >>> 15));
        w2 = r2 ^ (state[10] << 16) ^ (state[8] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[19] = feedback(state[3], state[7], state[13], state[16], state[18]);

        keystream[4] = ((((state[19] & 0xffff0000) << 1) ^ (state[18] & 0xffff) ^ r1) + r2) ^ (state[6] << 16) ^ (state[4] >>> 15);

        w1 = r1 + ((state[15] << 16) | (state[13] >>> 15));
        w2 = r2 ^ (state[11] << 16) ^ (state[9] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[20] = feedback(state[4], state[8], state[14], state[17], state[19]);

        keystream[5] = ((((state[20] & 0xffff0000) << 1) ^ (state[19] & 0xffff) ^ r1) + r2) ^ (state[7] << 16) ^ (state[5] >>> 15);

        w1 = r1 + ((state[16] << 16) | (state[14] >>> 15));
        w2 = r2 ^ (state[12] << 16) ^ (state[10] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[21] = feedback(state[5], state[9], state[15], state[18], state[20]);

        keystream[6] = ((((state[21] & 0xffff0000) << 1) ^ (state[20] & 0xffff) ^ r1) + r2) ^ (state[8] << 16) ^ (state[6] >>> 15);

        w1 = r1 + ((state[17] << 16) | (state[15] >>> 15));
        w2 = r2 ^ (state[13] << 16) ^ (state[11] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[22] = feedback(state[6], state[10], state[16], state[19], state[21]);

        keystream[7] = ((((state[22] & 0xffff0000) << 1) ^ (state[21] & 0xffff) ^ r1) + r2) ^ (state[9] << 16) ^ (state[7] >>> 15);

        w1 = r1 + ((state[18] << 16) | (state[16] >>> 15));
        w2 = r2 ^ (state[14] << 16) ^ (state[12] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[23] = feedback(state[7], state[11], state[17], state[20], state[22]);

        keystream[8] = ((((state[23] & 0xffff0000) << 1) ^ (state[22] & 0xffff) ^ r1) + r2) ^ (state[10] << 16) ^ (state[8] >>> 15);

        w1 = r1 + ((state[19] << 16) | (state[17] >>> 15));
        w2 = r2 ^ (state[15] << 16) ^ (state[13] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[24] = feedback(state[8], state[12], state[18], state[21], state[23]);

        keystream[9] = ((((state[24] & 0xffff0000) << 1) ^ (state[23] & 0xffff) ^ r1) + r2) ^ (state[11] << 16) ^ (state[9] >>> 15);

        w1 = r1 + ((state[20] << 16) | (state[18] >>> 15));
        w2 = r2 ^ (state[16] << 16) ^ (state[14] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[25] = feedback(state[9], state[13], state[19], state[22], state[24]);

        keystream[10] = ((((state[25] & 0xffff0000) << 1) ^ (state[24] & 0xffff) ^ r1) + r2) ^ (state[12] << 16) ^ (state[10] >>> 15);

        w1 = r1 + ((state[21] << 16) | (state[19] >>> 15));
        w2 = r2 ^ (state[17] << 16) ^ (state[15] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[26] = feedback(state[10], state[14], state[20], state[23], state[25]);

        keystream[11] = ((((state[26] & 0xffff0000) << 1) ^ (state[25] & 0xffff) ^ r1) + r2) ^ (state[13] << 16) ^ (state[11] >>> 15);

        w1 = r1 + ((state[22] << 16) | (state[20] >>> 15));
        w2 = r2 ^ (state[18] << 16) ^ (state[16] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[27] = feedback(state[11], state[15], state[21], state[24], state[26]);

        keystream[12] = ((((state[27] & 0xffff0000) << 1) ^ (state[26] & 0xffff) ^ r1) + r2) ^ (state[14] << 16) ^ (state[12] >>> 15);

        w1 = r1 + ((state[23] << 16) | (state[21] >>> 15));
        w2 = r2 ^ (state[19] << 16) ^ (state[17] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[28] = feedback(state[12], state[16], state[22], state[25], state[27]);

        keystream[13] = ((((state[28] & 0xffff0000) << 1) ^ (state[27] & 0xffff) ^ r1) + r2) ^ (state[15] << 16) ^ (state[13] >>> 15);

        w1 = r1 + ((state[24] << 16) | (state[22] >>> 15));
        w2 = r2 ^ (state[20] << 16) ^ (state[18] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[29] = feedback(state[13], state[17], state[23], state[26], state[28]);

        keystream[14] = ((((state[29] & 0xffff0000) << 1) ^ (state[28] & 0xffff) ^ r1) + r2) ^ (state[16] << 16) ^ (state[14] >>> 15);

        w1 = r1 + ((state[25] << 16) | (state[23] >>> 15));
        w2 = r2 ^ (state[21] << 16) ^ (state[19] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[30] = feedback(state[14], state[18], state[24], state[27], state[29]);

        keystream[15] = ((((state[30] & 0xffff0000) << 1) ^ (state[29] & 0xffff) ^ r1) + r2) ^ (state[17] << 16) ^ (state[15] >>> 15);

        w1 = r1 + ((state[26] << 16) | (state[24] >>> 15));
        w2 = r2 ^ (state[22] << 16) ^ (state[20] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[31] = feedback(state[15], state[19], state[25], state[28], state[30]);

        keystream[16] = ((((state[31] & 0xffff0000) << 1) ^ (state[30] & 0xffff) ^ r1) + r2) ^ (state[18] << 16) ^ (state[16] >>> 15);

        w1 = r1 + ((state[27] << 16) | (state[25] >>> 15));
        w2 = r2 ^ (state[23] << 16) ^ (state[21] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[0] = feedback(state[16], state[20], state[26], state[29], state[31]);

        keystream[17] = ((((state[0] & 0xffff0000) << 1) ^ (state[31] & 0xffff) ^ r1) + r2) ^ (state[19] << 16) ^ (state[17] >>> 15);

        w1 = r1 + ((state[28] << 16) | (state[26] >>> 15));
        w2 = r2 ^ (state[24] << 16) ^ (state[22] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[1] = feedback(state[17], state[21], state[27], state[30], state[0]);

        keystream[18] = ((((state[1] & 0xffff0000) << 1) ^ (state[0] & 0xffff) ^ r1) + r2) ^ (state[20] << 16) ^ (state[18] >>> 15);

        w1 = r1 + ((state[29] << 16) | (state[27] >>> 15));
        w2 = r2 ^ (state[25] << 16) ^ (state[23] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[2] = feedback(state[18], state[22], state[28], state[31], state[1]);

        keystream[19] = ((((state[2] & 0xffff0000) << 1) ^ (state[1] & 0xffff) ^ r1) + r2) ^ (state[21] << 16) ^ (state[19] >>> 15);

        w1 = r1 + ((state[30] << 16) | (state[28] >>> 15));
        w2 = r2 ^ (state[26] << 16) ^ (state[24] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[3] = feedback(state[19], state[23], state[29], state[0], state[2]);

        keystream[20] = ((((state[3] & 0xffff0000) << 1) ^ (state[2] & 0xffff) ^ r1) + r2) ^ (state[22] << 16) ^ (state[20] >>> 15);

        w1 = r1 + ((state[31] << 16) | (state[29] >>> 15));
        w2 = r2 ^ (state[27] << 16) ^ (state[25] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[4] = feedback(state[20], state[24], state[30], state[1], state[3]);

        keystream[21] = ((((state[4] & 0xffff0000) << 1) ^ (state[3] & 0xffff) ^ r1) + r2) ^ (state[23] << 16) ^ (state[21] >>> 15);

        w1 = r1 + ((state[0] << 16) | (state[30] >>> 15));
        w2 = r2 ^ (state[28] << 16) ^ (state[26] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[5] = feedback(state[21], state[25], state[31], state[2], state[4]);

        keystream[22] = ((((state[5] & 0xffff0000) << 1) ^ (state[4] & 0xffff) ^ r1) + r2) ^ (state[24] << 16) ^ (state[22] >>> 15);

        w1 = r1 + ((state[1] << 16) | (state[31] >>> 15));
        w2 = r2 ^ (state[29] << 16) ^ (state[27] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[6] = feedback(state[22], state[26], state[0], state[3], state[5]);

        keystream[23] = ((((state[6] & 0xffff0000) << 1) ^ (state[5] & 0xffff) ^ r1) + r2) ^ (state[25] << 16) ^ (state[23] >>> 15);

        w1 = r1 + ((state[2] << 16) | (state[0] >>> 15));
        w2 = r2 ^ (state[30] << 16) ^ (state[28] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[7] = feedback(state[23], state[27], state[1], state[4], state[6]);

        keystream[24] = ((((state[7] & 0xffff0000) << 1) ^ (state[6] & 0xffff) ^ r1) + r2) ^ (state[26] << 16) ^ (state[24] >>> 15);

        w1 = r1 + ((state[3] << 16) | (state[1] >>> 15));
        w2 = r2 ^ (state[31] << 16) ^ (state[29] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[8] = feedback(state[24], state[28], state[2], state[5], state[7]);

        keystream[25] = ((((state[8] & 0xffff0000) << 1) ^ (state[7] & 0xffff) ^ r1) + r2) ^ (state[27] << 16) ^ (state[25] >>> 15);

        w1 = r1 + ((state[4] << 16) | (state[2] >>> 15));
        w2 = r2 ^ (state[0] << 16) ^ (state[30] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[9] = feedback(state[25], state[29], state[3], state[6], state[8]);

        keystream[26] = ((((state[9] & 0xffff0000) << 1) ^ (state[8] & 0xffff) ^ r1) + r2) ^ (state[28] << 16) ^ (state[26] >>> 15);

        w1 = r1 + ((state[5] << 16) | (state[3] >>> 15));
        w2 = r2 ^ (state[1] << 16) ^ (state[31] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[10] = feedback(state[26], state[30], state[4], state[7], state[9]);

        keystream[27] = ((((state[10] & 0xffff0000) << 1) ^ (state[9] & 0xffff) ^ r1) + r2) ^ (state[29] << 16) ^ (state[27] >>> 15);

        w1 = r1 + ((state[6] << 16) | (state[4] >>> 15));
        w2 = r2 ^ (state[2] << 16) ^ (state[0] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[11] = feedback(state[27], state[31], state[5], state[8], state[10]);

        keystream[28] = ((((state[11] & 0xffff0000) << 1) ^ (state[10] & 0xffff) ^ r1) + r2) ^ (state[30] << 16) ^ (state[28] >>> 15);

        w1 = r1 + ((state[7] << 16) | (state[5] >>> 15));
        w2 = r2 ^ (state[3] << 16) ^ (state[1] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[12] = feedback(state[28], state[0], state[6], state[9], state[11]);

        keystream[29] = ((((state[12] & 0xffff0000) << 1) ^ (state[11] & 0xffff) ^ r1) + r2) ^ (state[31] << 16) ^ (state[29] >>> 15);

        w1 = r1 + ((state[8] << 16) | (state[6] >>> 15));
        w2 = r2 ^ (state[4] << 16) ^ (state[2] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[13] = feedback(state[29], state[1], state[7], state[10], state[12]);

        keystream[30] = ((((state[13] & 0xffff0000) << 1) ^ (state[12] & 0xffff) ^ r1) + r2) ^ (state[0] << 16) ^ (state[30] >>> 15);

        w1 = r1 + ((state[9] << 16) | (state[7] >>> 15));
        w2 = r2 ^ (state[5] << 16) ^ (state[3] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[14] = feedback(state[30], state[2], state[8], state[11], state[13]);

        keystream[31] = ((((state[14] & 0xffff0000) << 1) ^ (state[13] & 0xffff) ^ r1) + r2) ^ (state[1] << 16) ^ (state[31] >>> 15);

        w1 = r1 + ((state[10] << 16) | (state[8] >>> 15));
        w2 = r2 ^ (state[6] << 16) ^ (state[4] >>> 15);

        r1 = s(l1((w1 << 16) | (w2 >>> 16)));
        r2 = s(l2((w2 << 16) | (w1 >>> 16)));

        state[15] = feedback(state[31], state[3], state[9], state[12], state[14]);

        register[0] = r1;
        register[1] = r2;

    }

    @Override
    public EncryptEngine startEncryption(byte[] key, byte[] iv) {
        return new AbstractStreamEncrypter(128) {

            private final int[] register = new int[2], state = init(register, key, iv), keystream = new int[32];

            @Override
            protected void encryptOneBlock(MemorySegment plaintext, long pOffset, MemorySegment ciphertext, long cOffset) {
                keystream(state, register, keystream);
                for (int i = 0; i < 32; i++) {
                    ciphertext.set(Tools.BIG_ENDIAN_32_BIT, cOffset + 4 * i, keystream[i] ^ plaintext.get(Tools.BIG_ENDIAN_32_BIT, pOffset + 4 * i));
                }
            }

            @Override
            public Cipher getAlgorithm() {
                return ZUC;
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
