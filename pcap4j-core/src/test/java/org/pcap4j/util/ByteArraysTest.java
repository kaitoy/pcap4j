package org.pcap4j.util;

import static org.junit.Assert.*;

import org.junit.Test;

@SuppressWarnings("javadoc")
public class ByteArraysTest {

  @Test
  public void testToHexString() throws Exception {
    byte[] arr =
        new byte[] {
          (byte) 0x0,
          (byte) 0x1,
          (byte) 0x2,
          (byte) 0x3,
          (byte) 0x4,
          (byte) 0x55,
          (byte) 0x56,
          (byte) 0x57,
          (byte) 0x58,
          (byte) 0x59,
          (byte) 0xaa,
          (byte) 0xab,
          (byte) 0xac,
          (byte) 0xad,
          (byte) 0xae,
          (byte) 0xaf,
          (byte) 0xfa,
          (byte) 0xfb,
          (byte) 0xfc,
          (byte) 0xfd,
          (byte) 0xfe,
          (byte) 0xff
        };

    assertEquals(
        "00:01:02:03:04:55:56:57:58:59:aa:ab:ac:ad:ae:af:fa:fb:fc:fd:fe:ff",
        ByteArrays.toHexString(arr, ":"));
    assertEquals(
        "00 : 01 : 02 : 03 : 04 : 55 : 56 : 57 : 58 : 59 : aa : ab : ac : ad : ae : af : fa : fb : fc : fd : fe : ff",
        ByteArrays.toHexString(arr, " : "));
    assertEquals("55-56-57-58-59", ByteArrays.toHexString(arr, "-", 5, 5));
    assertEquals("aaabacadaeaf", ByteArrays.toHexString(arr, "", 10, 6));
  }
}
