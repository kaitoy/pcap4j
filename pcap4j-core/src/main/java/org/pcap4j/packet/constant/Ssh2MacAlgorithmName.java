/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.constant;

/**
 * MAC Algorithm Name
 * https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-18
 *
 * @author Kaito Yamada
 * @since pcap4j 1.0.1
 */
public final class Ssh2MacAlgorithmName {

  private Ssh2MacAlgorithmName() {
    throw new AssertionError();
  }

  /** */
  public static final String HMAC_SHA1 = "hmac-sha1";

  /** */
  public static final String HMAC_SHA1_96 = "hmac-sha1-96";

  /** */
  public static final String HMAC_MD5 = "hmac-md5";

  /** */
  public static final String HMAC_MD5_96 = "hmac-md5-96";

  /** */
  public static final String NONE = "none";

  /** */
  public static final String AEAD_AES_128_GCM = "AEAD_AES_128_GCM";

  /** */
  public static final String AEAD_AES_256_GCM = "AEAD_AES_256_GCM";

  /** */
  public static final String HMAC_SHA2_256 = "hmac-sha2-256";

  /** */
  public static final String HMAC_SHA2_512 = "hmac-sha2-512";
}
