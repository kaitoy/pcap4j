/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.constant;

/**
 * Encryption Algorithm Name
 * https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-17
 *
 * @author Kaito Yamada
 * @since pcap4j 1.0.1
 */
public final class Ssh2EncryptionAlgorithmName {

  private Ssh2EncryptionAlgorithmName() {
    throw new AssertionError();
  }

  /** */
  public static final String THREE_DES_CBC = "3des-cbc";

  /** */
  public static final String BLOWFISH_CBC = "blowfish-cbc";

  /** */
  public static final String TWOFISH256_CBC = "twofish256-cbc";

  /** */
  public static final String TWOFISH_CBC = "twofish-cbc";

  /** */
  public static final String TWOFISH192_CBC = "twofish192-cbc";

  /** */
  public static final String TWOFISH128_CBC = "twofish128-cbc";

  /** */
  public static final String AES256_CBC = "aes256-cbc";

  /** */
  public static final String AES192_CBC = "aes192-cbc";

  /** */
  public static final String AES128_CBC = "aes128-cbc";

  /** */
  public static final String SERPENT256_CBC = "serpent256-cbc";

  /** */
  public static final String SERPENT192_CBC = "serpent192-cbc";

  /** */
  public static final String SERPENT128_CBC = "serpent128-cbc";

  /** */
  public static final String ARCFOUR = "arcfour";

  /** */
  public static final String IDEA_CBC = "idea-cbc";

  /** */
  public static final String CAST128_CBC = "cast128-cbc";

  /** */
  public static final String NONE = "none";

  /** */
  public static final String DES_CBC = "des-cbc";

  /** */
  public static final String ARCFOUR128 = "arcfour128";

  /** */
  public static final String ARCFOUR256 = "arcfour256";

  /** */
  public static final String AES128_CTR = "aes128-ctr";

  /** */
  public static final String AES192_CTR = "aes192-ctr";

  /** */
  public static final String AES256_CTR = "aes256-ctr";

  /** */
  public static final String THREE_DES_CTR = "3des-ctr";

  /** */
  public static final String BLOWFISH_CTR = "blowfish-ctr";

  /** */
  public static final String TWOFISH128_CTR = "twofish128-ctr";

  /** */
  public static final String TWOFISH192_CTR = "twofish192-ctr";

  /** */
  public static final String TWOFISH256_CTR = "twofish256-ctr";

  /** */
  public static final String SERPENT128_CTR = "serpent128-ctr";

  /** */
  public static final String SERPENT192_CTR = "serpent192-ctr";

  /** */
  public static final String SERPENT256_CTR = "serpent256-ctr";

  /** */
  public static final String IDEA_CTR = "idea-ctr";

  /** */
  public static final String CAST128_CTR = "cast128-ctr";

  /** */
  public static final String AEAD_AES_128_GCM = "AEAD_AES_128_GCM";

  /** */
  public static final String AEAD_AES_256_GCM = "AEAD_AES_256_GCM";
}
