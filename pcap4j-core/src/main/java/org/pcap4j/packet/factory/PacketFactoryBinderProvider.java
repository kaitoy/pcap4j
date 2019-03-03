/*_##########################################################################
  _##
  _##  Copyright (C) 2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

/**
 * Provides an instance of {@link PacketFactoryBinder}
 *
 * <p>Implementing modules must declare themselves to the core module by:
 *
 * <ul>
 *   <li>creating the file
 *       src/main/resources/META-INF/services/org.pcap4j.packet.factory.PacketFactoryBinderProvider
 *   <li>adding a line in the file '&lt;package&gt;.&lt;className&gt;' for the name of the class
 *       implementing this {@link PacketFactoryBinderProvider}
 * </ul>
 *
 * <p>See {@link java.util.ServiceLoader} for more information.
 *
 * @author Jordan Dubie
 * @since pcap4j 1.8.0
 */
public interface PacketFactoryBinderProvider {
  /**
   * The instance of the {@link PacketFactoryBinder} to use to build the packets.
   *
   * @return a {@link PacketFactoryBinder}
   */
  public PacketFactoryBinder getBinder();
}
