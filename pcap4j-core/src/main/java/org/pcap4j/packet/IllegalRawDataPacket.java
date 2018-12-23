/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

/**
 * A marker interface which denotes a {@link Packet} object created due to an {@link
 * IllegalRawDataException}.
 *
 * @author Kaito Yamada
 * @since pcap4j 2.0.0
 */
public interface IllegalRawDataPacket extends IllegalRawDataHolder, Packet {}
