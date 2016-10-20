/*_##########################################################################
  _##
  _##  Copyright (C) 2018  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.producer;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.util.ByteArrays;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import java.util.zip.GZIPInputStream;

/**
 * Reassemble fragmented TCP payloads.
 *
 * @author Kaito Yamada
 * @since pcap4j 2.0.0
 */
public class TcpReassembler {

  private final List<TcpPort> protocols;
  private final ReassembledPacketListener listener;
  private final Map<TcpSessionKey, TcpSession> sessions = new HashMap<TcpSessionKey, TcpSession>();

  /**
   * @param protocols protocols to reassemble.
   * @param listener listener
   */
  public TcpReassembler(
    List<TcpPort> protocols,
    ReassembledPacketListener listener
  ) {
    this.protocols = new ArrayList<TcpPort>(protocols);
    this.listener = listener;
  }

  /**
   * Add a packet to reassemble.
   *
   * @param packet packet including an IP (v4 or v6) and TCP headers
   * @return true the given packet is actually added; false otherwise;
   */
  public boolean add(Packet packet) {
    TcpPacket tcpPacket = packet.get(TcpPacket.class);
    if (tcpPacket == null) {
      System.out.println("The given packet doesn't include a TCP packet. packet: " + packet);
      return false;
    }

    IpPacket ipPacket = packet.get(IpPacket.class);
    if (ipPacket == null) {
      System.out.println("The given packet doesn't include an IP packet. packet: " + packet);
      return false;
    }

    // Firstly assume the given packet is a client packet
    // (i.e. a packet sent from the client to the server).
    boolean isClientPacket = true;
    TcpPort clientPort = tcpPacket.getHeader().getSrcPort();
    if (protocols.contains(clientPort)) {
      // The above assumption seems wrong because the source port is a server port.
      // The given packet should be a server packet.
      clientPort = tcpPacket.getHeader().getDstPort();
      if (protocols.contains(clientPort)) {
        System.out.println(
          "Couldn't find the client port. packet: " + packet
        );
        return false;
      }
      isClientPacket = false;
    }

    TcpSessionKey key;
    if (isClientPacket) {
      key = new TcpSessionKey(
              ipPacket.getHeader().getDstAddr(),
              tcpPacket.getHeader().getDstPort(),
              ipPacket.getHeader().getSrcAddr(),
              clientPort
            );
    }
    else {
      key = new TcpSessionKey(
              ipPacket.getHeader().getSrcAddr(),
              tcpPacket.getHeader().getSrcPort(),
              ipPacket.getHeader().getDstAddr(),
              clientPort
            );
    }

    if (tcpPacket.getHeader().getSyn()) {
      TcpSession session;
      if (isClientPacket) {
        session = new TcpSession();
        sessions.put(key, session);
      }
      else {
        session = sessions.get(key);
      }
      session.setSeqNumOffset(isClientPacket, tcpPacket.getHeader().getSequenceNumberAsLong() + 1L);
    }
    else if (tcpPacket.getHeader().getFin()) {
      TcpSession session = sessions.get(key);
      if (session == null) {
        System.out.println("Session (" + key + ") not found when Fin");
        return false;
      }

      if (tcpPacket.getPayload() != null && tcpPacket.getPayload().length() != 0) {
        session.getPackets(isClientPacket).add(tcpPacket);
      }
      session.fin(isClientPacket);

      byte[] reassembledPayload
        = doReassemble(
            session.getPackets(isClientPacket),
            session.getSeqNumOffset(isClientPacket),
            tcpPacket.getHeader().getSequenceNumberAsLong(),
            tcpPacket.getPayload() == null ? 0 : tcpPacket.getPayload().length()
          );

      int len = reassembledPayload.length;
      for (int i = 0; i < len;) {
        Packet reassembledPacket
          = PacketFactories.getFactory(Packet.class, TcpPort.class)
              .newInstance(reassembledPayload, i, len - i);
        listener.gotPacket(reassembledPacket, key, isClientPacket);
        i += reassembledPacket.length();
      }

      // TODO remove finished session from sessions.
    }
    else {
      if (tcpPacket.getPayload() != null && tcpPacket.getPayload().length() != 0) {
        TcpSession session = sessions.get(key);
        if (session == null) {
          System.out.println("Session (" + key + ") not found.");
          return false;
        }

        session.getPackets(isClientPacket).add(tcpPacket);
      }
    }

    return true;
  }

  private byte[] doReassemble(
    List<TcpPacket> packets, long seqNumOffset, long lastSeqNum, int lastDataLen
  ) {
    // This cast is not safe.
    // The sequence number is unsigned int and so
    // (int) (lastSeqNum - seqNumOffset) may be negative.
    byte[] buffer = new byte[(int) (lastSeqNum - seqNumOffset) + lastDataLen];

    for (TcpPacket p: packets) {
      byte[] payload = p.getPayload().getRawData();
      long seq = p.getHeader().getSequenceNumberAsLong();
      System.arraycopy(payload, 0, buffer, (int) (seq - seqNumOffset), payload.length);
    }

    return buffer;
  }

  /**
   * The key to identify a TCP session, which is a combination of a server IP address,
   * a server port, a client IP address, and a client port.
   *
   * @author Kaito Yamada
   */
  public static final class TcpSessionKey {

    private final InetAddress serverAddr;
    private final TcpPort serverPort;
    private final InetAddress clientAddr;
    private final TcpPort clientPort;

    /**
     * @param serverAddr server IP address
     * @param serverPort server port
     * @param clientAddr client IP address
     * @param clientPort client port
     */
    public TcpSessionKey(
      InetAddress serverAddr, TcpPort serverPort, InetAddress clientAddr, TcpPort clientPort
    ) {
      if (serverAddr == null) {
        throw new NullPointerException("serverAddr is null.");
      }
      if (serverPort == null) {
        throw new NullPointerException("serverPort is null.");
      }
      if (clientAddr == null) {
        throw new NullPointerException("clientAddr is null.");
      }
      if (clientPort == null) {
        throw new NullPointerException("clientPort is null.");
      }
      this.serverAddr = serverAddr;
      this.serverPort = serverPort;
      this.clientAddr = clientAddr;
      this.clientPort = clientPort;
    }

    /**
     * @return the server IP address.
     */
    public InetAddress getServerAddr() {
      return serverAddr;
    }

    /**
     * @return the server port.
     */
    public TcpPort getServerPort() {
      return serverPort;
    }

    /**
     * @return the client IP address.
     */
    public InetAddress getClientAddr() {
      return clientAddr;
    }

    /**
     * @return the client port.
     */
    public TcpPort getClientPort() {
      return clientPort;
    }

    @Override
    public int hashCode() {
      final int prime = 31;
      int result = 1;
      result = prime * result + serverAddr.hashCode();
      result = prime * result + serverPort.hashCode();
      result = prime * result + clientAddr.hashCode();
      result = prime * result + clientPort.hashCode();
      return result;
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      }
      if (obj == null) {
        return false;
      }
      if (getClass() != obj.getClass()) {
        return false;
      }
      TcpSessionKey other = (TcpSessionKey) obj;
      if (!serverAddr.equals(other.serverAddr)) {
        return false;
      }
      if (!serverPort.equals(other.serverPort)) {
        return false;
      }
      if (!clientAddr.equals(other.clientAddr)) {
        return false;
      }
      if (!clientPort.equals(other.clientPort)) {
        return false;
      }
      return true;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder();
      sb.append("Server=")
        .append(serverAddr.getHostAddress())
        .append(":")
        .append(serverPort.valueAsInt())
        .append(", Client=")
        .append(clientAddr.getHostAddress())
        .append(":")
        .append(clientPort.valueAsInt());
      return sb.toString();
    }

  }

  /**
   * TCP session.
   *
   * @author Kaito Yamada
   */
  public static final class TcpSession {

    private final List<TcpPacket> clientPackets = new ArrayList<TcpPacket>();
    private final List<TcpPacket> serverPackets = new ArrayList<TcpPacket>();
    private long serverSeqNumOffset;
    private long clientSeqNumOffset;
    private boolean clientFinSent = false;
    private boolean serverFinSent = false;

    /**
     * Get the packets in this session.
     *
     * @param client pass true/false to get the packets sent from the client/server.
     * @return TCP packets.
     */
    public List<TcpPacket> getPackets(boolean client) {
      if (client) {
        return clientPackets;
      }
      else {
        return serverPackets;
      }
    }

    /**
     * Get the sequence number offset in this session.
     *
     * @param client pass true/false to get the client/server sequence number offset
     *        (i.e. the smallest sequence number in client/server packets).
     * @return the sequence number offset
     */
    public long getSeqNumOffset(boolean client) {
      if (client) {
        return clientSeqNumOffset;
      }
      else {
        return serverSeqNumOffset;
      }
    }

    /**
     * Set the sequence number offset in this session.
     *
     * @param client pass true/false to set the client/server sequence number offset
     *        (i.e. the smallest sequence number in client/server packets).
     * @param seqNumOffset the sequence number offset to set.
     */
    public void setSeqNumOffset(boolean client, long seqNumOffset) {
      if (client) {
        this.clientSeqNumOffset = seqNumOffset;
      }
      else {
        this.serverSeqNumOffset = seqNumOffset;
      }
    }

    /**
     * Call this method when the fin is sent in this session.
     *
     * @param client pass true/false if you call this method for the fin sent from client/server.
     */
    public void fin(boolean client) {
      if (client) {
        this.clientFinSent = true;
      }
      else {
        this.serverFinSent = true;
      }
    }

    /**
     * Check if the fin was sent in this session.
     * @param client pass true/false if you want to know if the fin was sent from client/server.
     * @return true if the fin was sent; false otherwise.
     */
    public boolean wasFinSent(boolean client) {
      if (client) {
        return clientFinSent;
      }
      else {
        return serverFinSent;
      }
    }

  }

  /**
   * Callback called when a packet is reassembled.
   *
   * @author Kaito Yamada
   */
  public interface ReassembledPacketListener {

    /**
     * @param packet a reassembled packet
     * @param key key
     * @param isClientPacket isClientPacket
     */
    public void gotPacket(Packet packet, TcpSessionKey key, boolean isClientPacket);

  }

  /**
   * A sample code to reassemble HTTP packets.
   * @param args The first arg is the path to pcap file.
   *             The second arg is HTTP port number.
   * @throws PcapNativeException PcapNativeException
   * @throws NotOpenException NotOpenException
   */
  public static void main(String[] args) throws PcapNativeException, NotOpenException {
    String pcapFile = args[0];
    short httpPort = Short.parseShort(args[1]);

    PcapHandle handle = Pcaps.openOffline(pcapFile);
    handle.setFilter(
      "tcp port " + httpPort,
      BpfCompileMode.OPTIMIZE
    );

    List<TcpPort> protos = new ArrayList<TcpPort>();
    protos.add(TcpPort.getInstance(httpPort));
    TcpReassembler tcpReassembler
      = new TcpReassembler(
          protos,
          (packet, key, isClientPacket) -> {
            if (isClientPacket) {
              StringBuilder sb
                = new StringBuilder()
                    .append("########### Client Packet (")
                    .append(key.getClientAddr().getHostAddress())
                    .append(":")
                    .append(key.getClientPort().valueAsInt())
                    .append(" -> ")
                    .append(key.getServerAddr().getHostAddress())
                    .append(":")
                    .append(key.getServerPort().valueAsInt())
                    .append(") ###########");
              System.out.println(sb.toString());
              System.out.println(new String(packet.getRawData()));
            }
            else {
              StringBuilder sb
                = new StringBuilder()
                    .append("########### Server Packet (")
                    .append(key.getServerAddr().getHostAddress())
                    .append(":")
                    .append(key.getServerPort().valueAsInt())
                    .append(" -> ")
                    .append(key.getClientAddr().getHostAddress())
                    .append(":")
                    .append(key.getClientPort().valueAsInt())
                    .append(") ###########");
              System.out.println(sb.toString());

              byte[] data = packet.getRawData();
              for (int i = 0; i < data.length - 4; i++) {
                // skipping the header
                if (
                     data[i    ] == 0x0d // \r
                  && data[i + 1] == 0x0a // \n
                  && data[i + 2] == 0x0d // \r
                  && data[i + 3] == 0x0a // \n
                ) {
                  // arrived at the body
                  byte[] body = ByteArrays.getSubArray(data, i + 4);
                  GZIPInputStream in = null;
                  try {
                    in = new GZIPInputStream(new ByteArrayInputStream(body));
                    byte[] extendedBody = new byte[4 * 1024 * 1024];
                    int totalLen = 0;
                    while (true) {
                      int len = in.read(extendedBody, totalLen, extendedBody.length - totalLen);
                      if (len == -1) {
                        break;
                      }
                      totalLen += len;
                    }
                    System.out.println(new String(extendedBody, 0, totalLen));
                    break;
                  } catch (Exception e) {
                    if (in != null) {
                      try {
                        in.close();
                      } catch (IOException e1) {}
                    }
                    e.printStackTrace();
                    break;
                  }
                }
              }
            }
          }
      );

    while (true) {
      try {
        tcpReassembler.add(handle.getNextPacketEx());
      } catch (TimeoutException e) {
        continue;
      } catch (EOFException e) {
        break;
      }
    }

    handle.close();
  }

}
