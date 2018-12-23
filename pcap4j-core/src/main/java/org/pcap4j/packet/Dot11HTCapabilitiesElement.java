/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.nio.ByteOrder;
import java.util.Arrays;
import org.pcap4j.packet.namednumber.Dot11InformationElementId;
import org.pcap4j.util.ByteArrays;

/**
 * IEEE802.11 HT Capabilities element
 *
 * <pre style="white-space: pre;">
 *       1            1            2            1            16           2            4            1
 * +------------+------------+------------+------------+------------+------------+------------+------------+
 * | Element ID |  Length    |     HT     |   A-MPDU   | Supported  |     HT     |  Transmit  |    ASEL    |
 * |            |            |Capabilities| Parameters |  MCS Set   |  Extended  |Beamforming |Capabilities|
 * |            |            |    Info    |            |            |Capabilities|Capabilities|            |
 * +------------+------------+------------+------------+------------+------------+------------+------------+
 * Element ID: 45
 *
 * HT Capabilities Info:
 *       B0           B1        B2    B3        B4           B5           B6           B7        B8    B9
 * +------------+------------+------------+------------+------------+------------+------------+------------+
 * |    LDPC    | Supported  |     SM     |     HT-    |Short GI for|Short GI for|     Tx     |     Rx     |
 * |   Coding   |  Channel   |    Power   | Greenfield |   20 MHz   |   40 MHz   |    STBC    |    STBC    |
 * | Capability | Width Set  |    Save    |            |            |            |            |            |
 * +------------+------------+------------+------------+------------+------------+------------+------------+
 *
 *       B10          B11          B12          B13         B14           B15
 * +------------+------------+------------+------------+------------+------------+
 * | HT-Delayed |  Maximum   |  DSSS/CCK  |  Reserved  | Forty MHz  | L-SIG TXOP |
 * | Block Ack  |   A-MSDU   |  Mode in   |            | Intolerant | Protection |
 * |            |   Length   |   40 MHz   |            |            |  Support   |
 * +------------+------------+------------+------------+------------+------------+
 *
 * A-MPDU Parameters:
 *     B0      B1      B2              B4       B5              B7
 * +---------------+------------------------+------------------------+
 * |Maximum A-MPDU |     Minimum MPDU       |        Reserved        |
 * |Length Exponent|     Start Spacing      |                        |
 * +---------------+------------------------+------------------------+
 *
 * Supported MCS Set field:
 *  B0          B76 B77    B79 B80                          B89 B90    B95
 * +---------------+----------+--------------------------------+----------+
 * |Rx MCS Bitmask | Reserved | Rx Highest Supported Data Rate | Reserved |
 * +---------------+----------+--------------------------------+----------+
 *
 *      B96        B97       B98        B99       B100    B101      B127
 * +----------+----------+--------------------+----------+------//------+
 * |Tx MCS Set| Tx Rx    | Tx Maximum Number  |Tx Unequal|  Reserved    |
 * | Defined  | MCS Set  |  Spatial Streams   |Modulation|              |
 * |          |Not Equal |    Supported       |Supported |              |
 * +----------+----------+--------------------+----------+------//------+
 *
 * HT Extended Capabilities:
 *     B0        B1        B2      B3     B7     B8        B9       B10       B11    B12     B15
 * +---------+-------------------+----//-----+-------------------+--------+---------+----//-----+
 * |   PCO   |       PCO         | Reserved  |       MCS         | +HTC   |   RD    | Reserved  |
 * |         |  Transition Time  |           |     Feedback      |Support |Responder|           |
 * |         |                   |           |                   |        |         |           |
 * +---------+-------------------+----//-----+-------------------+--------+---------+----//-----+
 *
 * Transmit Beamforming Capabilities:
 *       B0           B1           B2           B3           B4           B5           B6           B7           B8
 * +------------+------------+------------+------------+------------+------------+-------------------------+------------+
 * |  Implicit  |  Receive   |  Transmit  |  Receive   |  Transmit  |  Implicit  |      Calibration        |Explicit CSI|
 * |  Transmit  | Staggered  | Staggered  |    NDP     |    NDP     |  Transmit  |                         |  Transmit  |
 * |Beamforming |  Sounding  |  Sounding  |  Capable   |  Capable   |Beamforming |                         |Beamforming |
 * | Receiving  |  Capable   |  Capable   |            |            |  Capable   |                         |  Capable   |
 * |  Capable   |            |            |            |            |            |                         |            |
 * +------------+------------+------------+------------+------------+------------+-------------------------+------------+
 *
 *       B9            B10           B11           B12           B13           B14           B15           B16
 * +-------------+-------------+---------------------------+---------------------------+---------------------------+
 * |  Explicit   |  Explicit   |     Explicit Transmit     |  Explicit Noncompressed   |    Explicit Compressed    |
 * |Noncompressed| Compressed  |        Beamforming        |        Beamforming        |        Beamforming        |
 * |  Steering   |  Steering   |       CSI Feedback        |     Feedback Capable      |     Feedback Capable      |
 * |  Capable    |  Capable    |                           |                           |                           |
 * +-------------+-------------+---------------------------+---------------------------+---------------------------+
 *
 *       B17           B18           B19           B20           B21           B22           B23           B24
 * +---------------------------+---------------------------+---------------------------+---------------------------+
 * |          Minimal          |       CSI Number of       |  Noncompressed Steering   |   Compressed Steering     |
 * |          Grouping         |        Beamformer         |   Number of Beamformer    |   Number of Beamformer    |
 * |                           |     Antennas Supported    |    Antennas Supported     |    Antennas Supported     |
 * |                           |                           |                           |                           |
 * +---------------------------+---------------------------+---------------------------+---------------------------+
 *
 *      B25           B26         B27           B28         B29          B30          B31
 * +-------------------------+-------------------------+--------------------------------------+
 * |   CSI Max Number of     |         Channel         |                Reserved              |
 * |Rows Beamformer Supported|  Estimation Capability  |                                      |
 * +-------------------------+-------------------------+--------------------------------------+
 *
 * ASEL Capability:
 *        B0              B1              B2              B3              B4              B5              B6              B7
 * +---------------+---------------+---------------+---------------+---------------+---------------+---------------+---------------+
 * |    Antenna    | Explicit CSI  |Antenna Indices| Explicit CSI  |Antenna Indices|    Receive    |   Transmit    |   Reserved    |
 * |   Selection   |Feedback Based |Feedback Based |   Feedback    |   Feedback    | ASEL Capable  |   Sounding    |               |
 * |    Capable    |   Transmit    |   Transmit    |    Capable    |    Capable    |               |    PPDUs      |               |
 * |               | ASEL Capable  | ASEL Capable  |               |               |               |    Capable    |               |
 * +---------------+---------------+---------------+---------------+---------------+---------------+---------------+---------------+
 * </pre>
 *
 * The HT Capabilities element contains a number of fields that are used to advertise optional HT
 * capabilities of an HT STA. The HT Capabilities element is present in Beacon, Association Request,
 * Association Response, Reassociation Request, Reassociation Response, Probe Request, Probe
 * Response, Mesh Peering Open, and Mesh Peering Close frames.
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11HTCapabilitiesElement extends Dot11InformationElement {

  /** */
  private static final long serialVersionUID = -5174208022820530840L;

  private final boolean ldpcCodingSupported;
  private final boolean both20and40MhzSupported;
  private final SmPowerSaveMode smPowerSaveMode;
  private final boolean htGreenfieldSupported;
  private final boolean shortGiFor20MhzSupported;
  private final boolean shortGiFor40MhzSupported;
  private final boolean txStbcSupported;
  private final StbcSupport rxStbcSupport;
  private final boolean htDelayedBlockAckSupported;
  private final AMsduLength maxAMsduLength;
  private final boolean dsssCckModeIn40MhzSupported;
  private final boolean bit13OfHtCapabilitiesInfo;
  private final boolean fortyMhzIntolerant;
  private final boolean lSigTxopProtectionSupported;
  private final AMpduLength maxAMpduLength;
  private final MpduStartSpacing minMpduStartSpacing;
  private final boolean bit5OfAMpduParameters;
  private final boolean bit6OfAMpduParameters;
  private final boolean bit7OfAMpduParameters;
  private final boolean[] supportedRxMcsIndexes;
  private final boolean bit77OfSupportedMcsSet;
  private final boolean bit78OfSupportedMcsSet;
  private final boolean bit79OfSupportedMcsSet;
  private final short rxHighestSupportedDataRate;
  private final boolean bit90OfSupportedMcsSet;
  private final boolean bit91OfSupportedMcsSet;
  private final boolean bit92OfSupportedMcsSet;
  private final boolean bit93OfSupportedMcsSet;
  private final boolean bit94OfSupportedMcsSet;
  private final boolean bit95OfSupportedMcsSet;
  private final boolean txMcsSetDefined;
  private final boolean txRxMcsSetNotEqual;
  private final NumSpatialStreams txMaxNumSpatialStreamsSupported;
  private final boolean txUnequalModulationSupported;
  private final boolean bit101OfSupportedMcsSet;
  private final boolean bit102OfSupportedMcsSet;
  private final boolean bit103OfSupportedMcsSet;
  private final boolean bit104OfSupportedMcsSet;
  private final boolean bit105OfSupportedMcsSet;
  private final boolean bit106OfSupportedMcsSet;
  private final boolean bit107OfSupportedMcsSet;
  private final boolean bit108OfSupportedMcsSet;
  private final boolean bit109OfSupportedMcsSet;
  private final boolean bit110OfSupportedMcsSet;
  private final boolean bit111OfSupportedMcsSet;
  private final boolean bit112OfSupportedMcsSet;
  private final boolean bit113OfSupportedMcsSet;
  private final boolean bit114OfSupportedMcsSet;
  private final boolean bit115OfSupportedMcsSet;
  private final boolean bit116OfSupportedMcsSet;
  private final boolean bit117OfSupportedMcsSet;
  private final boolean bit118OfSupportedMcsSet;
  private final boolean bit119OfSupportedMcsSet;
  private final boolean bit120OfSupportedMcsSet;
  private final boolean bit121OfSupportedMcsSet;
  private final boolean bit122OfSupportedMcsSet;
  private final boolean bit123OfSupportedMcsSet;
  private final boolean bit124OfSupportedMcsSet;
  private final boolean bit125OfSupportedMcsSet;
  private final boolean bit126OfSupportedMcsSet;
  private final boolean bit127OfSupportedMcsSet;
  private final boolean pcoSupported;
  private final PcoTransitionTime pcoTransitionTime;
  private final boolean bit3OfHtExtendedCapabilities;
  private final boolean bit4OfHtExtendedCapabilities;
  private final boolean bit5OfHtExtendedCapabilities;
  private final boolean bit6OfHtExtendedCapabilities;
  private final boolean bit7OfHtExtendedCapabilities;
  private final McsFeedbackCapability mcsFeedbackCapability;
  private final boolean htControlFieldSupported;
  private final boolean rdResponderSupported;
  private final boolean bit12OfHtExtendedCapabilities;
  private final boolean bit13OfHtExtendedCapabilities;
  private final boolean bit14OfHtExtendedCapabilities;
  private final boolean bit15OfHtExtendedCapabilities;
  private final boolean implicitTxBeamformingReceivingSupported;
  private final boolean rxStaggeredSoundingSupported;
  private final boolean txStaggeredSoundingSupported;
  private final boolean rxNdpSupported;
  private final boolean txNdpSupported;
  private final boolean implicitTxBeamformingSupported;
  private final Calibration calibration;
  private final boolean explicitCsiTxBeamformingSupported;
  private final boolean explicitNoncompressedSteeringSupported;
  private final boolean explicitCompressedSteeringSupported;
  private final BeamformingFeedbackCapability explicitTxBeamformingCsiFeedbackCapability;
  private final BeamformingFeedbackCapability explicitNoncompressedBeamformingFeedbackCapability;
  private final BeamformingFeedbackCapability explicitCompressedBeamformingFeedbackCapability;
  private final Grouping minGrouping;
  private final NumBeamformerAntennas csiNumBeamformerAntennasSupported;
  private final NumBeamformerAntennas noncompressedSteeringNumBeamformerAntennasSupported;
  private final NumBeamformerAntennas compressedSteeringNumBeamformerAntennasSupported;
  private final CsiNumRows csiMaxNumRowsBeamformerSupported;
  private final ChannelEstimationCapability channelEstimationCapability;
  private final boolean bit29OfTransmitBeamformingCapabilities;
  private final boolean bit30OfTransmitBeamformingCapabilities;
  private final boolean bit31OfTransmitBeamformingCapabilities;
  private final boolean antennaSelectionSupported;
  private final boolean explicitCsiFeedbackBasedTxAselSupported;
  private final boolean antennaIndicesFeedbackBasedTxAselSupported;
  private final boolean explicitCsiFeedbackSupported;
  private final boolean antennaIndicesFeedbackSupported;
  private final boolean rxAselSupported;
  private final boolean txSoundingPpdusSupported;
  private final boolean bit7OfAselCapability;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Dot11HTCapabilitiesElement object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Dot11HTCapabilitiesElement newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new Dot11HTCapabilitiesElement(rawData, offset, length);
  }

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  private Dot11HTCapabilitiesElement(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    super(rawData, offset, length, Dot11InformationElementId.HT_CAPABILITIES);

    if (getLengthAsInt() != 26) {
      throw new IllegalRawDataException(
          "The length must be 26 but is actually: " + getLengthAsInt());
    }

    byte data = rawData[offset + 2];
    this.ldpcCodingSupported = (data & 0x01) != 0;
    this.both20and40MhzSupported = (data & 0x02) != 0;
    this.smPowerSaveMode = SmPowerSaveMode.getInstance((data >> 2) & 0x03);
    this.htGreenfieldSupported = (data & 0x10) != 0;
    this.shortGiFor20MhzSupported = (data & 0x20) != 0;
    this.shortGiFor40MhzSupported = (data & 0x40) != 0;
    this.txStbcSupported = (data & 0x80) != 0;

    data = rawData[offset + 3];
    this.rxStbcSupport = StbcSupport.getInstance(data & 0x03);
    this.htDelayedBlockAckSupported = (data & 0x04) != 0;
    this.maxAMsduLength = AMsduLength.getInstance((data >> 3) & 0x01);
    this.dsssCckModeIn40MhzSupported = (data & 0x10) != 0;
    this.bit13OfHtCapabilitiesInfo = (data & 0x20) != 0;
    this.fortyMhzIntolerant = (data & 0x40) != 0;
    this.lSigTxopProtectionSupported = (data & 0x80) != 0;

    data = rawData[offset + 4];
    this.maxAMpduLength = AMpduLength.getInstance(data & 0x03);
    this.minMpduStartSpacing = MpduStartSpacing.getInstance((data >> 2) & 0x07);
    this.bit5OfAMpduParameters = (data & 0x20) != 0;
    this.bit6OfAMpduParameters = (data & 0x40) != 0;
    this.bit7OfAMpduParameters = (data & 0x80) != 0;

    this.supportedRxMcsIndexes = new boolean[77];
    for (int i = 0; i < 9; i++) {
      data = rawData[offset + 5 + i];
      int bitOffset = i * 8;
      for (int bit = 0; bit < 8; bit++) {
        supportedRxMcsIndexes[bitOffset + bit] = (data & 0x01) != 0;
        data >>= 1;
      }
    }

    data = rawData[offset + 14];
    for (int bit = 0; bit < 5; bit++) {
      supportedRxMcsIndexes[72 + bit] = (data & 0x01) != 0;
      data >>= 1;
    }
    this.bit77OfSupportedMcsSet = (data & 0x01) != 0;
    this.bit78OfSupportedMcsSet = (data & 0x02) != 0;
    this.bit79OfSupportedMcsSet = (data & 0x04) != 0;

    data = rawData[offset + 16];
    this.rxHighestSupportedDataRate = (short) ((rawData[offset + 15] | (data << 8)) & 0x03FF);
    this.bit90OfSupportedMcsSet = (data & 0x04) != 0;
    this.bit91OfSupportedMcsSet = (data & 0x08) != 0;
    this.bit92OfSupportedMcsSet = (data & 0x10) != 0;
    this.bit93OfSupportedMcsSet = (data & 0x20) != 0;
    this.bit94OfSupportedMcsSet = (data & 0x40) != 0;
    this.bit95OfSupportedMcsSet = (data & 0x80) != 0;

    data = rawData[offset + 17];
    this.txMcsSetDefined = (data & 0x01) != 0;
    this.txRxMcsSetNotEqual = (data & 0x02) != 0;
    this.txMaxNumSpatialStreamsSupported = NumSpatialStreams.getInstance((data >> 2) & 0x03);
    this.txUnequalModulationSupported = (data & 0x10) != 0;
    this.bit101OfSupportedMcsSet = (data & 0x20) != 0;
    this.bit102OfSupportedMcsSet = (data & 0x40) != 0;
    this.bit103OfSupportedMcsSet = (data & 0x80) != 0;

    data = rawData[offset + 18];
    this.bit104OfSupportedMcsSet = (data & 0x01) != 0;
    this.bit105OfSupportedMcsSet = (data & 0x02) != 0;
    this.bit106OfSupportedMcsSet = (data & 0x04) != 0;
    this.bit107OfSupportedMcsSet = (data & 0x08) != 0;
    this.bit108OfSupportedMcsSet = (data & 0x10) != 0;
    this.bit109OfSupportedMcsSet = (data & 0x20) != 0;
    this.bit110OfSupportedMcsSet = (data & 0x40) != 0;
    this.bit111OfSupportedMcsSet = (data & 0x80) != 0;

    data = rawData[offset + 19];
    this.bit112OfSupportedMcsSet = (data & 0x01) != 0;
    this.bit113OfSupportedMcsSet = (data & 0x02) != 0;
    this.bit114OfSupportedMcsSet = (data & 0x04) != 0;
    this.bit115OfSupportedMcsSet = (data & 0x08) != 0;
    this.bit116OfSupportedMcsSet = (data & 0x10) != 0;
    this.bit117OfSupportedMcsSet = (data & 0x20) != 0;
    this.bit118OfSupportedMcsSet = (data & 0x40) != 0;
    this.bit119OfSupportedMcsSet = (data & 0x80) != 0;

    data = rawData[offset + 20];
    this.bit120OfSupportedMcsSet = (data & 0x01) != 0;
    this.bit121OfSupportedMcsSet = (data & 0x02) != 0;
    this.bit122OfSupportedMcsSet = (data & 0x04) != 0;
    this.bit123OfSupportedMcsSet = (data & 0x08) != 0;
    this.bit124OfSupportedMcsSet = (data & 0x10) != 0;
    this.bit125OfSupportedMcsSet = (data & 0x20) != 0;
    this.bit126OfSupportedMcsSet = (data & 0x40) != 0;
    this.bit127OfSupportedMcsSet = (data & 0x80) != 0;

    data = rawData[offset + 21];
    this.pcoSupported = (data & 0x01) != 0;
    this.pcoTransitionTime = PcoTransitionTime.getInstance((data >> 1) & 0x03);
    this.bit3OfHtExtendedCapabilities = (data & 0x08) != 0;
    this.bit4OfHtExtendedCapabilities = (data & 0x10) != 0;
    this.bit5OfHtExtendedCapabilities = (data & 0x20) != 0;
    this.bit6OfHtExtendedCapabilities = (data & 0x40) != 0;
    this.bit7OfHtExtendedCapabilities = (data & 0x80) != 0;

    data = rawData[offset + 22];
    this.mcsFeedbackCapability = McsFeedbackCapability.getInstance(data & 0x03);
    this.htControlFieldSupported = (data & 0x04) != 0;
    this.rdResponderSupported = (data & 0x08) != 0;
    this.bit12OfHtExtendedCapabilities = (data & 0x10) != 0;
    this.bit13OfHtExtendedCapabilities = (data & 0x20) != 0;
    this.bit14OfHtExtendedCapabilities = (data & 0x40) != 0;
    this.bit15OfHtExtendedCapabilities = (data & 0x80) != 0;

    data = rawData[offset + 23];
    this.implicitTxBeamformingReceivingSupported = (data & 0x01) != 0;
    this.rxStaggeredSoundingSupported = (data & 0x02) != 0;
    this.txStaggeredSoundingSupported = (data & 0x04) != 0;
    this.rxNdpSupported = (data & 0x08) != 0;
    this.txNdpSupported = (data & 0x10) != 0;
    this.implicitTxBeamformingSupported = (data & 0x20) != 0;
    this.calibration = Calibration.getInstance((data >> 6) & 0x03);

    int intData = ByteArrays.getInt(rawData, offset + 24, ByteOrder.LITTLE_ENDIAN);
    this.explicitCsiTxBeamformingSupported = (intData & 0x01) != 0;
    this.explicitNoncompressedSteeringSupported = (intData & 0x02) != 0;
    this.explicitCompressedSteeringSupported = (intData & 0x04) != 0;
    this.explicitTxBeamformingCsiFeedbackCapability =
        BeamformingFeedbackCapability.getInstance((intData >> 3) & 0x03);
    this.explicitNoncompressedBeamformingFeedbackCapability =
        BeamformingFeedbackCapability.getInstance((intData >> 5) & 0x03);
    this.explicitCompressedBeamformingFeedbackCapability =
        BeamformingFeedbackCapability.getInstance((intData >> 7) & 0x03);
    this.minGrouping = Grouping.getInstance((intData >> 9) & 0x03);
    this.csiNumBeamformerAntennasSupported =
        NumBeamformerAntennas.getInstance((intData >> 11) & 0x03);
    this.noncompressedSteeringNumBeamformerAntennasSupported =
        NumBeamformerAntennas.getInstance((intData >> 13) & 0x03);
    this.compressedSteeringNumBeamformerAntennasSupported =
        NumBeamformerAntennas.getInstance((intData >> 15) & 0x03);
    this.csiMaxNumRowsBeamformerSupported = CsiNumRows.getInstance((intData >> 17) & 0x03);
    this.channelEstimationCapability =
        ChannelEstimationCapability.getInstance((intData >> 19) & 0x03);
    this.bit29OfTransmitBeamformingCapabilities = (intData & 0x200000) != 0;
    this.bit30OfTransmitBeamformingCapabilities = (intData & 0x400000) != 0;
    this.bit31OfTransmitBeamformingCapabilities = (intData & 0x800000) != 0;
    this.antennaSelectionSupported = (intData & 0x01000000) != 0;
    this.explicitCsiFeedbackBasedTxAselSupported = (intData & 0x02000000) != 0;
    this.antennaIndicesFeedbackBasedTxAselSupported = (intData & 0x04000000) != 0;
    this.explicitCsiFeedbackSupported = (intData & 0x08000000) != 0;
    this.antennaIndicesFeedbackSupported = (intData & 0x10000000) != 0;
    this.rxAselSupported = (intData & 0x20000000) != 0;
    this.txSoundingPpdusSupported = (intData & 0x40000000) != 0;
    this.bit7OfAselCapability = (intData & 0x80000000) != 0;
  }

  /** @param builder builder */
  private Dot11HTCapabilitiesElement(Builder builder) {
    super(builder);
    if (builder == null
        || builder.smPowerSaveMode == null
        || builder.rxStbcSupport == null
        || builder.maxAMsduLength == null
        || builder.maxAMpduLength == null
        || builder.minMpduStartSpacing == null
        || builder.supportedRxMcsIndexes == null
        || builder.txMaxNumSpatialStreamsSupported == null
        || builder.pcoTransitionTime == null
        || builder.mcsFeedbackCapability == null
        || builder.calibration == null
        || builder.explicitTxBeamformingCsiFeedbackCapability == null
        || builder.explicitNoncompressedBeamformingFeedbackCapability == null
        || builder.explicitCompressedBeamformingFeedbackCapability == null
        || builder.minGrouping == null
        || builder.csiNumBeamformerAntennasSupported == null
        || builder.noncompressedSteeringNumBeamformerAntennasSupported == null
        || builder.compressedSteeringNumBeamformerAntennasSupported == null
        || builder.csiMaxNumRowsBeamformerSupported == null
        || builder.channelEstimationCapability == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.smPowerSaveMode: ")
          .append(builder.smPowerSaveMode)
          .append(" builder.rxStbcSupport: ")
          .append(builder.rxStbcSupport)
          .append(" builder.maxAMsduLength: ")
          .append(builder.maxAMsduLength)
          .append(" builder.maxAMpduLength: ")
          .append(builder.maxAMpduLength)
          .append(" builder.minMpduStartSpacing: ")
          .append(builder.minMpduStartSpacing)
          .append(" builder.supportedRxMcsIndexes: ")
          .append(builder.supportedRxMcsIndexes)
          .append(" builder.txMaxNumSpatialStreamsSupported: ")
          .append(builder.txMaxNumSpatialStreamsSupported)
          .append(" builder.pcoTransitionTime: ")
          .append(builder.pcoTransitionTime)
          .append(" builder.mcsFeedbackCapability: ")
          .append(builder.mcsFeedbackCapability)
          .append(" builder.calibration: ")
          .append(builder.calibration)
          .append(" builder.explicitTxBeamformingCsiFeedbackCapability: ")
          .append(builder.explicitTxBeamformingCsiFeedbackCapability)
          .append(" builder.explicitNoncompressedBeamformingFeedbackCapability: ")
          .append(builder.explicitNoncompressedBeamformingFeedbackCapability)
          .append(" builder.explicitCompressedBeamformingFeedbackCapability: ")
          .append(builder.explicitCompressedBeamformingFeedbackCapability)
          .append(" builder.minGrouping: ")
          .append(builder.minGrouping)
          .append(" builder.csiNumBeamformerAntennasSupported: ")
          .append(builder.csiNumBeamformerAntennasSupported)
          .append(" builder.noncompressedSteeringNumBeamformerAntennasSupported: ")
          .append(builder.noncompressedSteeringNumBeamformerAntennasSupported)
          .append(" builder.compressedSteeringNumBeamformerAntennasSupported: ")
          .append(builder.compressedSteeringNumBeamformerAntennasSupported)
          .append(" builder.csiMaxNumRowsBeamformerSupported: ")
          .append(builder.csiMaxNumRowsBeamformerSupported)
          .append(" builder.channelEstimationCapability: ")
          .append(builder.channelEstimationCapability);
      throw new NullPointerException(sb.toString());
    }
    if (builder.supportedRxMcsIndexes.length != 77) {
      throw new IllegalArgumentException(
          "supportedRxMcsIndexes.length must be 77. builder.supportedRxMcsIndexes.length: "
              + builder.supportedRxMcsIndexes.length);
    }
    if ((builder.rxHighestSupportedDataRate & 0xFC00) != 0) {
      throw new IllegalArgumentException(
          "(rxHighestSupportedDataRate & 0xFC00) must be zero."
              + " builder.rxHighestSupportedDataRate: "
              + builder.rxHighestSupportedDataRate);
    }

    this.ldpcCodingSupported = builder.ldpcCodingSupported;
    this.both20and40MhzSupported = builder.both20and40MhzSupported;
    this.smPowerSaveMode = builder.smPowerSaveMode;
    this.htGreenfieldSupported = builder.htGreenfieldSupported;
    this.shortGiFor20MhzSupported = builder.shortGiFor20MhzSupported;
    this.shortGiFor40MhzSupported = builder.shortGiFor40MhzSupported;
    this.txStbcSupported = builder.txStbcSupported;
    this.rxStbcSupport = builder.rxStbcSupport;
    this.htDelayedBlockAckSupported = builder.htDelayedBlockAckSupported;
    this.maxAMsduLength = builder.maxAMsduLength;
    this.dsssCckModeIn40MhzSupported = builder.dsssCckModeIn40MhzSupported;
    this.bit13OfHtCapabilitiesInfo = builder.bit13OfHtCapabilitiesInfo;
    this.fortyMhzIntolerant = builder.fortyMhzIntolerant;
    this.lSigTxopProtectionSupported = builder.lSigTxopProtectionSupported;
    this.maxAMpduLength = builder.maxAMpduLength;
    this.minMpduStartSpacing = builder.minMpduStartSpacing;
    this.bit5OfAMpduParameters = builder.bit5OfAMpduParameters;
    this.bit6OfAMpduParameters = builder.bit6OfAMpduParameters;
    this.bit7OfAMpduParameters = builder.bit7OfAMpduParameters;
    this.supportedRxMcsIndexes = builder.supportedRxMcsIndexes;
    this.bit77OfSupportedMcsSet = builder.bit77OfSupportedMcsSet;
    this.bit78OfSupportedMcsSet = builder.bit78OfSupportedMcsSet;
    this.bit79OfSupportedMcsSet = builder.bit79OfSupportedMcsSet;
    this.rxHighestSupportedDataRate = builder.rxHighestSupportedDataRate;
    this.bit90OfSupportedMcsSet = builder.bit90OfSupportedMcsSet;
    this.bit91OfSupportedMcsSet = builder.bit91OfSupportedMcsSet;
    this.bit92OfSupportedMcsSet = builder.bit92OfSupportedMcsSet;
    this.bit93OfSupportedMcsSet = builder.bit93OfSupportedMcsSet;
    this.bit94OfSupportedMcsSet = builder.bit94OfSupportedMcsSet;
    this.bit95OfSupportedMcsSet = builder.bit95OfSupportedMcsSet;
    this.txMcsSetDefined = builder.txMcsSetDefined;
    this.txRxMcsSetNotEqual = builder.txRxMcsSetNotEqual;
    this.txMaxNumSpatialStreamsSupported = builder.txMaxNumSpatialStreamsSupported;
    this.txUnequalModulationSupported = builder.txUnequalModulationSupported;
    this.bit101OfSupportedMcsSet = builder.bit101OfSupportedMcsSet;
    this.bit102OfSupportedMcsSet = builder.bit102OfSupportedMcsSet;
    this.bit103OfSupportedMcsSet = builder.bit103OfSupportedMcsSet;
    this.bit104OfSupportedMcsSet = builder.bit104OfSupportedMcsSet;
    this.bit105OfSupportedMcsSet = builder.bit105OfSupportedMcsSet;
    this.bit106OfSupportedMcsSet = builder.bit106OfSupportedMcsSet;
    this.bit107OfSupportedMcsSet = builder.bit107OfSupportedMcsSet;
    this.bit108OfSupportedMcsSet = builder.bit108OfSupportedMcsSet;
    this.bit109OfSupportedMcsSet = builder.bit109OfSupportedMcsSet;
    this.bit110OfSupportedMcsSet = builder.bit110OfSupportedMcsSet;
    this.bit111OfSupportedMcsSet = builder.bit111OfSupportedMcsSet;
    this.bit112OfSupportedMcsSet = builder.bit112OfSupportedMcsSet;
    this.bit113OfSupportedMcsSet = builder.bit113OfSupportedMcsSet;
    this.bit114OfSupportedMcsSet = builder.bit114OfSupportedMcsSet;
    this.bit115OfSupportedMcsSet = builder.bit115OfSupportedMcsSet;
    this.bit116OfSupportedMcsSet = builder.bit116OfSupportedMcsSet;
    this.bit117OfSupportedMcsSet = builder.bit117OfSupportedMcsSet;
    this.bit118OfSupportedMcsSet = builder.bit118OfSupportedMcsSet;
    this.bit119OfSupportedMcsSet = builder.bit119OfSupportedMcsSet;
    this.bit120OfSupportedMcsSet = builder.bit120OfSupportedMcsSet;
    this.bit121OfSupportedMcsSet = builder.bit121OfSupportedMcsSet;
    this.bit122OfSupportedMcsSet = builder.bit122OfSupportedMcsSet;
    this.bit123OfSupportedMcsSet = builder.bit123OfSupportedMcsSet;
    this.bit124OfSupportedMcsSet = builder.bit124OfSupportedMcsSet;
    this.bit125OfSupportedMcsSet = builder.bit125OfSupportedMcsSet;
    this.bit126OfSupportedMcsSet = builder.bit126OfSupportedMcsSet;
    this.bit127OfSupportedMcsSet = builder.bit127OfSupportedMcsSet;
    this.pcoSupported = builder.pcoSupported;
    this.pcoTransitionTime = builder.pcoTransitionTime;
    this.bit3OfHtExtendedCapabilities = builder.bit3OfHtExtendedCapabilities;
    this.bit4OfHtExtendedCapabilities = builder.bit4OfHtExtendedCapabilities;
    this.bit5OfHtExtendedCapabilities = builder.bit5OfHtExtendedCapabilities;
    this.bit6OfHtExtendedCapabilities = builder.bit6OfHtExtendedCapabilities;
    this.bit7OfHtExtendedCapabilities = builder.bit7OfHtExtendedCapabilities;
    this.mcsFeedbackCapability = builder.mcsFeedbackCapability;
    this.htControlFieldSupported = builder.htControlFieldSupported;
    this.rdResponderSupported = builder.rdResponderSupported;
    this.bit12OfHtExtendedCapabilities = builder.bit12OfHtExtendedCapabilities;
    this.bit13OfHtExtendedCapabilities = builder.bit13OfHtExtendedCapabilities;
    this.bit14OfHtExtendedCapabilities = builder.bit14OfHtExtendedCapabilities;
    this.bit15OfHtExtendedCapabilities = builder.bit15OfHtExtendedCapabilities;
    this.implicitTxBeamformingReceivingSupported = builder.implicitTxBeamformingReceivingSupported;
    this.rxStaggeredSoundingSupported = builder.rxStaggeredSoundingSupported;
    this.txStaggeredSoundingSupported = builder.txStaggeredSoundingSupported;
    this.rxNdpSupported = builder.rxNdpSupported;
    this.txNdpSupported = builder.txNdpSupported;
    this.implicitTxBeamformingSupported = builder.implicitTxBeamformingSupported;
    this.calibration = builder.calibration;
    this.explicitCsiTxBeamformingSupported = builder.explicitCsiTxBeamformingSupported;
    this.explicitNoncompressedSteeringSupported = builder.explicitNoncompressedSteeringSupported;
    this.explicitCompressedSteeringSupported = builder.explicitCompressedSteeringSupported;
    this.explicitTxBeamformingCsiFeedbackCapability =
        builder.explicitTxBeamformingCsiFeedbackCapability;
    this.explicitNoncompressedBeamformingFeedbackCapability =
        builder.explicitNoncompressedBeamformingFeedbackCapability;
    this.explicitCompressedBeamformingFeedbackCapability =
        builder.explicitCompressedBeamformingFeedbackCapability;
    this.minGrouping = builder.minGrouping;
    this.csiNumBeamformerAntennasSupported = builder.csiNumBeamformerAntennasSupported;
    this.noncompressedSteeringNumBeamformerAntennasSupported =
        builder.noncompressedSteeringNumBeamformerAntennasSupported;
    this.compressedSteeringNumBeamformerAntennasSupported =
        builder.compressedSteeringNumBeamformerAntennasSupported;
    this.csiMaxNumRowsBeamformerSupported = builder.csiMaxNumRowsBeamformerSupported;
    this.channelEstimationCapability = builder.channelEstimationCapability;
    this.bit29OfTransmitBeamformingCapabilities = builder.bit29OfTransmitBeamformingCapabilities;
    this.bit30OfTransmitBeamformingCapabilities = builder.bit30OfTransmitBeamformingCapabilities;
    this.bit31OfTransmitBeamformingCapabilities = builder.bit31OfTransmitBeamformingCapabilities;
    this.antennaSelectionSupported = builder.antennaSelectionSupported;
    this.explicitCsiFeedbackBasedTxAselSupported = builder.explicitCsiFeedbackBasedTxAselSupported;
    this.antennaIndicesFeedbackBasedTxAselSupported =
        builder.antennaIndicesFeedbackBasedTxAselSupported;
    this.explicitCsiFeedbackSupported = builder.explicitCsiFeedbackSupported;
    this.antennaIndicesFeedbackSupported = builder.antennaIndicesFeedbackSupported;
    this.rxAselSupported = builder.rxAselSupported;
    this.txSoundingPpdusSupported = builder.txSoundingPpdusSupported;
    this.bit7OfAselCapability = builder.bit7OfAselCapability;
  }

  /** @return true if the LDPC Coding Capability field is set to 1; false otherwise. */
  public boolean isLdpcCodingSupported() {
    return ldpcCodingSupported;
  }

  /** @return true if the Supported Channel Width Set field is set to 1; false otherwise. */
  public boolean isBoth20and40MhzSupported() {
    return both20and40MhzSupported;
  }

  /** @return smPowerSaveMode */
  public SmPowerSaveMode getSmPowerSaveMode() {
    return smPowerSaveMode;
  }

  /** @return true if the HT-Greenfield field is set to 1; false otherwise. */
  public boolean isHtGreenfieldSupported() {
    return htGreenfieldSupported;
  }

  /** @return true if the Short GI for 20 MHz field is set to 1; false otherwise. */
  public boolean isShortGiFor20MhzSupported() {
    return shortGiFor20MhzSupported;
  }

  /** @return true if the Short GI for 40 MHz field is set to 1; false otherwise. */
  public boolean isShortGiFor40MhzSupported() {
    return shortGiFor40MhzSupported;
  }

  /** @return true if the Tx STBC field is set to 1; false otherwise. */
  public boolean isTxStbcSupported() {
    return txStbcSupported;
  }

  /** @return rxStbcSupport */
  public StbcSupport getRxStbcSupport() {
    return rxStbcSupport;
  }

  /** @return true if the HT-Delayed Block Ack field is set to 1; false otherwise. */
  public boolean isHtDelayedBlockAckSupported() {
    return htDelayedBlockAckSupported;
  }

  /** @return maxAMsduLength */
  public AMsduLength getMaxAMsduLength() {
    return maxAMsduLength;
  }

  /** @return true if the DSSS/CCK Mode in 40 MHz field is set to 1; false otherwise. */
  public boolean isDsssCckModeIn40MhzSupported() {
    return dsssCckModeIn40MhzSupported;
  }

  /** @return true if the bit 13 of the HT Capabilities Info field is set to 1; false otherwise. */
  public boolean getBit13OfHtCapabilitiesInfo() {
    return bit13OfHtCapabilitiesInfo;
  }

  /** @return true if the Forty MHz Intolerant field is set to 1; false otherwise. */
  public boolean isFortyMhzIntolerant() {
    return fortyMhzIntolerant;
  }

  /** @return true if the L-SIG TXOP Protection Support field is set to 1; false otherwise. */
  public boolean islSigTxopProtectionSupported() {
    return lSigTxopProtectionSupported;
  }

  /** @return maxAMpduLength */
  public AMpduLength getMaxAMpduLength() {
    return maxAMpduLength;
  }

  /** @return minMpduStartSpacing */
  public MpduStartSpacing getMinMpduStartSpacing() {
    return minMpduStartSpacing;
  }

  /** @return true if the bit 5 of the A-MPDU Parameters field is set to 1; false otherwise. */
  public boolean getBit5OfAMpduParameters() {
    return bit5OfAMpduParameters;
  }

  /** @return true if the bit 6 of the A-MPDU Parameters field is set to 1; false otherwise. */
  public boolean getBit6OfAMpduParameters() {
    return bit6OfAMpduParameters;
  }

  /** @return true if the bit 7 of the A-MPDU Parameters field is set to 1; false otherwise. */
  public boolean getBit7OfAMpduParameters() {
    return bit7OfAMpduParameters;
  }

  /**
   * @return supportedRxMcsIndexes. supportedRxMcsIndexes[x] is set to true if the bit x of the Rx
   *     MCS Bitmask is set to 1; otherwise supportedRxMcsIndexes[x] is set to false.
   */
  public boolean[] getSupportedRxMcsIndexes() {
    boolean[] clone = new boolean[77];
    System.arraycopy(supportedRxMcsIndexes, 0, clone, 0, clone.length);
    return clone;
  }

  /** @return true if the bit 77 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit77OfSupportedMcsSet() {
    return bit77OfSupportedMcsSet;
  }

  /** @return true if the bit 78 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit78OfSupportedMcsSet() {
    return bit78OfSupportedMcsSet;
  }

  /** @return true if the bit 79 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit79OfSupportedMcsSet() {
    return bit79OfSupportedMcsSet;
  }

  /** @return rxHighestSupportedDataRate */
  public short getRxHighestSupportedDataRate() {
    return rxHighestSupportedDataRate;
  }

  /** @return rxHighestSupportedDataRate */
  public int getRxHighestSupportedDataRateAsInt() {
    return rxHighestSupportedDataRate;
  }

  /** @return true if the bit 90 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit90OfSupportedMcsSet() {
    return bit90OfSupportedMcsSet;
  }

  /** @return true if the bit 91 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit91OfSupportedMcsSet() {
    return bit91OfSupportedMcsSet;
  }

  /** @return true if the bit 92 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit92OfSupportedMcsSet() {
    return bit92OfSupportedMcsSet;
  }

  /** @return true if the bit 93 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit93OfSupportedMcsSet() {
    return bit93OfSupportedMcsSet;
  }

  /** @return true if the bit 94 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit94OfSupportedMcsSet() {
    return bit94OfSupportedMcsSet;
  }

  /** @return true if the bit 95 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit95OfSupportedMcsSet() {
    return bit95OfSupportedMcsSet;
  }

  /** @return true if the Tx MCS Set Defined field is set to 1; false otherwise. */
  public boolean isTxMcsSetDefined() {
    return txMcsSetDefined;
  }

  /** @return true if the Tx Rx MCS Set Not Equal field is set to 1; false otherwise. */
  public boolean isTxRxMcsSetNotEqual() {
    return txRxMcsSetNotEqual;
  }

  /** @return txMaxNumSpatialStreamsSupported */
  public NumSpatialStreams getTxMaxNumSpatialStreamsSupported() {
    return txMaxNumSpatialStreamsSupported;
  }

  /** @return true if the Tx Unequal Modulation Supported field is set to 1; false otherwise. */
  public boolean isTxUnequalModulationSupported() {
    return txUnequalModulationSupported;
  }

  /** @return true if the bit 101 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit101OfSupportedMcsSet() {
    return bit101OfSupportedMcsSet;
  }

  /** @return true if the bit 102 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit102OfSupportedMcsSet() {
    return bit102OfSupportedMcsSet;
  }

  /** @return true if the bit 103 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit103OfSupportedMcsSet() {
    return bit103OfSupportedMcsSet;
  }

  /** @return true if the bit 104 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit104OfSupportedMcsSet() {
    return bit104OfSupportedMcsSet;
  }

  /** @return true if the bit 105 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit105OfSupportedMcsSet() {
    return bit105OfSupportedMcsSet;
  }

  /** @return true if the bit 106 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit106OfSupportedMcsSet() {
    return bit106OfSupportedMcsSet;
  }

  /** @return true if the bit 107 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit107OfSupportedMcsSet() {
    return bit107OfSupportedMcsSet;
  }

  /** @return true if the bit 108 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit108OfSupportedMcsSet() {
    return bit108OfSupportedMcsSet;
  }

  /** @return true if the bit 109 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit109OfSupportedMcsSet() {
    return bit109OfSupportedMcsSet;
  }

  /** @return true if the bit 110 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit110OfSupportedMcsSet() {
    return bit110OfSupportedMcsSet;
  }

  /** @return true if the bit 111 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit111OfSupportedMcsSet() {
    return bit111OfSupportedMcsSet;
  }

  /** @return true if the bit 112 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit112OfSupportedMcsSet() {
    return bit112OfSupportedMcsSet;
  }

  /** @return true if the bit 113 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit113OfSupportedMcsSet() {
    return bit113OfSupportedMcsSet;
  }

  /** @return true if the bit 114 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit114OfSupportedMcsSet() {
    return bit114OfSupportedMcsSet;
  }

  /** @return true if the bit 115 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit115OfSupportedMcsSet() {
    return bit115OfSupportedMcsSet;
  }

  /** @return true if the bit 116 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit116OfSupportedMcsSet() {
    return bit116OfSupportedMcsSet;
  }

  /** @return true if the bit 117 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit117OfSupportedMcsSet() {
    return bit117OfSupportedMcsSet;
  }

  /** @return true if the bit 118 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit118OfSupportedMcsSet() {
    return bit118OfSupportedMcsSet;
  }

  /** @return true if the bit 119 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit119OfSupportedMcsSet() {
    return bit119OfSupportedMcsSet;
  }

  /** @return true if the bit 120 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit120OfSupportedMcsSet() {
    return bit120OfSupportedMcsSet;
  }

  /** @return true if the bit 121 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit121OfSupportedMcsSet() {
    return bit121OfSupportedMcsSet;
  }

  /** @return true if the bit 122 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit122OfSupportedMcsSet() {
    return bit122OfSupportedMcsSet;
  }

  /** @return true if the bit 123 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit123OfSupportedMcsSet() {
    return bit123OfSupportedMcsSet;
  }

  /** @return true if the bit 124 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit124OfSupportedMcsSet() {
    return bit124OfSupportedMcsSet;
  }

  /** @return true if the bit 125 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit125OfSupportedMcsSet() {
    return bit125OfSupportedMcsSet;
  }

  /** @return true if the bit 126 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit126OfSupportedMcsSet() {
    return bit126OfSupportedMcsSet;
  }

  /** @return true if the bit 127 of the Supported MCS Set field is set to 1; false otherwise. */
  public boolean getBit127OfSupportedMcsSet() {
    return bit127OfSupportedMcsSet;
  }

  /** @return true if the PCO field is set to 1; false otherwise. */
  public boolean isPcoSupported() {
    return pcoSupported;
  }

  /** @return pcoTransitionTime */
  public PcoTransitionTime getPcoTransitionTime() {
    return pcoTransitionTime;
  }

  /** @return true if the field is set to 1; false otherwise. */
  public boolean getBit3OfHtExtendedCapabilities() {
    return bit3OfHtExtendedCapabilities;
  }

  /**
   * @return true if the bit 4 of the HT Extended Capabilities field is set to 1; false otherwise.
   */
  public boolean getBit4OfHtExtendedCapabilities() {
    return bit4OfHtExtendedCapabilities;
  }

  /**
   * @return true if the bit 5 of the HT Extended Capabilities field is set to 1; false otherwise.
   */
  public boolean getBit5OfHtExtendedCapabilities() {
    return bit5OfHtExtendedCapabilities;
  }

  /**
   * @return true if the bit 6 of the HT Extended Capabilities field is set to 1; false otherwise.
   */
  public boolean getBit6OfHtExtendedCapabilities() {
    return bit6OfHtExtendedCapabilities;
  }

  /**
   * @return true if the bit 7 of the HT Extended Capabilities field is set to 1; false otherwise.
   */
  public boolean getBit7OfHtExtendedCapabilities() {
    return bit7OfHtExtendedCapabilities;
  }

  /** @return mcsFeedbackCapability */
  public McsFeedbackCapability getMcsFeedbackCapability() {
    return mcsFeedbackCapability;
  }

  /** @return true if the +HTC Support field is set to 1; false otherwise. */
  public boolean isHtControlFieldSupported() {
    return htControlFieldSupported;
  }

  /** @return true if the RD Responder field is set to 1; false otherwise. */
  public boolean isRdResponderSupported() {
    return rdResponderSupported;
  }

  /**
   * @return true if the bit 12 of the HT Extended Capabilities field is set to 1; false otherwise.
   */
  public boolean getBit12OfHtExtendedCapabilities() {
    return bit12OfHtExtendedCapabilities;
  }

  /**
   * @return true if the bit 13 of the HT Extended Capabilities field is set to 1; false otherwise.
   */
  public boolean getBit13OfHtExtendedCapabilities() {
    return bit13OfHtExtendedCapabilities;
  }

  /**
   * @return true if the bit 14 of the HT Extended Capabilities field is set to 1; false otherwise.
   */
  public boolean getBit14OfHtExtendedCapabilities() {
    return bit14OfHtExtendedCapabilities;
  }

  /**
   * @return true if the bit 15 of the HT Extended Capabilities field is set to 1; false otherwise.
   */
  public boolean getBit15OfHtExtendedCapabilities() {
    return bit15OfHtExtendedCapabilities;
  }

  /**
   * @return true if the Implicit Transmit Beamforming Receiving Capable field is set to 1; false
   *     otherwise.
   */
  public boolean isImplicitTxBeamformingReceivingSupported() {
    return implicitTxBeamformingReceivingSupported;
  }

  /** @return true if the Receive Staggered Sounding Capable field is set to 1; false otherwise. */
  public boolean isRxStaggeredSoundingSupported() {
    return rxStaggeredSoundingSupported;
  }

  /** @return true if the Transmit Staggered Sounding Capable field is set to 1; false otherwise. */
  public boolean isTxStaggeredSoundingSupported() {
    return txStaggeredSoundingSupported;
  }

  /** @return true if the Receive NDP Capable field is set to 1; false otherwise. */
  public boolean isRxNdpSupported() {
    return rxNdpSupported;
  }

  /** @return true if the Transmit NDP Capable field is set to 1; false otherwise. */
  public boolean isTxNdpSupported() {
    return txNdpSupported;
  }

  /**
   * @return true if the Implicit Transmit Beamforming Capable field is set to 1; false otherwise.
   */
  public boolean isImplicitTxBeamformingSupported() {
    return implicitTxBeamformingSupported;
  }

  /** @return calibration */
  public Calibration getCalibration() {
    return calibration;
  }

  /**
   * @return true if the Explicit CSI Transmit Beamforming Capable field is set to 1; false
   *     otherwise.
   */
  public boolean isExplicitCsiTxBeamformingSupported() {
    return explicitCsiTxBeamformingSupported;
  }

  /**
   * @return true if the Explicit Noncompressed Steering Capable field is set to 1; false otherwise.
   */
  public boolean isExplicitNoncompressedSteeringSupported() {
    return explicitNoncompressedSteeringSupported;
  }

  /**
   * @return true if the Explicit Compressed Steering Capable field is set to 1; false otherwise.
   */
  public boolean isExplicitCompressedSteeringSupported() {
    return explicitCompressedSteeringSupported;
  }

  /** @return explicitTxBeamformingCsiFeedbackCapability */
  public BeamformingFeedbackCapability getExplicitTxBeamformingCsiFeedbackCapability() {
    return explicitTxBeamformingCsiFeedbackCapability;
  }

  /** @return explicitNoncompressedBeamformingFeedbackCapability */
  public BeamformingFeedbackCapability getExplicitNoncompressedBeamformingFeedbackCapability() {
    return explicitNoncompressedBeamformingFeedbackCapability;
  }

  /** @return explicitCompressedBeamformingFeedbackCapability */
  public BeamformingFeedbackCapability getExplicitCompressedBeamformingFeedbackCapability() {
    return explicitCompressedBeamformingFeedbackCapability;
  }

  /** @return minGrouping */
  public Grouping getMinGrouping() {
    return minGrouping;
  }

  /** @return csiNumBeamformerAntennasSupported */
  public NumBeamformerAntennas getCsiNumBeamformerAntennasSupported() {
    return csiNumBeamformerAntennasSupported;
  }

  /** @return noncompressedSteeringNumBeamformerAntennasSupported */
  public NumBeamformerAntennas getNoncompressedSteeringNumBeamformerAntennasSupported() {
    return noncompressedSteeringNumBeamformerAntennasSupported;
  }

  /** @return compressedSteeringNumBeamformerAntennasSupported */
  public NumBeamformerAntennas getCompressedSteeringNumBeamformerAntennasSupported() {
    return compressedSteeringNumBeamformerAntennasSupported;
  }

  /** @return csiMaxNumRowsBeamformerSupported */
  public CsiNumRows getCsiMaxNumRowsBeamformerSupported() {
    return csiMaxNumRowsBeamformerSupported;
  }

  /** @return channelEstimationCapability */
  public ChannelEstimationCapability getChannelEstimationCapability() {
    return channelEstimationCapability;
  }

  /**
   * @return true if the bit 29 of the Transmit Beamforming Capabilities field is set to 1; false
   *     otherwise.
   */
  public boolean getBit29OfTransmitBeamformingCapabilities() {
    return bit29OfTransmitBeamformingCapabilities;
  }

  /**
   * @return true if the bit 30 of the Transmit Beamforming Capabilities field is set to 1; false
   *     otherwise.
   */
  public boolean getBit30OfTransmitBeamformingCapabilities() {
    return bit30OfTransmitBeamformingCapabilities;
  }

  /**
   * @return true if the bit 31 of the Transmit Beamforming Capabilities field is set to 1; false
   *     otherwise.
   */
  public boolean getBit31OfTransmitBeamformingCapabilities() {
    return bit31OfTransmitBeamformingCapabilities;
  }

  /** @return true if the Antenna Selection Capable field is set to 1; false otherwise. */
  public boolean isAntennaSelectionSupported() {
    return antennaSelectionSupported;
  }

  /**
   * @return true if the Explicit CSI Feedback Based Transmit ASEL Capable field is set to 1; false
   *     otherwise.
   */
  public boolean isExplicitCsiFeedbackBasedTxAselSupported() {
    return explicitCsiFeedbackBasedTxAselSupported;
  }

  /**
   * @return true if the Antenna Indices Feedback Based Transmit ASEL Capable field is set to 1;
   *     false otherwise.
   */
  public boolean isAntennaIndicesFeedbackBasedTxAselSupported() {
    return antennaIndicesFeedbackBasedTxAselSupported;
  }

  /** @return true if the Explicit CSI Feedback Capable field is set to 1; false otherwise. */
  public boolean isExplicitCsiFeedbackSupported() {
    return explicitCsiFeedbackSupported;
  }

  /** @return true if the Antenna Indices Feedback Capable field is set to 1; false otherwise. */
  public boolean isAntennaIndicesFeedbackSupported() {
    return antennaIndicesFeedbackSupported;
  }

  /** @return true if the Receive ASEL Capable field is set to 1; false otherwise. */
  public boolean isRxAselSupported() {
    return rxAselSupported;
  }

  /** @return true if the Transmit Sounding PPDUs Capable field is set to 1; false otherwise. */
  public boolean isTxSoundingPpdusSupported() {
    return txSoundingPpdusSupported;
  }

  /** @return true if the bit 70 of the ASEL Capability field is set to 1; false otherwise. */
  public boolean getBit7OfAselCapability() {
    return bit7OfAselCapability;
  }

  @Override
  public int length() {
    return 28;
  }

  @Override
  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[0] = getElementId().value();
    rawData[1] = getLength();

    int idx = 2;
    rawData[idx] = (byte) (smPowerSaveMode.value << 2);
    if (ldpcCodingSupported) {
      rawData[idx] |= 0x01;
    }
    if (both20and40MhzSupported) {
      rawData[idx] |= 0x02;
    }
    if (htGreenfieldSupported) {
      rawData[idx] |= 0x10;
    }
    if (shortGiFor20MhzSupported) {
      rawData[idx] |= 0x20;
    }
    if (shortGiFor40MhzSupported) {
      rawData[idx] |= 0x40;
    }
    if (txStbcSupported) {
      rawData[idx] |= 0x80;
    }

    idx = 3;
    rawData[idx] = (byte) (rxStbcSupport.value | (maxAMsduLength.value << 3));
    if (htDelayedBlockAckSupported) {
      rawData[idx] |= 0x04;
    }
    if (dsssCckModeIn40MhzSupported) {
      rawData[idx] |= 0x10;
    }
    if (bit13OfHtCapabilitiesInfo) {
      rawData[idx] |= 0x20;
    }
    if (fortyMhzIntolerant) {
      rawData[idx] |= 0x40;
    }
    if (lSigTxopProtectionSupported) {
      rawData[idx] |= 0x80;
    }

    idx = 4;
    rawData[idx] = (byte) (maxAMpduLength.value | (minMpduStartSpacing.value << 2));
    if (bit5OfAMpduParameters) {
      rawData[idx] |= 0x20;
    }
    if (bit6OfAMpduParameters) {
      rawData[idx] |= 0x40;
    }
    if (bit7OfAMpduParameters) {
      rawData[idx] |= 0x80;
    }

    for (int i = 0; i < supportedRxMcsIndexes.length; i++) {
      if (supportedRxMcsIndexes[i]) {
        idx = 5 + i / 8;
        switch (i % 8) {
          case 0:
            rawData[idx] |= 0x01;
            break;
          case 1:
            rawData[idx] |= 0x02;
            break;
          case 2:
            rawData[idx] |= 0x04;
            break;
          case 3:
            rawData[idx] |= 0x08;
            break;
          case 4:
            rawData[idx] |= 0x10;
            break;
          case 5:
            rawData[idx] |= 0x20;
            break;
          case 6:
            rawData[idx] |= 0x40;
            break;
          case 7:
            rawData[idx] |= 0x80;
            break;
        }
      }
    }

    idx = 14;
    if (bit77OfSupportedMcsSet) {
      rawData[idx] |= 0x20;
    }
    if (bit78OfSupportedMcsSet) {
      rawData[idx] |= 0x40;
    }
    if (bit79OfSupportedMcsSet) {
      rawData[idx] |= 0x80;
    }

    System.arraycopy(
        ByteArrays.toByteArray(rxHighestSupportedDataRate, ByteOrder.LITTLE_ENDIAN),
        0,
        rawData,
        15,
        2);

    idx = 16;
    if (bit90OfSupportedMcsSet) {
      rawData[idx] |= 0x04;
    }
    if (bit91OfSupportedMcsSet) {
      rawData[idx] |= 0x08;
    }
    if (bit92OfSupportedMcsSet) {
      rawData[idx] |= 0x10;
    }
    if (bit93OfSupportedMcsSet) {
      rawData[idx] |= 0x20;
    }
    if (bit94OfSupportedMcsSet) {
      rawData[idx] |= 0x40;
    }
    if (bit95OfSupportedMcsSet) {
      rawData[idx] |= 0x80;
    }

    idx = 17;
    rawData[idx] = (byte) (txMaxNumSpatialStreamsSupported.value << 2);
    if (txMcsSetDefined) {
      rawData[idx] |= 0x01;
    }
    if (txRxMcsSetNotEqual) {
      rawData[idx] |= 0x02;
    }
    if (txUnequalModulationSupported) {
      rawData[idx] |= 0x10;
    }
    if (bit101OfSupportedMcsSet) {
      rawData[idx] |= 0x20;
    }
    if (bit102OfSupportedMcsSet) {
      rawData[idx] |= 0x40;
    }
    if (bit103OfSupportedMcsSet) {
      rawData[idx] |= 0x80;
    }

    idx = 18;
    if (bit104OfSupportedMcsSet) {
      rawData[idx] |= 0x01;
    }
    if (bit105OfSupportedMcsSet) {
      rawData[idx] |= 0x02;
    }
    if (bit106OfSupportedMcsSet) {
      rawData[idx] |= 0x04;
    }
    if (bit107OfSupportedMcsSet) {
      rawData[idx] |= 0x08;
    }
    if (bit108OfSupportedMcsSet) {
      rawData[idx] |= 0x10;
    }
    if (bit109OfSupportedMcsSet) {
      rawData[idx] |= 0x20;
    }
    if (bit110OfSupportedMcsSet) {
      rawData[idx] |= 0x40;
    }
    if (bit111OfSupportedMcsSet) {
      rawData[idx] |= 0x80;
    }

    idx = 19;
    if (bit112OfSupportedMcsSet) {
      rawData[idx] |= 0x01;
    }
    if (bit113OfSupportedMcsSet) {
      rawData[idx] |= 0x02;
    }
    if (bit114OfSupportedMcsSet) {
      rawData[idx] |= 0x04;
    }
    if (bit115OfSupportedMcsSet) {
      rawData[idx] |= 0x08;
    }
    if (bit116OfSupportedMcsSet) {
      rawData[idx] |= 0x10;
    }
    if (bit117OfSupportedMcsSet) {
      rawData[idx] |= 0x20;
    }
    if (bit118OfSupportedMcsSet) {
      rawData[idx] |= 0x40;
    }
    if (bit119OfSupportedMcsSet) {
      rawData[idx] |= 0x80;
    }

    idx = 20;
    if (bit120OfSupportedMcsSet) {
      rawData[idx] |= 0x01;
    }
    if (bit121OfSupportedMcsSet) {
      rawData[idx] |= 0x02;
    }
    if (bit122OfSupportedMcsSet) {
      rawData[idx] |= 0x04;
    }
    if (bit123OfSupportedMcsSet) {
      rawData[idx] |= 0x08;
    }
    if (bit124OfSupportedMcsSet) {
      rawData[idx] |= 0x10;
    }
    if (bit125OfSupportedMcsSet) {
      rawData[idx] |= 0x20;
    }
    if (bit126OfSupportedMcsSet) {
      rawData[idx] |= 0x40;
    }
    if (bit127OfSupportedMcsSet) {
      rawData[idx] |= 0x80;
    }

    idx = 21;
    rawData[idx] = (byte) (pcoTransitionTime.value << 1);
    if (pcoSupported) {
      rawData[idx] |= 0x01;
    }
    if (bit3OfHtExtendedCapabilities) {
      rawData[idx] |= 0x08;
    }
    if (bit4OfHtExtendedCapabilities) {
      rawData[idx] |= 0x10;
    }
    if (bit5OfHtExtendedCapabilities) {
      rawData[idx] |= 0x20;
    }
    if (bit6OfHtExtendedCapabilities) {
      rawData[idx] |= 0x40;
    }
    if (bit7OfHtExtendedCapabilities) {
      rawData[idx] |= 0x80;
    }

    idx = 22;
    rawData[idx] = (byte) mcsFeedbackCapability.value;
    if (htControlFieldSupported) {
      rawData[idx] |= 0x04;
    }
    if (rdResponderSupported) {
      rawData[idx] |= 0x08;
    }
    if (bit12OfHtExtendedCapabilities) {
      rawData[idx] |= 0x10;
    }
    if (bit13OfHtExtendedCapabilities) {
      rawData[idx] |= 0x20;
    }
    if (bit14OfHtExtendedCapabilities) {
      rawData[idx] |= 0x40;
    }
    if (bit15OfHtExtendedCapabilities) {
      rawData[idx] |= 0x80;
    }

    idx = 23;
    rawData[idx] = (byte) (calibration.value << 6);
    if (implicitTxBeamformingReceivingSupported) {
      rawData[idx] |= 0x01;
    }
    if (rxStaggeredSoundingSupported) {
      rawData[idx] |= 0x02;
    }
    if (txStaggeredSoundingSupported) {
      rawData[idx] |= 0x04;
    }
    if (rxNdpSupported) {
      rawData[idx] |= 0x08;
    }
    if (txNdpSupported) {
      rawData[idx] |= 0x10;
    }
    if (implicitTxBeamformingSupported) {
      rawData[idx] |= 0x20;
    }

    int lastData =
        (explicitTxBeamformingCsiFeedbackCapability.value << 3)
            | (explicitNoncompressedBeamformingFeedbackCapability.value << 5)
            | (explicitCompressedBeamformingFeedbackCapability.value << 7)
            | (minGrouping.value << 9)
            | (csiNumBeamformerAntennasSupported.value << 11)
            | (noncompressedSteeringNumBeamformerAntennasSupported.value << 13)
            | (compressedSteeringNumBeamformerAntennasSupported.value << 15)
            | (csiMaxNumRowsBeamformerSupported.value << 17)
            | (channelEstimationCapability.value << 19);
    if (explicitCsiTxBeamformingSupported) {
      lastData |= 0x01;
    }
    if (explicitNoncompressedSteeringSupported) {
      lastData |= 0x02;
    }
    if (explicitCompressedSteeringSupported) {
      lastData |= 0x04;
    }
    if (bit29OfTransmitBeamformingCapabilities) {
      lastData |= 0x200000;
    }
    if (bit30OfTransmitBeamformingCapabilities) {
      lastData |= 0x400000;
    }
    if (bit31OfTransmitBeamformingCapabilities) {
      lastData |= 0x800000;
    }
    if (antennaSelectionSupported) {
      lastData |= 0x01000000;
    }
    if (explicitCsiFeedbackBasedTxAselSupported) {
      lastData |= 0x02000000;
    }
    if (antennaIndicesFeedbackBasedTxAselSupported) {
      lastData |= 0x04000000;
    }
    if (explicitCsiFeedbackSupported) {
      lastData |= 0x08000000;
    }
    if (antennaIndicesFeedbackSupported) {
      lastData |= 0x10000000;
    }
    if (rxAselSupported) {
      lastData |= 0x20000000;
    }
    if (txSoundingPpdusSupported) {
      lastData |= 0x40000000;
    }
    if (bit7OfAselCapability) {
      lastData |= 0x80000000;
    }
    System.arraycopy(ByteArrays.toByteArray(lastData, ByteOrder.LITTLE_ENDIAN), 0, rawData, 24, 4);

    return rawData;
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + (antennaIndicesFeedbackBasedTxAselSupported ? 1231 : 1237);
    result = prime * result + (antennaIndicesFeedbackSupported ? 1231 : 1237);
    result = prime * result + (antennaSelectionSupported ? 1231 : 1237);
    result = prime * result + (bit101OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit102OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit103OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit104OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit105OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit106OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit107OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit108OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit109OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit110OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit111OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit112OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit113OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit114OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit115OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit116OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit117OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit118OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit119OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit120OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit121OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit122OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit123OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit124OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit125OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit126OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit127OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit12OfHtExtendedCapabilities ? 1231 : 1237);
    result = prime * result + (bit13OfHtCapabilitiesInfo ? 1231 : 1237);
    result = prime * result + (bit13OfHtExtendedCapabilities ? 1231 : 1237);
    result = prime * result + (bit14OfHtExtendedCapabilities ? 1231 : 1237);
    result = prime * result + (bit15OfHtExtendedCapabilities ? 1231 : 1237);
    result = prime * result + (bit29OfTransmitBeamformingCapabilities ? 1231 : 1237);
    result = prime * result + (bit30OfTransmitBeamformingCapabilities ? 1231 : 1237);
    result = prime * result + (bit31OfTransmitBeamformingCapabilities ? 1231 : 1237);
    result = prime * result + (bit3OfHtExtendedCapabilities ? 1231 : 1237);
    result = prime * result + (bit4OfHtExtendedCapabilities ? 1231 : 1237);
    result = prime * result + (bit5OfAMpduParameters ? 1231 : 1237);
    result = prime * result + (bit5OfHtExtendedCapabilities ? 1231 : 1237);
    result = prime * result + (bit6OfAMpduParameters ? 1231 : 1237);
    result = prime * result + (bit6OfHtExtendedCapabilities ? 1231 : 1237);
    result = prime * result + (bit77OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit78OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit79OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit7OfAMpduParameters ? 1231 : 1237);
    result = prime * result + (bit7OfAselCapability ? 1231 : 1237);
    result = prime * result + (bit7OfHtExtendedCapabilities ? 1231 : 1237);
    result = prime * result + (bit90OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit91OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit92OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit93OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit94OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (bit95OfSupportedMcsSet ? 1231 : 1237);
    result = prime * result + (both20and40MhzSupported ? 1231 : 1237);
    result = prime * result + calibration.hashCode();
    result = prime * result + channelEstimationCapability.hashCode();
    result = prime * result + compressedSteeringNumBeamformerAntennasSupported.hashCode();
    result = prime * result + csiMaxNumRowsBeamformerSupported.hashCode();
    result = prime * result + csiNumBeamformerAntennasSupported.hashCode();
    result = prime * result + (dsssCckModeIn40MhzSupported ? 1231 : 1237);
    result = prime * result + explicitCompressedBeamformingFeedbackCapability.hashCode();
    result = prime * result + (explicitCompressedSteeringSupported ? 1231 : 1237);
    result = prime * result + (explicitCsiFeedbackBasedTxAselSupported ? 1231 : 1237);
    result = prime * result + (explicitCsiFeedbackSupported ? 1231 : 1237);
    result = prime * result + (explicitCsiTxBeamformingSupported ? 1231 : 1237);
    result = prime * result + explicitNoncompressedBeamformingFeedbackCapability.hashCode();
    result = prime * result + (explicitNoncompressedSteeringSupported ? 1231 : 1237);
    result = prime * result + explicitTxBeamformingCsiFeedbackCapability.hashCode();
    result = prime * result + (fortyMhzIntolerant ? 1231 : 1237);
    result = prime * result + (htControlFieldSupported ? 1231 : 1237);
    result = prime * result + (htDelayedBlockAckSupported ? 1231 : 1237);
    result = prime * result + (htGreenfieldSupported ? 1231 : 1237);
    result = prime * result + (implicitTxBeamformingReceivingSupported ? 1231 : 1237);
    result = prime * result + (implicitTxBeamformingSupported ? 1231 : 1237);
    result = prime * result + (lSigTxopProtectionSupported ? 1231 : 1237);
    result = prime * result + (ldpcCodingSupported ? 1231 : 1237);
    result = prime * result + maxAMpduLength.hashCode();
    result = prime * result + maxAMsduLength.hashCode();
    result = prime * result + mcsFeedbackCapability.hashCode();
    result = prime * result + minGrouping.hashCode();
    result = prime * result + minMpduStartSpacing.hashCode();
    result = prime * result + noncompressedSteeringNumBeamformerAntennasSupported.hashCode();
    result = prime * result + (pcoSupported ? 1231 : 1237);
    result = prime * result + pcoTransitionTime.hashCode();
    result = prime * result + (rdResponderSupported ? 1231 : 1237);
    result = prime * result + (rxAselSupported ? 1231 : 1237);
    result = prime * result + rxHighestSupportedDataRate;
    result = prime * result + (rxNdpSupported ? 1231 : 1237);
    result = prime * result + (rxStaggeredSoundingSupported ? 1231 : 1237);
    result = prime * result + rxStbcSupport.hashCode();
    result = prime * result + (shortGiFor20MhzSupported ? 1231 : 1237);
    result = prime * result + (shortGiFor40MhzSupported ? 1231 : 1237);
    result = prime * result + smPowerSaveMode.hashCode();
    result = prime * result + Arrays.hashCode(supportedRxMcsIndexes);
    result = prime * result + txMaxNumSpatialStreamsSupported.hashCode();
    result = prime * result + (txMcsSetDefined ? 1231 : 1237);
    result = prime * result + (txNdpSupported ? 1231 : 1237);
    result = prime * result + (txRxMcsSetNotEqual ? 1231 : 1237);
    result = prime * result + (txSoundingPpdusSupported ? 1231 : 1237);
    result = prime * result + (txStaggeredSoundingSupported ? 1231 : 1237);
    result = prime * result + (txStbcSupported ? 1231 : 1237);
    result = prime * result + (txUnequalModulationSupported ? 1231 : 1237);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!super.equals(obj)) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    Dot11HTCapabilitiesElement other = (Dot11HTCapabilitiesElement) obj;
    if (antennaIndicesFeedbackBasedTxAselSupported
        != other.antennaIndicesFeedbackBasedTxAselSupported) {
      return false;
    }
    if (antennaIndicesFeedbackSupported != other.antennaIndicesFeedbackSupported) {
      return false;
    }
    if (antennaSelectionSupported != other.antennaSelectionSupported) {
      return false;
    }
    if (bit101OfSupportedMcsSet != other.bit101OfSupportedMcsSet) {
      return false;
    }
    if (bit102OfSupportedMcsSet != other.bit102OfSupportedMcsSet) {
      return false;
    }
    if (bit103OfSupportedMcsSet != other.bit103OfSupportedMcsSet) {
      return false;
    }
    if (bit104OfSupportedMcsSet != other.bit104OfSupportedMcsSet) {
      return false;
    }
    if (bit105OfSupportedMcsSet != other.bit105OfSupportedMcsSet) {
      return false;
    }
    if (bit106OfSupportedMcsSet != other.bit106OfSupportedMcsSet) {
      return false;
    }
    if (bit107OfSupportedMcsSet != other.bit107OfSupportedMcsSet) {
      return false;
    }
    if (bit108OfSupportedMcsSet != other.bit108OfSupportedMcsSet) {
      return false;
    }
    if (bit109OfSupportedMcsSet != other.bit109OfSupportedMcsSet) {
      return false;
    }
    if (bit110OfSupportedMcsSet != other.bit110OfSupportedMcsSet) {
      return false;
    }
    if (bit111OfSupportedMcsSet != other.bit111OfSupportedMcsSet) {
      return false;
    }
    if (bit112OfSupportedMcsSet != other.bit112OfSupportedMcsSet) {
      return false;
    }
    if (bit113OfSupportedMcsSet != other.bit113OfSupportedMcsSet) {
      return false;
    }
    if (bit114OfSupportedMcsSet != other.bit114OfSupportedMcsSet) {
      return false;
    }
    if (bit115OfSupportedMcsSet != other.bit115OfSupportedMcsSet) {
      return false;
    }
    if (bit116OfSupportedMcsSet != other.bit116OfSupportedMcsSet) {
      return false;
    }
    if (bit117OfSupportedMcsSet != other.bit117OfSupportedMcsSet) {
      return false;
    }
    if (bit118OfSupportedMcsSet != other.bit118OfSupportedMcsSet) {
      return false;
    }
    if (bit119OfSupportedMcsSet != other.bit119OfSupportedMcsSet) {
      return false;
    }
    if (bit120OfSupportedMcsSet != other.bit120OfSupportedMcsSet) {
      return false;
    }
    if (bit121OfSupportedMcsSet != other.bit121OfSupportedMcsSet) {
      return false;
    }
    if (bit122OfSupportedMcsSet != other.bit122OfSupportedMcsSet) {
      return false;
    }
    if (bit123OfSupportedMcsSet != other.bit123OfSupportedMcsSet) {
      return false;
    }
    if (bit124OfSupportedMcsSet != other.bit124OfSupportedMcsSet) {
      return false;
    }
    if (bit125OfSupportedMcsSet != other.bit125OfSupportedMcsSet) {
      return false;
    }
    if (bit126OfSupportedMcsSet != other.bit126OfSupportedMcsSet) {
      return false;
    }
    if (bit127OfSupportedMcsSet != other.bit127OfSupportedMcsSet) {
      return false;
    }
    if (bit12OfHtExtendedCapabilities != other.bit12OfHtExtendedCapabilities) {
      return false;
    }
    if (bit13OfHtCapabilitiesInfo != other.bit13OfHtCapabilitiesInfo) {
      return false;
    }
    if (bit13OfHtExtendedCapabilities != other.bit13OfHtExtendedCapabilities) {
      return false;
    }
    if (bit14OfHtExtendedCapabilities != other.bit14OfHtExtendedCapabilities) {
      return false;
    }
    if (bit15OfHtExtendedCapabilities != other.bit15OfHtExtendedCapabilities) {
      return false;
    }
    if (bit29OfTransmitBeamformingCapabilities != other.bit29OfTransmitBeamformingCapabilities) {
      return false;
    }
    if (bit30OfTransmitBeamformingCapabilities != other.bit30OfTransmitBeamformingCapabilities) {
      return false;
    }
    if (bit31OfTransmitBeamformingCapabilities != other.bit31OfTransmitBeamformingCapabilities) {
      return false;
    }
    if (bit3OfHtExtendedCapabilities != other.bit3OfHtExtendedCapabilities) {
      return false;
    }
    if (bit4OfHtExtendedCapabilities != other.bit4OfHtExtendedCapabilities) {
      return false;
    }
    if (bit5OfAMpduParameters != other.bit5OfAMpduParameters) {
      return false;
    }
    if (bit5OfHtExtendedCapabilities != other.bit5OfHtExtendedCapabilities) {
      return false;
    }
    if (bit6OfAMpduParameters != other.bit6OfAMpduParameters) {
      return false;
    }
    if (bit6OfHtExtendedCapabilities != other.bit6OfHtExtendedCapabilities) {
      return false;
    }
    if (bit77OfSupportedMcsSet != other.bit77OfSupportedMcsSet) {
      return false;
    }
    if (bit78OfSupportedMcsSet != other.bit78OfSupportedMcsSet) {
      return false;
    }
    if (bit79OfSupportedMcsSet != other.bit79OfSupportedMcsSet) {
      return false;
    }
    if (bit7OfAMpduParameters != other.bit7OfAMpduParameters) {
      return false;
    }
    if (bit7OfAselCapability != other.bit7OfAselCapability) {
      return false;
    }
    if (bit7OfHtExtendedCapabilities != other.bit7OfHtExtendedCapabilities) {
      return false;
    }
    if (bit90OfSupportedMcsSet != other.bit90OfSupportedMcsSet) {
      return false;
    }
    if (bit91OfSupportedMcsSet != other.bit91OfSupportedMcsSet) {
      return false;
    }
    if (bit92OfSupportedMcsSet != other.bit92OfSupportedMcsSet) {
      return false;
    }
    if (bit93OfSupportedMcsSet != other.bit93OfSupportedMcsSet) {
      return false;
    }
    if (bit94OfSupportedMcsSet != other.bit94OfSupportedMcsSet) {
      return false;
    }
    if (bit95OfSupportedMcsSet != other.bit95OfSupportedMcsSet) {
      return false;
    }
    if (both20and40MhzSupported != other.both20and40MhzSupported) {
      return false;
    }
    if (calibration != other.calibration) {
      return false;
    }
    if (channelEstimationCapability != other.channelEstimationCapability) {
      return false;
    }
    if (compressedSteeringNumBeamformerAntennasSupported
        != other.compressedSteeringNumBeamformerAntennasSupported) {
      return false;
    }
    if (csiMaxNumRowsBeamformerSupported != other.csiMaxNumRowsBeamformerSupported) {
      return false;
    }
    if (csiNumBeamformerAntennasSupported != other.csiNumBeamformerAntennasSupported) {
      return false;
    }
    if (dsssCckModeIn40MhzSupported != other.dsssCckModeIn40MhzSupported) {
      return false;
    }
    if (explicitCompressedBeamformingFeedbackCapability
        != other.explicitCompressedBeamformingFeedbackCapability) {
      return false;
    }
    if (explicitCompressedSteeringSupported != other.explicitCompressedSteeringSupported) {
      return false;
    }
    if (explicitCsiFeedbackBasedTxAselSupported != other.explicitCsiFeedbackBasedTxAselSupported) {
      return false;
    }
    if (explicitCsiFeedbackSupported != other.explicitCsiFeedbackSupported) {
      return false;
    }
    if (explicitCsiTxBeamformingSupported != other.explicitCsiTxBeamformingSupported) {
      return false;
    }
    if (explicitNoncompressedBeamformingFeedbackCapability
        != other.explicitNoncompressedBeamformingFeedbackCapability) {
      return false;
    }
    if (explicitNoncompressedSteeringSupported != other.explicitNoncompressedSteeringSupported) {
      return false;
    }
    if (explicitTxBeamformingCsiFeedbackCapability
        != other.explicitTxBeamformingCsiFeedbackCapability) {
      return false;
    }
    if (fortyMhzIntolerant != other.fortyMhzIntolerant) {
      return false;
    }
    if (htControlFieldSupported != other.htControlFieldSupported) {
      return false;
    }
    if (htDelayedBlockAckSupported != other.htDelayedBlockAckSupported) {
      return false;
    }
    if (htGreenfieldSupported != other.htGreenfieldSupported) {
      return false;
    }
    if (implicitTxBeamformingReceivingSupported != other.implicitTxBeamformingReceivingSupported) {
      return false;
    }
    if (implicitTxBeamformingSupported != other.implicitTxBeamformingSupported) {
      return false;
    }
    if (lSigTxopProtectionSupported != other.lSigTxopProtectionSupported) {
      return false;
    }
    if (ldpcCodingSupported != other.ldpcCodingSupported) {
      return false;
    }
    if (maxAMpduLength != other.maxAMpduLength) {
      return false;
    }
    if (maxAMsduLength != other.maxAMsduLength) {
      return false;
    }
    if (mcsFeedbackCapability != other.mcsFeedbackCapability) {
      return false;
    }
    if (minGrouping != other.minGrouping) {
      return false;
    }
    if (minMpduStartSpacing != other.minMpduStartSpacing) {
      return false;
    }
    if (noncompressedSteeringNumBeamformerAntennasSupported
        != other.noncompressedSteeringNumBeamformerAntennasSupported) {
      return false;
    }
    if (pcoSupported != other.pcoSupported) {
      return false;
    }
    if (pcoTransitionTime != other.pcoTransitionTime) {
      return false;
    }
    if (rdResponderSupported != other.rdResponderSupported) {
      return false;
    }
    if (rxAselSupported != other.rxAselSupported) {
      return false;
    }
    if (rxHighestSupportedDataRate != other.rxHighestSupportedDataRate) {
      return false;
    }
    if (rxNdpSupported != other.rxNdpSupported) {
      return false;
    }
    if (rxStaggeredSoundingSupported != other.rxStaggeredSoundingSupported) {
      return false;
    }
    if (rxStbcSupport != other.rxStbcSupport) {
      return false;
    }
    if (shortGiFor20MhzSupported != other.shortGiFor20MhzSupported) {
      return false;
    }
    if (shortGiFor40MhzSupported != other.shortGiFor40MhzSupported) {
      return false;
    }
    if (smPowerSaveMode != other.smPowerSaveMode) {
      return false;
    }
    if (!Arrays.equals(supportedRxMcsIndexes, other.supportedRxMcsIndexes)) {
      return false;
    }
    if (txMaxNumSpatialStreamsSupported != other.txMaxNumSpatialStreamsSupported) {
      return false;
    }
    if (txMcsSetDefined != other.txMcsSetDefined) {
      return false;
    }
    if (txNdpSupported != other.txNdpSupported) {
      return false;
    }
    if (txRxMcsSetNotEqual != other.txRxMcsSetNotEqual) {
      return false;
    }
    if (txSoundingPpdusSupported != other.txSoundingPpdusSupported) {
      return false;
    }
    if (txStaggeredSoundingSupported != other.txStaggeredSoundingSupported) {
      return false;
    }
    if (txStbcSupported != other.txStbcSupported) {
      return false;
    }
    if (txUnequalModulationSupported != other.txUnequalModulationSupported) {
      return false;
    }
    return true;
  }

  @Override
  public String toString() {
    return toString("");
  }

  /**
   * @param indent indent
   * @return the string representation of this object.
   */
  public String toString(String indent) {
    StringBuilder sb = new StringBuilder();
    String ls = System.getProperty("line.separator");

    sb.append(indent).append("HT Capabilities:").append(ls);
    sb.append(indent).append("  Element ID: ").append(getElementId()).append(ls);
    sb.append(indent).append("  Length: ").append(getLengthAsInt()).append(" bytes").append(ls);
    sb.append(indent)
        .append("  HT Capabilities Info:")
        .append(ls)
        .append(indent)
        .append("    LDPC Coding is Supported: ")
        .append(ldpcCodingSupported)
        .append(ls)
        .append(indent)
        .append("    Supported Channel Width Set: ")
        .append(both20and40MhzSupported ? "20 MHz and 40 MHz" : "20 MHz")
        .append(ls)
        .append(indent)
        .append("    SM Power Save: ")
        .append(smPowerSaveMode)
        .append(ls)
        .append(indent)
        .append("    HT-Greenfield is Supported: ")
        .append(htGreenfieldSupported)
        .append(ls)
        .append(indent)
        .append("    Short GI for 20 MHz is Supported: ")
        .append(shortGiFor20MhzSupported)
        .append(ls)
        .append(indent)
        .append("    Short GI for 40 MHz is Supported: ")
        .append(shortGiFor40MhzSupported)
        .append(ls)
        .append(indent)
        .append("    Tx STBC is Supported: ")
        .append(txStbcSupported)
        .append(ls)
        .append(indent)
        .append("    Rx STBC Support: ")
        .append(rxStbcSupport)
        .append(ls)
        .append(indent)
        .append("    HT-Delayed Block Ack is Supported: ")
        .append(htDelayedBlockAckSupported)
        .append(ls)
        .append(indent)
        .append("    Max A-MSDU Length: ")
        .append(maxAMsduLength)
        .append(" octets")
        .append(ls)
        .append(indent)
        .append("    DSSS/CCK Mode in 40 MHz is Supported: ")
        .append(dsssCckModeIn40MhzSupported)
        .append(ls)
        .append(indent)
        .append("    Bit 13: ")
        .append(bit13OfHtCapabilitiesInfo)
        .append(ls)
        .append(indent)
        .append("    40 MHz is Intolerant: ")
        .append(fortyMhzIntolerant)
        .append(ls)
        .append(indent)
        .append("    L-SIG TXOP Protection is Supported: ")
        .append(lSigTxopProtectionSupported)
        .append(ls);
    sb.append(indent)
        .append("  A-MPDU Parameters:")
        .append(ls)
        .append(indent)
        .append("    Max A-MPDU Length: ")
        .append(maxAMpduLength)
        .append(" octets")
        .append(ls)
        .append(indent)
        .append("    Min MPDU Start Spacing: ")
        .append(minMpduStartSpacing)
        .append(ls)
        .append(indent)
        .append("    Bit 5: ")
        .append(bit5OfAMpduParameters)
        .append(ls)
        .append(indent)
        .append("    Bit 6: ")
        .append(bit6OfAMpduParameters)
        .append(ls)
        .append(indent)
        .append("    Bit 7: ")
        .append(bit7OfAMpduParameters)
        .append(ls);
    sb.append(indent)
        .append("  Supported MCS Set:")
        .append(ls)
        .append(indent)
        .append("    Supported Rx MCS Indexes: ");
    boolean firstMcsIdx = true;
    for (int i = 0; i < supportedRxMcsIndexes.length; i++) {
      if (supportedRxMcsIndexes[i]) {
        if (!firstMcsIdx) {
          sb.append(", ");
        } else {
          firstMcsIdx = false;
        }
        sb.append(i);
      }
    }
    sb.append(ls)
        .append(indent)
        .append("    Bit 77: ")
        .append(bit77OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 78: ")
        .append(bit78OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 79: ")
        .append(bit79OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Rx Highest Supported Data Rate: ")
        .append(rxHighestSupportedDataRate)
        .append(" Mb/s")
        .append(ls)
        .append(indent)
        .append("    Bit 90: ")
        .append(bit90OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 91: ")
        .append(bit91OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 92: ")
        .append(bit92OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 93: ")
        .append(bit93OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 94: ")
        .append(bit94OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 95: ")
        .append(bit95OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Tx MCS Set is Defined: ")
        .append(txMcsSetDefined)
        .append(ls)
        .append(indent)
        .append("    Tx Rx MCS Set Not Equal: ")
        .append(txRxMcsSetNotEqual)
        .append(ls)
        .append(indent)
        .append("    Tx Max Number Spatial Streams Supported: ")
        .append(txMaxNumSpatialStreamsSupported)
        .append(ls)
        .append(indent)
        .append("    Tx Unequal Modulation is Supported: ")
        .append(txUnequalModulationSupported)
        .append(ls)
        .append(indent)
        .append("    Bit 101: ")
        .append(bit101OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 102: ")
        .append(bit102OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 103: ")
        .append(bit103OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 104: ")
        .append(bit104OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 105: ")
        .append(bit105OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 106: ")
        .append(bit106OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 107: ")
        .append(bit107OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 108: ")
        .append(bit108OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 109: ")
        .append(bit109OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 110: ")
        .append(bit110OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 111: ")
        .append(bit111OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 112: ")
        .append(bit112OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 113: ")
        .append(bit113OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 114: ")
        .append(bit114OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 115: ")
        .append(bit115OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 116: ")
        .append(bit116OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 117: ")
        .append(bit117OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 118: ")
        .append(bit118OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 119: ")
        .append(bit119OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 120: ")
        .append(bit120OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 121: ")
        .append(bit121OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 122: ")
        .append(bit122OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 123: ")
        .append(bit123OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 124: ")
        .append(bit124OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 125: ")
        .append(bit125OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 126: ")
        .append(bit126OfSupportedMcsSet)
        .append(ls)
        .append(indent)
        .append("    Bit 127: ")
        .append(bit127OfSupportedMcsSet)
        .append(ls);
    sb.append(indent)
        .append("  HT Extended Capabilities:")
        .append(ls)
        .append(indent)
        .append("    PCO is Supported: ")
        .append(pcoSupported)
        .append(ls)
        .append(indent)
        .append("    PCO Transition Time: ")
        .append(pcoTransitionTime)
        .append(ls)
        .append(indent)
        .append("    Bit 3: ")
        .append(bit3OfHtExtendedCapabilities)
        .append(ls)
        .append(indent)
        .append("    Bit 4: ")
        .append(bit4OfHtExtendedCapabilities)
        .append(ls)
        .append(indent)
        .append("    Bit 5: ")
        .append(bit5OfHtExtendedCapabilities)
        .append(ls)
        .append(indent)
        .append("    Bit 6: ")
        .append(bit6OfHtExtendedCapabilities)
        .append(ls)
        .append(indent)
        .append("    Bit 7: ")
        .append(bit7OfHtExtendedCapabilities)
        .append(ls)
        .append(indent)
        .append("    MCS Feedback: ")
        .append(mcsFeedbackCapability)
        .append(ls)
        .append(indent)
        .append("    HT Control Field is Support: ")
        .append(htControlFieldSupported)
        .append(ls)
        .append(indent)
        .append("    RD Responder is Supported: ")
        .append(rdResponderSupported)
        .append(ls)
        .append(indent)
        .append("    Bit 12: ")
        .append(bit12OfHtExtendedCapabilities)
        .append(ls)
        .append(indent)
        .append("    Bit 13: ")
        .append(bit13OfHtExtendedCapabilities)
        .append(ls)
        .append(indent)
        .append("    Bit 14: ")
        .append(bit14OfHtExtendedCapabilities)
        .append(ls)
        .append(indent)
        .append("    Bit 15: ")
        .append(bit15OfHtExtendedCapabilities)
        .append(ls);
    sb.append(indent)
        .append("  Transmit Beamforming Capabilities:")
        .append(ls)
        .append(indent)
        .append("    Implicit Tx Beamforming Receiving is Supported: ")
        .append(implicitTxBeamformingReceivingSupported)
        .append(ls)
        .append(indent)
        .append("    Rx Staggered Sounding is Supported: ")
        .append(rxStaggeredSoundingSupported)
        .append(ls)
        .append(indent)
        .append("    Tx Staggered Sounding is Supported: ")
        .append(txStaggeredSoundingSupported)
        .append(ls)
        .append(indent)
        .append("    Rx NDP is Supported: ")
        .append(rxNdpSupported)
        .append(ls)
        .append(indent)
        .append("    Tx NDP is Supported: ")
        .append(txNdpSupported)
        .append(ls)
        .append(indent)
        .append("    Implicit Tx Beamforming is Supported: ")
        .append(implicitTxBeamformingSupported)
        .append(ls)
        .append(indent)
        .append("    Calibration: ")
        .append(calibration)
        .append(ls)
        .append(indent)
        .append("    Explicit CSI Tx Beamforming is Supported: ")
        .append(explicitCsiTxBeamformingSupported)
        .append(ls)
        .append(indent)
        .append("    Explicit Noncompressed Steering is Supported: ")
        .append(explicitNoncompressedSteeringSupported)
        .append(ls)
        .append(indent)
        .append("    Explicit Compressed Steering is Supported: ")
        .append(explicitCompressedSteeringSupported)
        .append(ls)
        .append(indent)
        .append("    Explicit Tx Beamforming CSI Feedback: ")
        .append(explicitTxBeamformingCsiFeedbackCapability)
        .append(ls)
        .append(indent)
        .append("    Explicit Noncompressed Beamforming Feedback: ")
        .append(explicitNoncompressedBeamformingFeedbackCapability)
        .append(ls)
        .append(indent)
        .append("    Explicit Compressed Beamforming Feedback: ")
        .append(explicitCompressedBeamformingFeedbackCapability)
        .append(ls)
        .append(indent)
        .append("    Min Grouping: ")
        .append(minGrouping)
        .append(ls)
        .append(indent)
        .append("    CSI Number of Beamformer Antennas Supported: ")
        .append(csiNumBeamformerAntennasSupported)
        .append(ls)
        .append(indent)
        .append("    Noncompressed Steering Number of Beamformer Antennas Supported: ")
        .append(noncompressedSteeringNumBeamformerAntennasSupported)
        .append(ls)
        .append(indent)
        .append("    Compressed Steering Number of Beamformer Antennas Supported: ")
        .append(compressedSteeringNumBeamformerAntennasSupported)
        .append(ls)
        .append(indent)
        .append("    CSI Max Number of Rows Beamformer Supported: ")
        .append(csiMaxNumRowsBeamformerSupported)
        .append(ls)
        .append(indent)
        .append("    Channel Estimation: ")
        .append(channelEstimationCapability)
        .append(ls)
        .append(indent)
        .append("    Bit 29: ")
        .append(bit29OfTransmitBeamformingCapabilities)
        .append(ls)
        .append(indent)
        .append("    Bit 30: ")
        .append(bit30OfTransmitBeamformingCapabilities)
        .append(ls)
        .append(indent)
        .append("    Bit 31: ")
        .append(bit31OfTransmitBeamformingCapabilities)
        .append(ls);
    sb.append(indent)
        .append("  ASEL Capabilities:")
        .append(ls)
        .append(indent)
        .append("    Antenna Selection is Supported: ")
        .append(antennaSelectionSupported)
        .append(ls)
        .append(indent)
        .append("    Explicit CSI Feedback Based Tx ASEL is Supported: ")
        .append(explicitCsiFeedbackBasedTxAselSupported)
        .append(ls)
        .append(indent)
        .append("    Antenna Indices Feedback Based Tx ASEL is Supported: ")
        .append(antennaIndicesFeedbackBasedTxAselSupported)
        .append(ls)
        .append(indent)
        .append("    Explicit CSI Feedback is Supported: ")
        .append(explicitCsiFeedbackSupported)
        .append(ls)
        .append(indent)
        .append("    Antenna Indices Feedback is Supported: ")
        .append(antennaIndicesFeedbackSupported)
        .append(ls)
        .append(indent)
        .append("    Rx ASEL is Supported: ")
        .append(rxAselSupported)
        .append(ls)
        .append(indent)
        .append("    Tx Sounding PPDUs is Supported: ")
        .append(txSoundingPpdusSupported)
        .append(ls)
        .append(indent)
        .append("    Bit 7: ")
        .append(bit7OfAselCapability)
        .append(ls);

    return sb.toString();
  }

  /**
   * SM Power Save field of IEEE802.11 HT Capabilities element.
   *
   * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static enum SmPowerSaveMode {

    /** Static: 0 */
    STATIC(0),

    /** Dynamic: 1 */
    DYNAMIC(1),

    /** reserved: 2 */
    RESERVED(2),

    /** disabled: 3 */
    DISABLED(3);

    private final int value;

    private SmPowerSaveMode(int value) {
      this.value = value;
    }

    /** @return value */
    public int getValue() {
      return value;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder(20);
      sb.append(value).append(" (").append(name()).append(")");
      return sb.toString();
    }

    /**
     * @param value value
     * @return the SmPowerSaveMode object the value of which is the given value.
     */
    public static SmPowerSaveMode getInstance(int value) {
      for (SmPowerSaveMode mode : values()) {
        if (mode.value == value) {
          return mode;
        }
      }
      throw new IllegalArgumentException("Invalid value: " + value);
    }
  }

  /**
   * Rx STBC field of IEEE802.11 HT Capabilities element.
   *
   * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static enum StbcSupport {

    /** No support: 0 */
    NO_SUPPORT(0, "No support"),

    /** One spatial stream is supported: 1 */
    ONE_SPATIAL_STREAM(1, "One spatial stream is supported"),

    /** One and two spatial streams are supported: 2 */
    ONE_AND_TWO_SPATIAL_STREAMS(2, "One and two spatial streams are supported"),

    /** One, two and three spatial streams are supported: 3 */
    ONE_TWO_AND_THREE_SPATIAL_STREAMS(3, "One, two and three spatial streams are supported");

    private final int value;
    private final String name;

    private StbcSupport(int value, String name) {
      this.value = value;
      this.name = name;
    }

    /** @return value */
    public int getValue() {
      return value;
    }

    /** @return name */
    public String getName() {
      return name;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder(60);
      sb.append(value).append(" (").append(name).append(")");
      return sb.toString();
    }

    /**
     * @param value value
     * @return the StbcSupport object the value of which is the given value.
     */
    public static StbcSupport getInstance(int value) {
      for (StbcSupport val : values()) {
        if (val.value == value) {
          return val;
        }
      }
      throw new IllegalArgumentException("Invalid value: " + value);
    }
  }

  /**
   * Maximum A-MSDU Length field of IEEE802.11 HT Capabilities element.
   *
   * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static enum AMsduLength {

    /** 3839 octets: 0 */
    MAX_3839(0, "3839 octets"),

    /** 7935 octets: 1 */
    MAX_7935(1, "7935 octets");

    private final int value;
    private final String name;

    private AMsduLength(int value, String name) {
      this.value = value;
      this.name = name;
    }

    /** @return value */
    public int getValue() {
      return value;
    }

    /** @return name */
    public String getName() {
      return name;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder(50);
      sb.append(value).append(" (").append(name).append(")");
      return sb.toString();
    }

    /**
     * @param value value
     * @return the AMsduLength object the value of which is the given value.
     */
    public static AMsduLength getInstance(int value) {
      for (AMsduLength val : values()) {
        if (val.value == value) {
          return val;
        }
      }
      throw new IllegalArgumentException("Invalid value: " + value);
    }
  }

  /**
   * Maximum A-MPDU Length Exponent field of IEEE802.11 HT Capabilities element.
   *
   * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static enum AMpduLength {

    /** 8191 octets: 0 */
    MAX_8191(0, "8191 octets"),

    /** 16383 octets: 1 */
    MAX_16383(1, "16383 octets"),

    /** 32767 octets: 2 */
    MAX_32767(2, "32767 octets"),

    /** 65535 octets: 3 */
    MAX_65535(3, "65535 octets");

    private final int value;
    private final String name;

    private AMpduLength(int value, String name) {
      this.value = value;
      this.name = name;
    }

    /** @return value */
    public int getValue() {
      return value;
    }

    /** @return name */
    public String getName() {
      return name;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder(50);
      sb.append(value).append(" (").append(name).append(")");
      return sb.toString();
    }

    /**
     * @param value value
     * @return the AMpduLength object the value of which is the given value.
     */
    public static AMpduLength getInstance(int value) {
      for (AMpduLength val : values()) {
        if (val.value == value) {
          return val;
        }
      }
      throw new IllegalArgumentException("Invalid value: " + value);
    }
  }

  /**
   * Minimum MPDU Start Spacing field of IEEE802.11 HT Capabilities element.
   *
   * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static enum MpduStartSpacing {

    /** No restriction: 0 */
    NO_RESTRICTION(0, "No restriction"),

    /** 1/4 us: 1 */
    ONE_FOURTH_US(1, "1/4 us"),

    /** 1/2 us: 2 */
    HALF_US(2, "1/2 us"),

    /** 1 us: 3 */
    ONE_US(3, "1 us"),

    /** 2 us: 4 */
    TWO_US(4, "2 us"),

    /** 4 us: 5 */
    FOUR_US(5, "4 us"),

    /** 8 us: 6 */
    EIGHT_US(6, "8 us"),

    /** 16 us: 7 */
    SIXTEEN_US(7, "16 us");

    private final int value;
    private final String name;

    private MpduStartSpacing(int value, String name) {
      this.value = value;
      this.name = name;
    }

    /** @return value */
    public int getValue() {
      return value;
    }

    /** @return name */
    public String getName() {
      return name;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder(50);
      sb.append(value).append(" (").append(name).append(")");
      return sb.toString();
    }

    /**
     * @param value value
     * @return the MpduStartSpacing object the value of which is the given value.
     */
    public static MpduStartSpacing getInstance(int value) {
      for (MpduStartSpacing cp : values()) {
        if (cp.value == value) {
          return cp;
        }
      }
      throw new IllegalArgumentException("Invalid value: " + value);
    }
  }

  /**
   * Tx Maximum Number Spatial Streams Supported field of IEEE802.11 HT Capabilities element.
   *
   * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static enum NumSpatialStreams {

    /** 1 spatial stream: 0 */
    ONE(0, "1 spatial stream"),

    /** 2 spatial stream: 1 */
    TWO(1, "2 spatial stream"),

    /** 3 spatial stream: 2 */
    THREE(2, "3 spatial stream"),

    /** 4 spatial stream: 3 */
    FOUR(3, "4 spatial stream");

    private final int value;
    private final String name;

    private NumSpatialStreams(int value, String name) {
      this.value = value;
      this.name = name;
    }

    /** @return value */
    public int getValue() {
      return value;
    }

    /** @return name */
    public String getName() {
      return name;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder(50);
      sb.append(value).append(" (").append(name).append(")");
      return sb.toString();
    }

    /**
     * @param value value
     * @return the NumSpatialStreams object the value of which is the given value.
     */
    public static NumSpatialStreams getInstance(int value) {
      for (NumSpatialStreams cp : values()) {
        if (cp.value == value) {
          return cp;
        }
      }
      throw new IllegalArgumentException("Invalid value: " + value);
    }
  }

  /**
   * PCO Transition Time field of IEEE802.11 HT Capabilities element.
   *
   * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static enum PcoTransitionTime {

    /** No transition: 0 */
    NO_TRANSITION(0, "No transition"),

    /** 400 us: 1 */
    PTT_400_US(1, "400 us"),

    /** 1.5 ms: 2 */
    PTT_1_5_MS(2, "1.5 ms"),

    /** 5 ms: 3 */
    PTT_5_MS(3, "5 ms");

    private final int value;
    private final String name;

    private PcoTransitionTime(int value, String name) {
      this.value = value;
      this.name = name;
    }

    /** @return value */
    public int getValue() {
      return value;
    }

    /** @return name */
    public String getName() {
      return name;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder(50);
      sb.append(value).append(" (").append(name).append(")");
      return sb.toString();
    }

    /**
     * @param value value
     * @return the PcoTransitionTime object the value of which is the given value.
     */
    public static PcoTransitionTime getInstance(int value) {
      for (PcoTransitionTime cp : values()) {
        if (cp.value == value) {
          return cp;
        }
      }
      throw new IllegalArgumentException("Invalid value: " + value);
    }
  }

  /**
   * MCA Feedback field of IEEE802.11 HT Capabilities element.
   *
   * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static enum McsFeedbackCapability {

    /** No Feedback: 0 */
    NO_FEEDBACK(0, "No Feedback"),

    /** reserved: 1 */
    RESERVED(1, "reserved"),

    /** Only unsolicited: 2 */
    ONLY_UNSOLICITED(2, "Only unsolicited"),

    /** Unsolicited and solicited: 3 */
    UNSOLICITED_AND_SOLICITED(3, "Unsolicited and solicited");

    private final int value;
    private final String name;

    private McsFeedbackCapability(int value, String name) {
      this.value = value;
      this.name = name;
    }

    /** @return value */
    public int getValue() {
      return value;
    }

    /** @return name */
    public String getName() {
      return name;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder(50);
      sb.append(value).append(" (").append(name).append(")");
      return sb.toString();
    }

    /**
     * @param value value
     * @return the McsFeedbackCapability object the value of which is the given value.
     */
    public static McsFeedbackCapability getInstance(int value) {
      for (McsFeedbackCapability cp : values()) {
        if (cp.value == value) {
          return cp;
        }
      }
      throw new IllegalArgumentException("Invalid value: " + value);
    }
  }

  /**
   * Calibration field of IEEE802.11 HT Capabilities element.
   *
   * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static enum Calibration {

    /** Not supported: 0 */
    NOT_SUPPORTED(0, "Not supported"),

    /** Respond: 1 */
    RESPOND(1, "Respond"),

    /** reserved: 2 */
    RESERVED(2, "reserved"),

    /** Initiate and respond: 3 */
    INITIATE_AND_RESPOND(3, "Initiate and respond");

    private final int value;
    private final String name;

    private Calibration(int value, String name) {
      this.value = value;
      this.name = name;
    }

    /** @return value */
    public int getValue() {
      return value;
    }

    /** @return name */
    public String getName() {
      return name;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder(50);
      sb.append(value).append(" (").append(name).append(")");
      return sb.toString();
    }

    /**
     * @param value value
     * @return the Calibration object the value of which is the given value.
     */
    public static Calibration getInstance(int value) {
      for (Calibration cp : values()) {
        if (cp.value == value) {
          return cp;
        }
      }
      throw new IllegalArgumentException("Invalid value: " + value);
    }
  }

  /**
   * Explicit Transmit Beamforming CSI Feedback field, Explicit Noncompressed Beamforming Feedback
   * Capable field, and Explicit Compressed Beamforming Feedback Capable field of IEEE802.11 HT
   * Capabilities element.
   *
   * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static enum BeamformingFeedbackCapability {

    /** Not supported: 0 */
    NOT_SUPPORTED(0, "Not supported"),

    /** Delayed: 1 */
    DELAYED(1, "Delayed"),

    /** Immediate: 2 */
    IMMEDIATE(2, "Immediate"),

    /** Delayed and immediate: 3 */
    DELAYED_AND_IMMEDIATE(3, "Delayed and immediate");

    private final int value;
    private final String name;

    private BeamformingFeedbackCapability(int value, String name) {
      this.value = value;
      this.name = name;
    }

    /** @return value */
    public int getValue() {
      return value;
    }

    /** @return name */
    public String getName() {
      return name;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder(50);
      sb.append(value).append(" (").append(name).append(")");
      return sb.toString();
    }

    /**
     * @param value value
     * @return the BeamformingFeedbackCapability object the value of which is the given value.
     */
    public static BeamformingFeedbackCapability getInstance(int value) {
      for (BeamformingFeedbackCapability cp : values()) {
        if (cp.value == value) {
          return cp;
        }
      }
      throw new IllegalArgumentException("Invalid value: " + value);
    }
  }

  /**
   * Minimal Grouping field of IEEE802.11 HT Capabilities element.
   *
   * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static enum Grouping {

    /** No grouping: 0 */
    NO_GROUPING(0, "No grouping"),

    /** Groups of 1, 2: 1 */
    GROUPS_OF_1_2(1, "Groups of 1, 2"),

    /** Groups of 1, 4: 2 */
    GROUPS_OF_1_4(2, "Groups of 1, 4"),

    /** Groups of 1, 2, 4: 3 */
    GROUPS_OF_1_2_4(3, "Groups of 1, 2, 4");

    private final int value;
    private final String name;

    private Grouping(int value, String name) {
      this.value = value;
      this.name = name;
    }

    /** @return value */
    public int getValue() {
      return value;
    }

    /** @return name */
    public String getName() {
      return name;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder(50);
      sb.append(value).append(" (").append(name).append(")");
      return sb.toString();
    }

    /**
     * @param value value
     * @return the Grouping object the value of which is the given value.
     */
    public static Grouping getInstance(int value) {
      for (Grouping cp : values()) {
        if (cp.value == value) {
          return cp;
        }
      }
      throw new IllegalArgumentException("Invalid value: " + value);
    }
  }

  /**
   * CSI Number of Beamformer Antennas Supported field, Noncompressed Steering Number of Beamformer
   * Antennas Supported field, and Compressed Steering Number of Beamformer Antennas Supported field
   * of IEEE802.11 HT Capabilities element.
   *
   * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static enum NumBeamformerAntennas {

    /** Single Tx antenna sounding: 0 */
    SINGLE(0, "Single Tx antenna sounding"),

    /** 2 Tx antenna sounding: 1 */
    TWO(1, "2 Tx antenna sounding"),

    /** 3 Tx antenna sounding: 2 */
    THREE(2, "3 Tx antenna sounding"),

    /** 4 Tx antenna sounding: 3 */
    FOUR(3, "4 Tx antenna sounding");

    private final int value;
    private final String name;

    private NumBeamformerAntennas(int value, String name) {
      this.value = value;
      this.name = name;
    }

    /** @return value */
    public int getValue() {
      return value;
    }

    /** @return name */
    public String getName() {
      return name;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder(50);
      sb.append(value).append(" (").append(name).append(")");
      return sb.toString();
    }

    /**
     * @param value value
     * @return the NumBeamformerAntennas object the value of which is the given value.
     */
    public static NumBeamformerAntennas getInstance(int value) {
      for (NumBeamformerAntennas cp : values()) {
        if (cp.value == value) {
          return cp;
        }
      }
      throw new IllegalArgumentException("Invalid value: " + value);
    }
  }

  /**
   * CSI Max Number of Rows Beamformer Supported field of IEEE802.11 HT Capabilities element.
   *
   * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static enum CsiNumRows {

    /** Single row of CSI: 0 */
    SINGLE(0, "Single row of CSI"),

    /** 2 rows of CSI: 1 */
    TWO(1, "2 rows of CSI"),

    /** 3 rows of CSI: 2 */
    THREE(2, "3 rows of CSI"),

    /** 4 rows of CSI: 3 */
    FOUR(3, "4 rows of CSI");

    private final int value;
    private final String name;

    private CsiNumRows(int value, String name) {
      this.value = value;
      this.name = name;
    }

    /** @return value */
    public int getValue() {
      return value;
    }

    /** @return name */
    public String getName() {
      return name;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder(50);
      sb.append(value).append(" (").append(name).append(")");
      return sb.toString();
    }

    /**
     * @param value value
     * @return the CsiNumRows object the value of which is the given value.
     */
    public static CsiNumRows getInstance(int value) {
      for (CsiNumRows cp : values()) {
        if (cp.value == value) {
          return cp;
        }
      }
      throw new IllegalArgumentException("Invalid value: " + value);
    }
  }

  /**
   * Channel Estimation Capability field of IEEE802.11 HT Capabilities element.
   *
   * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static enum ChannelEstimationCapability {

    /** 1 space-time stream: 0 */
    ONE_SPACE_TIME_STREAM(0, "1 space-time stream"),

    /** 2 space-time streams: 1 */
    TWO_SPACE_TIME_STREAMS(1, "2 space-time streams"),

    /** 3 space-time streams: 2 */
    THREE_SPACE_TIME_STREAMS(2, "3 space-time streams"),

    /** 4 space-time streams: 3 */
    FOUR_SPACE_TIME_STREAMS(3, "4 space-time streams");

    private final int value;
    private final String name;

    private ChannelEstimationCapability(int value, String name) {
      this.value = value;
      this.name = name;
    }

    /** @return value */
    public int getValue() {
      return value;
    }

    /** @return name */
    public String getName() {
      return name;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder(50);
      sb.append(value).append(" (").append(name).append(")");
      return sb.toString();
    }

    /**
     * @param value value
     * @return the ChannelEstimationCapability object the value of which is the given value.
     */
    public static ChannelEstimationCapability getInstance(int value) {
      for (ChannelEstimationCapability cp : values()) {
        if (cp.value == value) {
          return cp;
        }
      }
      throw new IllegalArgumentException("Invalid value: " + value);
    }
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static final class Builder extends Dot11InformationElement.Builder {

    private boolean ldpcCodingSupported;
    private boolean both20and40MhzSupported;
    private SmPowerSaveMode smPowerSaveMode;
    private boolean htGreenfieldSupported;
    private boolean shortGiFor20MhzSupported;
    private boolean shortGiFor40MhzSupported;
    private boolean txStbcSupported;
    private StbcSupport rxStbcSupport;
    private boolean htDelayedBlockAckSupported;
    private AMsduLength maxAMsduLength;
    private boolean dsssCckModeIn40MhzSupported;
    private boolean bit13OfHtCapabilitiesInfo;
    private boolean fortyMhzIntolerant;
    private boolean lSigTxopProtectionSupported;
    private AMpduLength maxAMpduLength;
    private MpduStartSpacing minMpduStartSpacing;
    private boolean bit5OfAMpduParameters;
    private boolean bit6OfAMpduParameters;
    private boolean bit7OfAMpduParameters;
    private boolean[] supportedRxMcsIndexes;
    private boolean bit77OfSupportedMcsSet;
    private boolean bit78OfSupportedMcsSet;
    private boolean bit79OfSupportedMcsSet;
    private short rxHighestSupportedDataRate;
    private boolean bit90OfSupportedMcsSet;
    private boolean bit91OfSupportedMcsSet;
    private boolean bit92OfSupportedMcsSet;
    private boolean bit93OfSupportedMcsSet;
    private boolean bit94OfSupportedMcsSet;
    private boolean bit95OfSupportedMcsSet;
    private boolean txMcsSetDefined;
    private boolean txRxMcsSetNotEqual;
    private NumSpatialStreams txMaxNumSpatialStreamsSupported;
    private boolean txUnequalModulationSupported;
    private boolean bit101OfSupportedMcsSet;
    private boolean bit102OfSupportedMcsSet;
    private boolean bit103OfSupportedMcsSet;
    private boolean bit104OfSupportedMcsSet;
    private boolean bit105OfSupportedMcsSet;
    private boolean bit106OfSupportedMcsSet;
    private boolean bit107OfSupportedMcsSet;
    private boolean bit108OfSupportedMcsSet;
    private boolean bit109OfSupportedMcsSet;
    private boolean bit110OfSupportedMcsSet;
    private boolean bit111OfSupportedMcsSet;
    private boolean bit112OfSupportedMcsSet;
    private boolean bit113OfSupportedMcsSet;
    private boolean bit114OfSupportedMcsSet;
    private boolean bit115OfSupportedMcsSet;
    private boolean bit116OfSupportedMcsSet;
    private boolean bit117OfSupportedMcsSet;
    private boolean bit118OfSupportedMcsSet;
    private boolean bit119OfSupportedMcsSet;
    private boolean bit120OfSupportedMcsSet;
    private boolean bit121OfSupportedMcsSet;
    private boolean bit122OfSupportedMcsSet;
    private boolean bit123OfSupportedMcsSet;
    private boolean bit124OfSupportedMcsSet;
    private boolean bit125OfSupportedMcsSet;
    private boolean bit126OfSupportedMcsSet;
    private boolean bit127OfSupportedMcsSet;
    private boolean pcoSupported;
    private PcoTransitionTime pcoTransitionTime;
    private boolean bit3OfHtExtendedCapabilities;
    private boolean bit4OfHtExtendedCapabilities;
    private boolean bit5OfHtExtendedCapabilities;
    private boolean bit6OfHtExtendedCapabilities;
    private boolean bit7OfHtExtendedCapabilities;
    private McsFeedbackCapability mcsFeedbackCapability;
    private boolean htControlFieldSupported;
    private boolean rdResponderSupported;
    private boolean bit12OfHtExtendedCapabilities;
    private boolean bit13OfHtExtendedCapabilities;
    private boolean bit14OfHtExtendedCapabilities;
    private boolean bit15OfHtExtendedCapabilities;
    private boolean implicitTxBeamformingReceivingSupported;
    private boolean rxStaggeredSoundingSupported;
    private boolean txStaggeredSoundingSupported;
    private boolean rxNdpSupported;
    private boolean txNdpSupported;
    private boolean implicitTxBeamformingSupported;
    private Calibration calibration;
    private boolean explicitCsiTxBeamformingSupported;
    private boolean explicitNoncompressedSteeringSupported;
    private boolean explicitCompressedSteeringSupported;
    private BeamformingFeedbackCapability explicitTxBeamformingCsiFeedbackCapability;
    private BeamformingFeedbackCapability explicitNoncompressedBeamformingFeedbackCapability;
    private BeamformingFeedbackCapability explicitCompressedBeamformingFeedbackCapability;
    private Grouping minGrouping;
    private NumBeamformerAntennas csiNumBeamformerAntennasSupported;
    private NumBeamformerAntennas noncompressedSteeringNumBeamformerAntennasSupported;
    private NumBeamformerAntennas compressedSteeringNumBeamformerAntennasSupported;
    private CsiNumRows csiMaxNumRowsBeamformerSupported;
    private ChannelEstimationCapability channelEstimationCapability;
    private boolean bit29OfTransmitBeamformingCapabilities;
    private boolean bit30OfTransmitBeamformingCapabilities;
    private boolean bit31OfTransmitBeamformingCapabilities;
    private boolean antennaSelectionSupported;
    private boolean explicitCsiFeedbackBasedTxAselSupported;
    private boolean antennaIndicesFeedbackBasedTxAselSupported;
    private boolean explicitCsiFeedbackSupported;
    private boolean antennaIndicesFeedbackSupported;
    private boolean rxAselSupported;
    private boolean txSoundingPpdusSupported;
    private boolean bit7OfAselCapability;

    /** */
    public Builder() {
      elementId(
          Dot11InformationElementId.getInstance(Dot11InformationElementId.HT_CAPABILITIES.value()));
    }

    /** @param elem a Dot11HTCapabilitiesElement object. */
    private Builder(Dot11HTCapabilitiesElement obj) {
      super(obj);
      this.ldpcCodingSupported = obj.ldpcCodingSupported;
      this.both20and40MhzSupported = obj.both20and40MhzSupported;
      this.smPowerSaveMode = obj.smPowerSaveMode;
      this.htGreenfieldSupported = obj.htGreenfieldSupported;
      this.shortGiFor20MhzSupported = obj.shortGiFor20MhzSupported;
      this.shortGiFor40MhzSupported = obj.shortGiFor40MhzSupported;
      this.txStbcSupported = obj.txStbcSupported;
      this.rxStbcSupport = obj.rxStbcSupport;
      this.htDelayedBlockAckSupported = obj.htDelayedBlockAckSupported;
      this.maxAMsduLength = obj.maxAMsduLength;
      this.dsssCckModeIn40MhzSupported = obj.dsssCckModeIn40MhzSupported;
      this.bit13OfHtCapabilitiesInfo = obj.bit13OfHtCapabilitiesInfo;
      this.fortyMhzIntolerant = obj.fortyMhzIntolerant;
      this.lSigTxopProtectionSupported = obj.lSigTxopProtectionSupported;
      this.maxAMpduLength = obj.maxAMpduLength;
      this.minMpduStartSpacing = obj.minMpduStartSpacing;
      this.bit5OfAMpduParameters = obj.bit5OfAMpduParameters;
      this.bit6OfAMpduParameters = obj.bit6OfAMpduParameters;
      this.bit7OfAMpduParameters = obj.bit7OfAMpduParameters;
      this.supportedRxMcsIndexes = obj.supportedRxMcsIndexes;
      this.bit77OfSupportedMcsSet = obj.bit77OfSupportedMcsSet;
      this.bit78OfSupportedMcsSet = obj.bit78OfSupportedMcsSet;
      this.bit79OfSupportedMcsSet = obj.bit79OfSupportedMcsSet;
      this.rxHighestSupportedDataRate = obj.rxHighestSupportedDataRate;
      this.bit90OfSupportedMcsSet = obj.bit90OfSupportedMcsSet;
      this.bit91OfSupportedMcsSet = obj.bit91OfSupportedMcsSet;
      this.bit92OfSupportedMcsSet = obj.bit92OfSupportedMcsSet;
      this.bit93OfSupportedMcsSet = obj.bit93OfSupportedMcsSet;
      this.bit94OfSupportedMcsSet = obj.bit94OfSupportedMcsSet;
      this.bit95OfSupportedMcsSet = obj.bit95OfSupportedMcsSet;
      this.txMcsSetDefined = obj.txMcsSetDefined;
      this.txRxMcsSetNotEqual = obj.txRxMcsSetNotEqual;
      this.txMaxNumSpatialStreamsSupported = obj.txMaxNumSpatialStreamsSupported;
      this.txUnequalModulationSupported = obj.txUnequalModulationSupported;
      this.bit101OfSupportedMcsSet = obj.bit101OfSupportedMcsSet;
      this.bit102OfSupportedMcsSet = obj.bit102OfSupportedMcsSet;
      this.bit103OfSupportedMcsSet = obj.bit103OfSupportedMcsSet;
      this.bit104OfSupportedMcsSet = obj.bit104OfSupportedMcsSet;
      this.bit105OfSupportedMcsSet = obj.bit105OfSupportedMcsSet;
      this.bit106OfSupportedMcsSet = obj.bit106OfSupportedMcsSet;
      this.bit107OfSupportedMcsSet = obj.bit107OfSupportedMcsSet;
      this.bit108OfSupportedMcsSet = obj.bit108OfSupportedMcsSet;
      this.bit109OfSupportedMcsSet = obj.bit109OfSupportedMcsSet;
      this.bit110OfSupportedMcsSet = obj.bit110OfSupportedMcsSet;
      this.bit111OfSupportedMcsSet = obj.bit111OfSupportedMcsSet;
      this.bit112OfSupportedMcsSet = obj.bit112OfSupportedMcsSet;
      this.bit113OfSupportedMcsSet = obj.bit113OfSupportedMcsSet;
      this.bit114OfSupportedMcsSet = obj.bit114OfSupportedMcsSet;
      this.bit115OfSupportedMcsSet = obj.bit115OfSupportedMcsSet;
      this.bit116OfSupportedMcsSet = obj.bit116OfSupportedMcsSet;
      this.bit117OfSupportedMcsSet = obj.bit117OfSupportedMcsSet;
      this.bit118OfSupportedMcsSet = obj.bit118OfSupportedMcsSet;
      this.bit119OfSupportedMcsSet = obj.bit119OfSupportedMcsSet;
      this.bit120OfSupportedMcsSet = obj.bit120OfSupportedMcsSet;
      this.bit121OfSupportedMcsSet = obj.bit121OfSupportedMcsSet;
      this.bit122OfSupportedMcsSet = obj.bit122OfSupportedMcsSet;
      this.bit123OfSupportedMcsSet = obj.bit123OfSupportedMcsSet;
      this.bit124OfSupportedMcsSet = obj.bit124OfSupportedMcsSet;
      this.bit125OfSupportedMcsSet = obj.bit125OfSupportedMcsSet;
      this.bit126OfSupportedMcsSet = obj.bit126OfSupportedMcsSet;
      this.bit127OfSupportedMcsSet = obj.bit127OfSupportedMcsSet;
      this.pcoSupported = obj.pcoSupported;
      this.pcoTransitionTime = obj.pcoTransitionTime;
      this.bit3OfHtExtendedCapabilities = obj.bit3OfHtExtendedCapabilities;
      this.bit4OfHtExtendedCapabilities = obj.bit4OfHtExtendedCapabilities;
      this.bit5OfHtExtendedCapabilities = obj.bit5OfHtExtendedCapabilities;
      this.bit6OfHtExtendedCapabilities = obj.bit6OfHtExtendedCapabilities;
      this.bit7OfHtExtendedCapabilities = obj.bit7OfHtExtendedCapabilities;
      this.mcsFeedbackCapability = obj.mcsFeedbackCapability;
      this.htControlFieldSupported = obj.htControlFieldSupported;
      this.rdResponderSupported = obj.rdResponderSupported;
      this.bit12OfHtExtendedCapabilities = obj.bit12OfHtExtendedCapabilities;
      this.bit13OfHtExtendedCapabilities = obj.bit13OfHtExtendedCapabilities;
      this.bit14OfHtExtendedCapabilities = obj.bit14OfHtExtendedCapabilities;
      this.bit15OfHtExtendedCapabilities = obj.bit15OfHtExtendedCapabilities;
      this.implicitTxBeamformingReceivingSupported = obj.implicitTxBeamformingReceivingSupported;
      this.rxStaggeredSoundingSupported = obj.rxStaggeredSoundingSupported;
      this.txStaggeredSoundingSupported = obj.txStaggeredSoundingSupported;
      this.rxNdpSupported = obj.rxNdpSupported;
      this.txNdpSupported = obj.txNdpSupported;
      this.implicitTxBeamformingSupported = obj.implicitTxBeamformingSupported;
      this.calibration = obj.calibration;
      this.explicitCsiTxBeamformingSupported = obj.explicitCsiTxBeamformingSupported;
      this.explicitNoncompressedSteeringSupported = obj.explicitNoncompressedSteeringSupported;
      this.explicitCompressedSteeringSupported = obj.explicitCompressedSteeringSupported;
      this.explicitTxBeamformingCsiFeedbackCapability =
          obj.explicitTxBeamformingCsiFeedbackCapability;
      this.explicitNoncompressedBeamformingFeedbackCapability =
          obj.explicitNoncompressedBeamformingFeedbackCapability;
      this.explicitCompressedBeamformingFeedbackCapability =
          obj.explicitCompressedBeamformingFeedbackCapability;
      this.minGrouping = obj.minGrouping;
      this.csiNumBeamformerAntennasSupported = obj.csiNumBeamformerAntennasSupported;
      this.noncompressedSteeringNumBeamformerAntennasSupported =
          obj.noncompressedSteeringNumBeamformerAntennasSupported;
      this.compressedSteeringNumBeamformerAntennasSupported =
          obj.compressedSteeringNumBeamformerAntennasSupported;
      this.csiMaxNumRowsBeamformerSupported = obj.csiMaxNumRowsBeamformerSupported;
      this.channelEstimationCapability = obj.channelEstimationCapability;
      this.bit29OfTransmitBeamformingCapabilities = obj.bit29OfTransmitBeamformingCapabilities;
      this.bit30OfTransmitBeamformingCapabilities = obj.bit30OfTransmitBeamformingCapabilities;
      this.bit31OfTransmitBeamformingCapabilities = obj.bit31OfTransmitBeamformingCapabilities;
      this.antennaSelectionSupported = obj.antennaSelectionSupported;
      this.explicitCsiFeedbackBasedTxAselSupported = obj.explicitCsiFeedbackBasedTxAselSupported;
      this.antennaIndicesFeedbackBasedTxAselSupported =
          obj.antennaIndicesFeedbackBasedTxAselSupported;
      this.explicitCsiFeedbackSupported = obj.explicitCsiFeedbackSupported;
      this.antennaIndicesFeedbackSupported = obj.antennaIndicesFeedbackSupported;
      this.rxAselSupported = obj.rxAselSupported;
      this.txSoundingPpdusSupported = obj.txSoundingPpdusSupported;
      this.bit7OfAselCapability = obj.bit7OfAselCapability;
    }

    /**
     * @param ldpcCodingSupported ldpcCodingSupported
     * @return this Builder object for method chaining.
     */
    public Builder ldpcCodingSupported(boolean ldpcCodingSupported) {
      this.ldpcCodingSupported = ldpcCodingSupported;
      return this;
    }

    /**
     * @param both20and40MhzSupported both20and40MhzSupported
     * @return this Builder object for method chaining.
     */
    public Builder both20and40MhzSupported(boolean both20and40MhzSupported) {
      this.both20and40MhzSupported = both20and40MhzSupported;
      return this;
    }

    /**
     * @param smPowerSaveMode smPowerSaveMode
     * @return this Builder object for method chaining.
     */
    public Builder smPowerSaveMode(SmPowerSaveMode smPowerSaveMode) {
      this.smPowerSaveMode = smPowerSaveMode;
      return this;
    }

    /**
     * @param htGreenfieldSupported htGreenfieldSupported
     * @return this Builder object for method chaining.
     */
    public Builder htGreenfieldSupported(boolean htGreenfieldSupported) {
      this.htGreenfieldSupported = htGreenfieldSupported;
      return this;
    }

    /**
     * @param shortGiFor20MhzSupported shortGiFor20MhzSupported
     * @return this Builder object for method chaining.
     */
    public Builder shortGiFor20MhzSupported(boolean shortGiFor20MhzSupported) {
      this.shortGiFor20MhzSupported = shortGiFor20MhzSupported;
      return this;
    }

    /**
     * @param shortGiFor40MhzSupported shortGiFor40MhzSupported
     * @return this Builder object for method chaining.
     */
    public Builder shortGiFor40MhzSupported(boolean shortGiFor40MhzSupported) {
      this.shortGiFor40MhzSupported = shortGiFor40MhzSupported;
      return this;
    }

    /**
     * @param txStbcSupported txStbcSupported
     * @return this Builder object for method chaining.
     */
    public Builder txStbcSupported(boolean txStbcSupported) {
      this.txStbcSupported = txStbcSupported;
      return this;
    }

    /**
     * @param rxStbcSupport rxStbcSupport
     * @return this Builder object for method chaining.
     */
    public Builder rxStbcSupport(StbcSupport rxStbcSupport) {
      this.rxStbcSupport = rxStbcSupport;
      return this;
    }

    /**
     * @param htDelayedBlockAckSupported htDelayedBlockAckSupported
     * @return this Builder object for method chaining.
     */
    public Builder htDelayedBlockAckSupported(boolean htDelayedBlockAckSupported) {
      this.htDelayedBlockAckSupported = htDelayedBlockAckSupported;
      return this;
    }

    /**
     * @param maxAMsduLength maxAMsduLength
     * @return this Builder object for method chaining.
     */
    public Builder maxAMsduLength(AMsduLength maxAMsduLength) {
      this.maxAMsduLength = maxAMsduLength;
      return this;
    }

    /**
     * @param dsssCckModeIn40MhzSupported dsssCckModeIn40MhzSupported
     * @return this Builder object for method chaining.
     */
    public Builder dsssCckModeIn40MhzSupported(boolean dsssCckModeIn40MhzSupported) {
      this.dsssCckModeIn40MhzSupported = dsssCckModeIn40MhzSupported;
      return this;
    }

    /**
     * @param bit13OfHtCapabilitiesInfo bit13OfHtCapabilitiesInfo
     * @return this Builder object for method chaining.
     */
    public Builder bit13OfHtCapabilitiesInfo(boolean bit13OfHtCapabilitiesInfo) {
      this.bit13OfHtCapabilitiesInfo = bit13OfHtCapabilitiesInfo;
      return this;
    }

    /**
     * @param fortyMhzIntolerant fortyMhzIntolerant
     * @return this Builder object for method chaining.
     */
    public Builder fortyMhzIntolerant(boolean fortyMhzIntolerant) {
      this.fortyMhzIntolerant = fortyMhzIntolerant;
      return this;
    }

    /**
     * @param lSigTxopProtectionSupported lSigTxopProtectionSupported
     * @return this Builder object for method chaining.
     */
    public Builder lSigTxopProtectionSupported(boolean lSigTxopProtectionSupported) {
      this.lSigTxopProtectionSupported = lSigTxopProtectionSupported;
      return this;
    }

    /**
     * @param maxAMpduLength maxAMpduLength
     * @return this Builder object for method chaining.
     */
    public Builder maxAMpduLength(AMpduLength maxAMpduLength) {
      this.maxAMpduLength = maxAMpduLength;
      return this;
    }

    /**
     * @param minMpduStartSpacing minMpduStartSpacing
     * @return this Builder object for method chaining.
     */
    public Builder minMpduStartSpacing(MpduStartSpacing minMpduStartSpacing) {
      this.minMpduStartSpacing = minMpduStartSpacing;
      return this;
    }

    /**
     * @param bit5OfAMpduParameters bit5OfAMpduParameters
     * @return this Builder object for method chaining.
     */
    public Builder bit5OfAMpduParameters(boolean bit5OfAMpduParameters) {
      this.bit5OfAMpduParameters = bit5OfAMpduParameters;
      return this;
    }

    /**
     * @param bit6OfAMpduParameters bit6OfAMpduParameters
     * @return this Builder object for method chaining.
     */
    public Builder bit6OfAMpduParameters(boolean bit6OfAMpduParameters) {
      this.bit6OfAMpduParameters = bit6OfAMpduParameters;
      return this;
    }

    /**
     * @param bit7OfAMpduParameters bit7OfAMpduParameters
     * @return this Builder object for method chaining.
     */
    public Builder bit7OfAMpduParameters(boolean bit7OfAMpduParameters) {
      this.bit7OfAMpduParameters = bit7OfAMpduParameters;
      return this;
    }

    /**
     * @param supportedRxMcsIndexes supportedRxMcsIndexes. supportedRxMcsIndexes.length must be 77.
     * @return this Builder object for method chaining.
     */
    public Builder supportedRxMcsIndexes(boolean[] supportedRxMcsIndexes) {
      this.supportedRxMcsIndexes = supportedRxMcsIndexes;
      return this;
    }

    /**
     * @param bit77OfSupportedMcsSet bit77OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit77OfSupportedMcsSet(boolean bit77OfSupportedMcsSet) {
      this.bit77OfSupportedMcsSet = bit77OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit78OfSupportedMcsSet bit78OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit78OfSupportedMcsSet(boolean bit78OfSupportedMcsSet) {
      this.bit78OfSupportedMcsSet = bit78OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit79OfSupportedMcsSet bit79OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit79OfSupportedMcsSet(boolean bit79OfSupportedMcsSet) {
      this.bit79OfSupportedMcsSet = bit79OfSupportedMcsSet;
      return this;
    }

    /**
     * @param rxHighestSupportedDataRate rxHighestSupportedDataRate. The value is between 0 and 1023
     *     (inclusive).
     * @return this Builder object for method chaining.
     */
    public Builder rxHighestSupportedDataRate(short rxHighestSupportedDataRate) {
      this.rxHighestSupportedDataRate = rxHighestSupportedDataRate;
      return this;
    }

    /**
     * @param bit90OfSupportedMcsSet bit90OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit90OfSupportedMcsSet(boolean bit90OfSupportedMcsSet) {
      this.bit90OfSupportedMcsSet = bit90OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit91OfSupportedMcsSet bit91OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit91OfSupportedMcsSet(boolean bit91OfSupportedMcsSet) {
      this.bit91OfSupportedMcsSet = bit91OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit92OfSupportedMcsSet bit92OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit92OfSupportedMcsSet(boolean bit92OfSupportedMcsSet) {
      this.bit92OfSupportedMcsSet = bit92OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit93OfSupportedMcsSet bit93OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit93OfSupportedMcsSet(boolean bit93OfSupportedMcsSet) {
      this.bit93OfSupportedMcsSet = bit93OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit94OfSupportedMcsSet bit94OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit94OfSupportedMcsSet(boolean bit94OfSupportedMcsSet) {
      this.bit94OfSupportedMcsSet = bit94OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit95OfSupportedMcsSet bit95OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit95OfSupportedMcsSet(boolean bit95OfSupportedMcsSet) {
      this.bit95OfSupportedMcsSet = bit95OfSupportedMcsSet;
      return this;
    }

    /**
     * @param txMcsSetDefined txMcsSetDefined
     * @return this Builder object for method chaining.
     */
    public Builder txMcsSetDefined(boolean txMcsSetDefined) {
      this.txMcsSetDefined = txMcsSetDefined;
      return this;
    }

    /**
     * @param txRxMcsSetNotEqual txRxMcsSetNotEqual
     * @return this Builder object for method chaining.
     */
    public Builder txRxMcsSetNotEqual(boolean txRxMcsSetNotEqual) {
      this.txRxMcsSetNotEqual = txRxMcsSetNotEqual;
      return this;
    }

    /**
     * @param txMaxNumSpatialStreamsSupported txMaxNumSpatialStreamsSupported
     * @return this Builder object for method chaining.
     */
    public Builder txMaxNumSpatialStreamsSupported(
        NumSpatialStreams txMaxNumSpatialStreamsSupported) {
      this.txMaxNumSpatialStreamsSupported = txMaxNumSpatialStreamsSupported;
      return this;
    }

    /**
     * @param txUnequalModulationSupported txUnequalModulationSupported
     * @return this Builder object for method chaining.
     */
    public Builder txUnequalModulationSupported(boolean txUnequalModulationSupported) {
      this.txUnequalModulationSupported = txUnequalModulationSupported;
      return this;
    }

    /**
     * @param bit101OfSupportedMcsSet bit101OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit101OfSupportedMcsSet(boolean bit101OfSupportedMcsSet) {
      this.bit101OfSupportedMcsSet = bit101OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit102OfSupportedMcsSet bit102OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit102OfSupportedMcsSet(boolean bit102OfSupportedMcsSet) {
      this.bit102OfSupportedMcsSet = bit102OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit103OfSupportedMcsSet bit103OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit103OfSupportedMcsSet(boolean bit103OfSupportedMcsSet) {
      this.bit103OfSupportedMcsSet = bit103OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit104OfSupportedMcsSet bit104OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit104OfSupportedMcsSet(boolean bit104OfSupportedMcsSet) {
      this.bit104OfSupportedMcsSet = bit104OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit105OfSupportedMcsSet bit105OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit105OfSupportedMcsSet(boolean bit105OfSupportedMcsSet) {
      this.bit105OfSupportedMcsSet = bit105OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit106OfSupportedMcsSet bit106OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit106OfSupportedMcsSet(boolean bit106OfSupportedMcsSet) {
      this.bit106OfSupportedMcsSet = bit106OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit107OfSupportedMcsSet bit107OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit107OfSupportedMcsSet(boolean bit107OfSupportedMcsSet) {
      this.bit107OfSupportedMcsSet = bit107OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit108OfSupportedMcsSet bit108OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit108OfSupportedMcsSet(boolean bit108OfSupportedMcsSet) {
      this.bit108OfSupportedMcsSet = bit108OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit109OfSupportedMcsSet bit109OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit109OfSupportedMcsSet(boolean bit109OfSupportedMcsSet) {
      this.bit109OfSupportedMcsSet = bit109OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit110OfSupportedMcsSet bit110OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit110OfSupportedMcsSet(boolean bit110OfSupportedMcsSet) {
      this.bit110OfSupportedMcsSet = bit110OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit111OfSupportedMcsSet bit111OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit111OfSupportedMcsSet(boolean bit111OfSupportedMcsSet) {
      this.bit111OfSupportedMcsSet = bit111OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit112OfSupportedMcsSet bit112OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit112OfSupportedMcsSet(boolean bit112OfSupportedMcsSet) {
      this.bit112OfSupportedMcsSet = bit112OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit113OfSupportedMcsSet bit113OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit113OfSupportedMcsSet(boolean bit113OfSupportedMcsSet) {
      this.bit113OfSupportedMcsSet = bit113OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit114OfSupportedMcsSet bit114OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit114OfSupportedMcsSet(boolean bit114OfSupportedMcsSet) {
      this.bit114OfSupportedMcsSet = bit114OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit115OfSupportedMcsSet bit115OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit115OfSupportedMcsSet(boolean bit115OfSupportedMcsSet) {
      this.bit115OfSupportedMcsSet = bit115OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit116OfSupportedMcsSet bit116OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit116OfSupportedMcsSet(boolean bit116OfSupportedMcsSet) {
      this.bit116OfSupportedMcsSet = bit116OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit117OfSupportedMcsSet bit117OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit117OfSupportedMcsSet(boolean bit117OfSupportedMcsSet) {
      this.bit117OfSupportedMcsSet = bit117OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit118OfSupportedMcsSet bit118OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit118OfSupportedMcsSet(boolean bit118OfSupportedMcsSet) {
      this.bit118OfSupportedMcsSet = bit118OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit119OfSupportedMcsSet bit119OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit119OfSupportedMcsSet(boolean bit119OfSupportedMcsSet) {
      this.bit119OfSupportedMcsSet = bit119OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit120OfSupportedMcsSet bit120OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit120OfSupportedMcsSet(boolean bit120OfSupportedMcsSet) {
      this.bit120OfSupportedMcsSet = bit120OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit121OfSupportedMcsSet bit121OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit121OfSupportedMcsSet(boolean bit121OfSupportedMcsSet) {
      this.bit121OfSupportedMcsSet = bit121OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit122OfSupportedMcsSet bit122OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit122OfSupportedMcsSet(boolean bit122OfSupportedMcsSet) {
      this.bit122OfSupportedMcsSet = bit122OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit123OfSupportedMcsSet bit123OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit123OfSupportedMcsSet(boolean bit123OfSupportedMcsSet) {
      this.bit123OfSupportedMcsSet = bit123OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit124OfSupportedMcsSet bit124OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit124OfSupportedMcsSet(boolean bit124OfSupportedMcsSet) {
      this.bit124OfSupportedMcsSet = bit124OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit125OfSupportedMcsSet bit125OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit125OfSupportedMcsSet(boolean bit125OfSupportedMcsSet) {
      this.bit125OfSupportedMcsSet = bit125OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit126OfSupportedMcsSet bit126OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit126OfSupportedMcsSet(boolean bit126OfSupportedMcsSet) {
      this.bit126OfSupportedMcsSet = bit126OfSupportedMcsSet;
      return this;
    }

    /**
     * @param bit127OfSupportedMcsSet bit127OfSupportedMcsSet
     * @return this Builder object for method chaining.
     */
    public Builder bit127OfSupportedMcsSet(boolean bit127OfSupportedMcsSet) {
      this.bit127OfSupportedMcsSet = bit127OfSupportedMcsSet;
      return this;
    }

    /**
     * @param pcoSupported pcoSupported
     * @return this Builder object for method chaining.
     */
    public Builder pcoSupported(boolean pcoSupported) {
      this.pcoSupported = pcoSupported;
      return this;
    }

    /**
     * @param pcoTransitionTime pcoTransitionTime
     * @return this Builder object for method chaining.
     */
    public Builder pcoTransitionTime(PcoTransitionTime pcoTransitionTime) {
      this.pcoTransitionTime = pcoTransitionTime;
      return this;
    }

    /**
     * @param bit3OfHtExtendedCapabilities bit3OfHtExtendedCapabilities
     * @return this Builder object for method chaining.
     */
    public Builder bit3OfHtExtendedCapabilities(boolean bit3OfHtExtendedCapabilities) {
      this.bit3OfHtExtendedCapabilities = bit3OfHtExtendedCapabilities;
      return this;
    }

    /**
     * @param bit4OfHtExtendedCapabilities bit4OfHtExtendedCapabilities
     * @return this Builder object for method chaining.
     */
    public Builder bit4OfHtExtendedCapabilities(boolean bit4OfHtExtendedCapabilities) {
      this.bit4OfHtExtendedCapabilities = bit4OfHtExtendedCapabilities;
      return this;
    }

    /**
     * @param bit5OfHtExtendedCapabilities bit5OfHtExtendedCapabilities
     * @return this Builder object for method chaining.
     */
    public Builder bit5OfHtExtendedCapabilities(boolean bit5OfHtExtendedCapabilities) {
      this.bit5OfHtExtendedCapabilities = bit5OfHtExtendedCapabilities;
      return this;
    }

    /**
     * @param bit6OfHtExtendedCapabilities bit6OfHtExtendedCapabilities
     * @return this Builder object for method chaining.
     */
    public Builder bit6OfHtExtendedCapabilities(boolean bit6OfHtExtendedCapabilities) {
      this.bit6OfHtExtendedCapabilities = bit6OfHtExtendedCapabilities;
      return this;
    }

    /**
     * @param bit7OfHtExtendedCapabilities bit7OfHtExtendedCapabilities
     * @return this Builder object for method chaining.
     */
    public Builder bit7OfHtExtendedCapabilities(boolean bit7OfHtExtendedCapabilities) {
      this.bit7OfHtExtendedCapabilities = bit7OfHtExtendedCapabilities;
      return this;
    }

    /**
     * @param mcsFeedbackCapability mcsFeedbackCapability
     * @return this Builder object for method chaining.
     */
    public Builder mcsFeedbackCapability(McsFeedbackCapability mcsFeedbackCapability) {
      this.mcsFeedbackCapability = mcsFeedbackCapability;
      return this;
    }

    /**
     * @param htControlFieldSupported htControlFieldSupported
     * @return this Builder object for method chaining.
     */
    public Builder htControlFieldSupported(boolean htControlFieldSupported) {
      this.htControlFieldSupported = htControlFieldSupported;
      return this;
    }

    /**
     * @param rdResponderSupported rdResponderSupported
     * @return this Builder object for method chaining.
     */
    public Builder rdResponderSupported(boolean rdResponderSupported) {
      this.rdResponderSupported = rdResponderSupported;
      return this;
    }

    /**
     * @param bit12OfHtExtendedCapabilities bit12OfHtExtendedCapabilities
     * @return this Builder object for method chaining.
     */
    public Builder bit12OfHtExtendedCapabilities(boolean bit12OfHtExtendedCapabilities) {
      this.bit12OfHtExtendedCapabilities = bit12OfHtExtendedCapabilities;
      return this;
    }

    /**
     * @param bit13OfHtExtendedCapabilities bit13OfHtExtendedCapabilities
     * @return this Builder object for method chaining.
     */
    public Builder bit13OfHtExtendedCapabilities(boolean bit13OfHtExtendedCapabilities) {
      this.bit13OfHtExtendedCapabilities = bit13OfHtExtendedCapabilities;
      return this;
    }

    /**
     * @param bit14OfHtExtendedCapabilities bit14OfHtExtendedCapabilities
     * @return this Builder object for method chaining.
     */
    public Builder bit14OfHtExtendedCapabilities(boolean bit14OfHtExtendedCapabilities) {
      this.bit14OfHtExtendedCapabilities = bit14OfHtExtendedCapabilities;
      return this;
    }

    /**
     * @param bit15OfHtExtendedCapabilities bit15OfHtExtendedCapabilities
     * @return this Builder object for method chaining.
     */
    public Builder bit15OfHtExtendedCapabilities(boolean bit15OfHtExtendedCapabilities) {
      this.bit15OfHtExtendedCapabilities = bit15OfHtExtendedCapabilities;
      return this;
    }

    /**
     * @param implicitTxBeamformingReceivingSupported implicitTxBeamformingReceivingSupported
     * @return this Builder object for method chaining.
     */
    public Builder implicitTxBeamformingReceivingSupported(
        boolean implicitTxBeamformingReceivingSupported) {
      this.implicitTxBeamformingReceivingSupported = implicitTxBeamformingReceivingSupported;
      return this;
    }

    /**
     * @param rxStaggeredSoundingSupported rxStaggeredSoundingSupported
     * @return this Builder object for method chaining.
     */
    public Builder rxStaggeredSoundingSupported(boolean rxStaggeredSoundingSupported) {
      this.rxStaggeredSoundingSupported = rxStaggeredSoundingSupported;
      return this;
    }

    /**
     * @param txStaggeredSoundingSupported txStaggeredSoundingSupported
     * @return this Builder object for method chaining.
     */
    public Builder txStaggeredSoundingSupported(boolean txStaggeredSoundingSupported) {
      this.txStaggeredSoundingSupported = txStaggeredSoundingSupported;
      return this;
    }

    /**
     * @param rxNdpSupported rxNdpSupported
     * @return this Builder object for method chaining.
     */
    public Builder rxNdpSupported(boolean rxNdpSupported) {
      this.rxNdpSupported = rxNdpSupported;
      return this;
    }

    /**
     * @param txNdpSupported txNdpSupported
     * @return this Builder object for method chaining.
     */
    public Builder txNdpSupported(boolean txNdpSupported) {
      this.txNdpSupported = txNdpSupported;
      return this;
    }

    /**
     * @param implicitTxBeamformingSupported implicitTxBeamformingSupported
     * @return this Builder object for method chaining.
     */
    public Builder implicitTxBeamformingSupported(boolean implicitTxBeamformingSupported) {
      this.implicitTxBeamformingSupported = implicitTxBeamformingSupported;
      return this;
    }

    /**
     * @param calibration calibration
     * @return this Builder object for method chaining.
     */
    public Builder calibration(Calibration calibration) {
      this.calibration = calibration;
      return this;
    }

    /**
     * @param explicitCsiTxBeamformingSupported explicitCsiTxBeamformingSupported
     * @return this Builder object for method chaining.
     */
    public Builder explicitCsiTxBeamformingSupported(boolean explicitCsiTxBeamformingSupported) {
      this.explicitCsiTxBeamformingSupported = explicitCsiTxBeamformingSupported;
      return this;
    }

    /**
     * @param explicitNoncompressedSteeringSupported explicitNoncompressedSteeringSupported
     * @return this Builder object for method chaining.
     */
    public Builder explicitNoncompressedSteeringSupported(
        boolean explicitNoncompressedSteeringSupported) {
      this.explicitNoncompressedSteeringSupported = explicitNoncompressedSteeringSupported;
      return this;
    }

    /**
     * @param explicitCompressedSteeringSupported explicitCompressedSteeringSupported
     * @return this Builder object for method chaining.
     */
    public Builder explicitCompressedSteeringSupported(
        boolean explicitCompressedSteeringSupported) {
      this.explicitCompressedSteeringSupported = explicitCompressedSteeringSupported;
      return this;
    }

    /**
     * @param explicitTxBeamformingCsiFeedbackCapability explicitTxBeamformingCsiFeedbackCapability
     * @return this Builder object for method chaining.
     */
    public Builder explicitTxBeamformingCsiFeedbackCapability(
        BeamformingFeedbackCapability explicitTxBeamformingCsiFeedbackCapability) {
      this.explicitTxBeamformingCsiFeedbackCapability = explicitTxBeamformingCsiFeedbackCapability;
      return this;
    }

    /**
     * @param explicitNoncompressedBeamformingFeedbackCapability
     *     explicitNoncompressedBeamformingFeedbackCapability
     * @return this Builder object for method chaining.
     */
    public Builder explicitNoncompressedBeamformingFeedbackCapability(
        BeamformingFeedbackCapability explicitNoncompressedBeamformingFeedbackCapability) {
      this.explicitNoncompressedBeamformingFeedbackCapability =
          explicitNoncompressedBeamformingFeedbackCapability;
      return this;
    }

    /**
     * @param explicitCompressedBeamformingFeedbackCapability
     *     explicitCompressedBeamformingFeedbackCapability
     * @return this Builder object for method chaining.
     */
    public Builder explicitCompressedBeamformingFeedbackCapability(
        BeamformingFeedbackCapability explicitCompressedBeamformingFeedbackCapability) {
      this.explicitCompressedBeamformingFeedbackCapability =
          explicitCompressedBeamformingFeedbackCapability;
      return this;
    }

    /**
     * @param minGrouping minGrouping
     * @return this Builder object for method chaining.
     */
    public Builder minGrouping(Grouping minGrouping) {
      this.minGrouping = minGrouping;
      return this;
    }

    /**
     * @param csiNumBeamformerAntennasSupported csiNumBeamformerAntennasSupported
     * @return this Builder object for method chaining.
     */
    public Builder csiNumBeamformerAntennasSupported(
        NumBeamformerAntennas csiNumBeamformerAntennasSupported) {
      this.csiNumBeamformerAntennasSupported = csiNumBeamformerAntennasSupported;
      return this;
    }

    /**
     * @param noncompressedSteeringNumBeamformerAntennasSupported
     *     noncompressedSteeringNumBeamformerAntennasSupported
     * @return this Builder object for method chaining.
     */
    public Builder noncompressedSteeringNumBeamformerAntennasSupported(
        NumBeamformerAntennas noncompressedSteeringNumBeamformerAntennasSupported) {
      this.noncompressedSteeringNumBeamformerAntennasSupported =
          noncompressedSteeringNumBeamformerAntennasSupported;
      return this;
    }

    /**
     * @param compressedSteeringNumBeamformerAntennasSupported
     *     compressedSteeringNumBeamformerAntennasSupported
     * @return this Builder object for method chaining.
     */
    public Builder compressedSteeringNumBeamformerAntennasSupported(
        NumBeamformerAntennas compressedSteeringNumBeamformerAntennasSupported) {
      this.compressedSteeringNumBeamformerAntennasSupported =
          compressedSteeringNumBeamformerAntennasSupported;
      return this;
    }

    /**
     * @param csiMaxNumRowsBeamformerSupported csiMaxNumRowsBeamformerSupported
     * @return this Builder object for method chaining.
     */
    public Builder csiMaxNumRowsBeamformerSupported(CsiNumRows csiMaxNumRowsBeamformerSupported) {
      this.csiMaxNumRowsBeamformerSupported = csiMaxNumRowsBeamformerSupported;
      return this;
    }

    /**
     * @param channelEstimationCapability channelEstimationCapability
     * @return this Builder object for method chaining.
     */
    public Builder channelEstimationCapability(
        ChannelEstimationCapability channelEstimationCapability) {
      this.channelEstimationCapability = channelEstimationCapability;
      return this;
    }

    /**
     * @param bit29OfTransmitBeamformingCapabilities bit29OfTransmitBeamformingCapabilities
     * @return this Builder object for method chaining.
     */
    public Builder bit29OfTransmitBeamformingCapabilities(
        boolean bit29OfTransmitBeamformingCapabilities) {
      this.bit29OfTransmitBeamformingCapabilities = bit29OfTransmitBeamformingCapabilities;
      return this;
    }

    /**
     * @param bit30OfTransmitBeamformingCapabilities bit30OfTransmitBeamformingCapabilities
     * @return this Builder object for method chaining.
     */
    public Builder bit30OfTransmitBeamformingCapabilities(
        boolean bit30OfTransmitBeamformingCapabilities) {
      this.bit30OfTransmitBeamformingCapabilities = bit30OfTransmitBeamformingCapabilities;
      return this;
    }

    /**
     * @param bit31OfTransmitBeamformingCapabilities bit31OfTransmitBeamformingCapabilities
     * @return this Builder object for method chaining.
     */
    public Builder bit31OfTransmitBeamformingCapabilities(
        boolean bit31OfTransmitBeamformingCapabilities) {
      this.bit31OfTransmitBeamformingCapabilities = bit31OfTransmitBeamformingCapabilities;
      return this;
    }

    /**
     * @param antennaSelectionSupported antennaSelectionSupported
     * @return this Builder object for method chaining.
     */
    public Builder antennaSelectionSupported(boolean antennaSelectionSupported) {
      this.antennaSelectionSupported = antennaSelectionSupported;
      return this;
    }

    /**
     * @param explicitCsiFeedbackBasedTxAselSupported explicitCsiFeedbackBasedTxAselSupported
     * @return this Builder object for method chaining.
     */
    public Builder explicitCsiFeedbackBasedTxAselSupported(
        boolean explicitCsiFeedbackBasedTxAselSupported) {
      this.explicitCsiFeedbackBasedTxAselSupported = explicitCsiFeedbackBasedTxAselSupported;
      return this;
    }

    /**
     * @param antennaIndicesFeedbackBasedTxAselSupported antennaIndicesFeedbackBasedTxAselSupported
     * @return this Builder object for method chaining.
     */
    public Builder antennaIndicesFeedbackBasedTxAselSupported(
        boolean antennaIndicesFeedbackBasedTxAselSupported) {
      this.antennaIndicesFeedbackBasedTxAselSupported = antennaIndicesFeedbackBasedTxAselSupported;
      return this;
    }

    /**
     * @param explicitCsiFeedbackSupported explicitCsiFeedbackSupported
     * @return this Builder object for method chaining.
     */
    public Builder explicitCsiFeedbackSupported(boolean explicitCsiFeedbackSupported) {
      this.explicitCsiFeedbackSupported = explicitCsiFeedbackSupported;
      return this;
    }

    /**
     * @param antennaIndicesFeedbackSupported antennaIndicesFeedbackSupported
     * @return this Builder object for method chaining.
     */
    public Builder antennaIndicesFeedbackSupported(boolean antennaIndicesFeedbackSupported) {
      this.antennaIndicesFeedbackSupported = antennaIndicesFeedbackSupported;
      return this;
    }

    /**
     * @param rxAselSupported rxAselSupported
     * @return this Builder object for method chaining.
     */
    public Builder rxAselSupported(boolean rxAselSupported) {
      this.rxAselSupported = rxAselSupported;
      return this;
    }

    /**
     * @param txSoundingPpdusSupported txSoundingPpdusSupported
     * @return this Builder object for method chaining.
     */
    public Builder txSoundingPpdusSupported(boolean txSoundingPpdusSupported) {
      this.txSoundingPpdusSupported = txSoundingPpdusSupported;
      return this;
    }

    /**
     * @param bit7OfAselCapability bit7OfAselCapability
     * @return this Builder object for method chaining.
     */
    public Builder bit7OfAselCapability(boolean bit7OfAselCapability) {
      this.bit7OfAselCapability = bit7OfAselCapability;
      return this;
    }

    @Override
    public Builder length(byte length) {
      super.length(length);
      return this;
    }

    @Override
    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      super.correctLengthAtBuild(correctLengthAtBuild);
      return this;
    }

    @Override
    public Dot11HTCapabilitiesElement build() {
      if (getCorrectLengthAtBuild()) {
        length((byte) 26);
      }
      return new Dot11HTCapabilitiesElement(this);
    }
  }
}
