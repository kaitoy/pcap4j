/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.nio.ByteOrder;
import java.util.Arrays;
import org.pcap4j.packet.RadiotapPacket.RadiotapData;
import org.pcap4j.packet.namednumber.RadiotapVhtBandwidth;
import org.pcap4j.util.ByteArrays;

/**
 * Radiotap VHT field.
 *
 * @see <a href="http://www.radiotap.org/defined-fields/VHT">Radiotap</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class RadiotapDataVht implements RadiotapData {

  /** */
  private static final long serialVersionUID = -7423738690741454273L;

  private static final int LENGTH = 12;

  private final boolean stbcKnown;
  private final boolean txopPsNotAllowedKnown;
  private final boolean guardIntervalKnown;
  private final boolean shortGiNsymDisambiguationKnown;
  private final boolean ldpcExtraOfdmSymbolKnown;
  private final boolean beamformedKnown;
  private final boolean bandwidthKnown;
  private final boolean groupIdKnown;
  private final boolean partialAidKnown;
  private final boolean seventhMsbOfKnown;
  private final boolean sixthMsbOfKnown;
  private final boolean fifthMsbOfKnown;
  private final boolean fourthMsbOfKnown;
  private final boolean thirdMsbOfKnown;
  private final boolean secondMsbOfKnown;
  private final boolean msbOfKnown;
  private final boolean stbc;
  private final boolean txopPsNotAllowed;
  private final boolean shortGuardInterval;
  private final boolean shortGiNsymDisambiguation;
  private final boolean ldpcExtraOfdmSymbol;
  private final boolean beamformed;
  private final boolean secondMsbOfFlags;
  private final boolean msbOfFlags;
  private final RadiotapVhtBandwidth bandwidth;
  private final byte[] mcses;
  private final byte[] nsses;
  private final RadiotapFecType[] fecTypes;
  private final byte unusedInCoding;
  private final byte groupId;
  private final short partialAid;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new RadiotapVht object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static RadiotapDataVht newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new RadiotapDataVht(rawData, offset, length);
  }

  private RadiotapDataVht(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    if (length < LENGTH) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("The data is too short to build a RadiotapVht (")
          .append(LENGTH)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.stbcKnown = (rawData[offset] & 0x01) != 0;
    this.txopPsNotAllowedKnown = (rawData[offset] & 0x02) != 0;
    this.guardIntervalKnown = (rawData[offset] & 0x04) != 0;
    this.shortGiNsymDisambiguationKnown = (rawData[offset] & 0x08) != 0;
    this.ldpcExtraOfdmSymbolKnown = (rawData[offset] & 0x10) != 0;
    this.beamformedKnown = (rawData[offset] & 0x20) != 0;
    this.bandwidthKnown = (rawData[offset] & 0x40) != 0;
    this.groupIdKnown = (rawData[offset] & 0x80) != 0;
    this.partialAidKnown = (rawData[offset + 1] & 0x01) != 0;
    this.seventhMsbOfKnown = (rawData[offset + 1] & 0x02) != 0;
    this.sixthMsbOfKnown = (rawData[offset + 1] & 0x04) != 0;
    this.fifthMsbOfKnown = (rawData[offset + 1] & 0x08) != 0;
    this.fourthMsbOfKnown = (rawData[offset + 1] & 0x10) != 0;
    this.thirdMsbOfKnown = (rawData[offset + 1] & 0x20) != 0;
    this.secondMsbOfKnown = (rawData[offset + 1] & 0x40) != 0;
    this.msbOfKnown = (rawData[offset + 1] & 0x80) != 0;
    this.stbc = (rawData[offset + 2] & 0x01) != 0;
    this.txopPsNotAllowed = (rawData[offset + 2] & 0x02) != 0;
    this.shortGuardInterval = (rawData[offset + 2] & 0x04) != 0;
    this.shortGiNsymDisambiguation = (rawData[offset + 2] & 0x08) != 0;
    this.ldpcExtraOfdmSymbol = (rawData[offset + 2] & 0x10) != 0;
    this.beamformed = (rawData[offset + 2] & 0x20) != 0;
    this.secondMsbOfFlags = (rawData[offset + 2] & 0x40) != 0;
    this.msbOfFlags = (rawData[offset + 2] & 0x80) != 0;
    this.bandwidth = RadiotapVhtBandwidth.getInstance(rawData[offset + 3]);
    this.mcses = new byte[4];
    this.nsses = new byte[4];
    for (int i = 0; i < 4; i++) {
      byte mcsNss = rawData[offset + 4 + i];
      mcses[i] = (byte) ((mcsNss >> 4) & 0x0F);
      nsses[i] = (byte) (mcsNss & 0x0F);
    }
    this.fecTypes = new RadiotapFecType[4];
    for (int i = 0; i < 4; i++) {
      switch ((rawData[offset + 8] >> i) & 0x01) {
        case 0:
          fecTypes[i] = RadiotapFecType.BCC;
          break;
        default:
          fecTypes[i] = RadiotapFecType.LDPC;
      }
    }
    this.unusedInCoding = (byte) ((rawData[offset + 8] >> 4) & 0x0F);
    this.groupId = rawData[offset + 9];
    this.partialAid = ByteArrays.getShort(rawData, offset + 10, ByteOrder.LITTLE_ENDIAN);
  }

  private RadiotapDataVht(Builder builder) {
    if (builder == null
        || builder.bandwidth == null
        || builder.mcses == null
        || builder.nsses == null
        || builder.fecTypes == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.bandwidth: ")
          .append(builder.bandwidth)
          .append(" builder.mcses: ")
          .append(builder.mcses)
          .append(" builder.nsses: ")
          .append(builder.nsses)
          .append(" builder.fecTypes: ")
          .append(builder.fecTypes);
      throw new NullPointerException(sb.toString());
    }
    if ((builder.unusedInCoding & 0xF0) != 0) {
      throw new IllegalArgumentException(
          "builder.unusedInCoding & 0xF0 must be 0. builder.unusedInCoding: "
              + builder.unusedInCoding);
    }
    if (builder.mcses.length != 4) {
      throw new IllegalArgumentException(
          "builder.mcses.length must be 4. builder.mcses: " + Arrays.toString(builder.mcses));
    }
    if (builder.nsses.length != 4) {
      throw new IllegalArgumentException(
          "builder.nsses.length must be 4. builder.nsses: " + Arrays.toString(builder.nsses));
    }
    if (builder.fecTypes.length != 4) {
      throw new IllegalArgumentException(
          "builder.fecTypes.length must be 4. builder.fecTypes: "
              + Arrays.toString(builder.fecTypes));
    }
    for (byte mcs : builder.mcses) {
      if ((mcs & 0xF0) != 0) {
        throw new IllegalArgumentException(
            "(mcs & 0xF0) must be zero. builder.mcses: " + Arrays.toString(builder.mcses));
      }
    }
    for (byte nss : builder.nsses) {
      if ((nss & 0xF0) != 0) {
        throw new IllegalArgumentException(
            "(nss & 0xF0) must be zero. builder.nsses: " + Arrays.toString(builder.nsses));
      }
    }

    this.stbcKnown = builder.stbcKnown;
    this.txopPsNotAllowedKnown = builder.txopPsNotAllowedKnown;
    this.guardIntervalKnown = builder.guardIntervalKnown;
    this.shortGiNsymDisambiguationKnown = builder.shortGiNsymDisambiguationKnown;
    this.ldpcExtraOfdmSymbolKnown = builder.ldpcExtraOfdmSymbolKnown;
    this.beamformedKnown = builder.beamformedKnown;
    this.bandwidthKnown = builder.bandwidthKnown;
    this.groupIdKnown = builder.groupIdKnown;
    this.partialAidKnown = builder.partialAidKnown;
    this.seventhMsbOfKnown = builder.seventhMsbOfKnown;
    this.sixthMsbOfKnown = builder.sixthMsbOfKnown;
    this.fifthMsbOfKnown = builder.fifthMsbOfKnown;
    this.fourthMsbOfKnown = builder.fourthMsbOfKnown;
    this.thirdMsbOfKnown = builder.thirdMsbOfKnown;
    this.secondMsbOfKnown = builder.secondMsbOfKnown;
    this.msbOfKnown = builder.msbOfKnown;
    this.stbc = builder.stbc;
    this.txopPsNotAllowed = builder.txopPsNotAllowed;
    this.shortGuardInterval = builder.shortGuardInterval;
    this.shortGiNsymDisambiguation = builder.shortGiNsymDisambiguation;
    this.ldpcExtraOfdmSymbol = builder.ldpcExtraOfdmSymbol;
    this.beamformed = builder.beamformed;
    this.secondMsbOfFlags = builder.secondMsbOfFlags;
    this.msbOfFlags = builder.msbOfFlags;
    this.bandwidth = builder.bandwidth;
    this.mcses = ByteArrays.clone(builder.mcses);
    this.nsses = ByteArrays.clone(builder.nsses);
    this.fecTypes = builder.fecTypes.clone();
    this.unusedInCoding = builder.unusedInCoding;
    this.groupId = builder.groupId;
    this.partialAid = builder.partialAid;
  }

  /** @return true if the STBC is known; false otherwise. */
  public boolean isStbcKnown() {
    return stbcKnown;
  }

  /** @return true if the TXOP_PS_NOT_ALLOWED is known; false otherwise. */
  public boolean isTxopPsNotAllowedKnown() {
    return txopPsNotAllowedKnown;
  }

  /** @return true if the Guard interval is known; false otherwise. */
  public boolean isGuardIntervalKnown() {
    return guardIntervalKnown;
  }

  /** @return true if the Short GI NSYM disambiguation is known; false otherwise. */
  public boolean isShortGiNsymDisambiguationKnown() {
    return shortGiNsymDisambiguationKnown;
  }

  /** @return true if the LDPC extra OFDM symbol is known; false otherwise. */
  public boolean isLdpcExtraOfdmSymbolKnown() {
    return ldpcExtraOfdmSymbolKnown;
  }

  /** @return true if the Beamformed is known; false otherwise. */
  public boolean isBeamformedKnown() {
    return beamformedKnown;
  }

  /** @return true if the Bandwidth is known; false otherwise. */
  public boolean isBandwidthKnown() {
    return bandwidthKnown;
  }

  /** @return true if the Group ID is known; false otherwise. */
  public boolean isGroupIdKnown() {
    return groupIdKnown;
  }

  /** @return true if the Partial AID is known; false otherwise. */
  public boolean isPartialAidKnown() {
    return partialAidKnown;
  }

  /** @return true if the seventh MSB of the known field is set to 1; false otherwise. */
  public boolean getSeventhMsbOfKnown() {
    return seventhMsbOfKnown;
  }

  /** @return true if the sixth MSB of the known field is set to 1; false otherwise. */
  public boolean getSixthMsbOfKnown() {
    return sixthMsbOfKnown;
  }

  /** @return true if the fifth MSB of the known field is set to 1; false otherwise. */
  public boolean getFifthMsbOfKnown() {
    return fifthMsbOfKnown;
  }

  /** @return true if the fourth MSB of the known field is set to 1; false otherwise. */
  public boolean getFourthMsbOfKnown() {
    return fourthMsbOfKnown;
  }

  /** @return true if the third MSB of the known field is set to 1; false otherwise. */
  public boolean getThirdMsbOfKnown() {
    return thirdMsbOfKnown;
  }

  /** @return true if the second MSB of the known field is set to 1; false otherwise. */
  public boolean getSecondMsbOfKnown() {
    return secondMsbOfKnown;
  }

  /** @return true if the MSB of the known field is set to 1; false otherwise. */
  public boolean getMsbOfKnown() {
    return msbOfKnown;
  }

  /** @return true if all spatial streams of all users have STBC; false otherwise. */
  public boolean isStbc() {
    return stbc;
  }

  /** @return true if STAs may not doze during TXOP or transmitter is non-AP; false otherwise. */
  public boolean isTxopPsNotAllowed() {
    return txopPsNotAllowed;
  }

  /** @return true if short GI; false otherwise. */
  public boolean isShortGuardInterval() {
    return shortGuardInterval;
  }

  /** @return true if NSYM mod 10 = 9; false otherwise. */
  public boolean isShortGiNsymDisambiguation() {
    return shortGiNsymDisambiguation;
  }

  /**
   * @return true if one or more users are using LDPC and the encoding process resulted in extra
   *     OFDM symbol(s); false otherwise.
   */
  public boolean isLdpcExtraOfdmSymbol() {
    return ldpcExtraOfdmSymbol;
  }

  /** @return true if Beamformed; false otherwise. */
  public boolean isBeamformed() {
    return beamformed;
  }

  /** @return true if the second MSB of the flags field is set to 1; false otherwise. */
  public boolean getSecondMsbOfFlags() {
    return secondMsbOfFlags;
  }

  /** @return true if the MSB of the flags field is set to 1; false otherwise. */
  public boolean getMsbOfFlags() {
    return msbOfFlags;
  }

  /** @return bandwidth */
  public RadiotapVhtBandwidth getBandwidth() {
    return bandwidth;
  }

  /** @return MCSes for four users. mcses[n] is for user n. */
  public byte[] getMcses() {
    return ByteArrays.clone(mcses);
  }

  /** @return NSSes for four users. nsses[n] is for user n. */
  public byte[] getNsses() {
    return ByteArrays.clone(nsses);
  }

  /** @return FEC types for four users. fecTypes[n] is for user n. */
  public RadiotapFecType[] getFecTypes() {
    return fecTypes.clone();
  }

  /** @return unusedInCoding */
  public byte getUnusedInCoding() {
    return unusedInCoding;
  }

  /** @return groupId */
  public byte getGroupId() {
    return groupId;
  }

  /** @return groupId */
  public int getGroupIdAsInt() {
    return groupId & 0xFF;
  }

  /** @return partialAid */
  public short getPartialAid() {
    return partialAid;
  }

  /** @return partialAid */
  public int getPartialAidAsInt() {
    return partialAid & 0xFFFF;
  }

  @Override
  public int length() {
    return LENGTH;
  }

  @Override
  public byte[] getRawData() {
    byte[] data = new byte[LENGTH];

    if (stbcKnown) {
      data[0] |= 0x01;
    }
    if (txopPsNotAllowedKnown) {
      data[0] |= 0x02;
    }
    if (guardIntervalKnown) {
      data[0] |= 0x04;
    }
    if (shortGiNsymDisambiguationKnown) {
      data[0] |= 0x08;
    }
    if (ldpcExtraOfdmSymbolKnown) {
      data[0] |= 0x10;
    }
    if (beamformedKnown) {
      data[0] |= 0x20;
    }
    if (bandwidthKnown) {
      data[0] |= 0x40;
    }
    if (groupIdKnown) {
      data[0] |= 0x80;
    }
    if (partialAidKnown) {
      data[1] |= 0x01;
    }
    if (seventhMsbOfKnown) {
      data[1] |= 0x02;
    }
    if (sixthMsbOfKnown) {
      data[1] |= 0x04;
    }
    if (fifthMsbOfKnown) {
      data[1] |= 0x08;
    }
    if (fourthMsbOfKnown) {
      data[1] |= 0x10;
    }
    if (thirdMsbOfKnown) {
      data[1] |= 0x20;
    }
    if (secondMsbOfKnown) {
      data[1] |= 0x40;
    }
    if (msbOfKnown) {
      data[1] |= 0x80;
    }
    if (stbc) {
      data[2] |= 0x01;
    }
    if (txopPsNotAllowed) {
      data[2] |= 0x02;
    }
    if (shortGuardInterval) {
      data[2] |= 0x04;
    }
    if (shortGiNsymDisambiguation) {
      data[2] |= 0x08;
    }
    if (ldpcExtraOfdmSymbol) {
      data[2] |= 0x10;
    }
    if (beamformed) {
      data[2] |= 0x20;
    }
    if (secondMsbOfFlags) {
      data[2] |= 0x40;
    }
    if (msbOfFlags) {
      data[2] |= 0x80;
    }
    data[3] = bandwidth.value();
    for (int i = 0; i < 4; i++) {
      data[4 + i] = (byte) (nsses[i] | (mcses[i] << 4));
    }
    data[8] = (byte) (unusedInCoding << 4);
    if (fecTypes[0] == RadiotapFecType.LDPC) {
      data[8] |= 0x01;
    }
    if (fecTypes[1] == RadiotapFecType.LDPC) {
      data[8] |= 0x02;
    }
    if (fecTypes[2] == RadiotapFecType.LDPC) {
      data[8] |= 0x04;
    }
    if (fecTypes[3] == RadiotapFecType.LDPC) {
      data[8] |= 0x08;
    }
    data[9] = groupId;
    System.arraycopy(ByteArrays.toByteArray(partialAid, ByteOrder.LITTLE_ENDIAN), 0, data, 10, 2);

    return data;
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public String toString() {
    return toString("");
  }

  @Override
  public String toString(String indent) {
    StringBuilder sb = new StringBuilder();
    String ls = System.getProperty("line.separator");

    sb.append(indent)
        .append("VHT: ")
        .append(ls)
        .append(indent)
        .append("  STBC known: ")
        .append(stbcKnown)
        .append(ls)
        .append(indent)
        .append("  TXOP_PS_NOT_ALLOWED known: ")
        .append(txopPsNotAllowedKnown)
        .append(ls)
        .append(indent)
        .append("  Guard interval known: ")
        .append(guardIntervalKnown)
        .append(ls)
        .append(indent)
        .append("  Short GI NSYM disambiguation known: ")
        .append(shortGiNsymDisambiguationKnown)
        .append(ls)
        .append(indent)
        .append("  LDPC extra OFDM symbol known: ")
        .append(ldpcExtraOfdmSymbolKnown)
        .append(ls)
        .append(indent)
        .append("  Beamformed known: ")
        .append(beamformedKnown)
        .append(ls)
        .append(indent)
        .append("  Bandwidth known: ")
        .append(bandwidthKnown)
        .append(ls)
        .append(indent)
        .append("  Group ID known: ")
        .append(groupIdKnown)
        .append(ls)
        .append(indent)
        .append("  Partial AID known: ")
        .append(partialAidKnown)
        .append(ls)
        .append(indent)
        .append("  7th MSB of known: ")
        .append(seventhMsbOfKnown)
        .append(ls)
        .append(indent)
        .append("  6th MSB of known: ")
        .append(sixthMsbOfKnown)
        .append(ls)
        .append(indent)
        .append("  5th MSB of known: ")
        .append(fifthMsbOfKnown)
        .append(ls)
        .append(indent)
        .append("  4th MSB of known: ")
        .append(fourthMsbOfKnown)
        .append(ls)
        .append(indent)
        .append("  3rd MSB of known: ")
        .append(thirdMsbOfKnown)
        .append(ls)
        .append(indent)
        .append("  2nd MSB of known: ")
        .append(secondMsbOfKnown)
        .append(ls)
        .append(indent)
        .append("  MSB of known: ")
        .append(msbOfKnown)
        .append(ls)
        .append(indent)
        .append("  STBC: ")
        .append(stbc)
        .append(ls)
        .append(indent)
        .append("  TXOP_PS_NOT_ALLOWED: ")
        .append(txopPsNotAllowed)
        .append(ls)
        .append(indent)
        .append("  Short Guard interval: ")
        .append(shortGuardInterval)
        .append(ls)
        .append(indent)
        .append("  Short GI NSYM disambiguation: ")
        .append(shortGiNsymDisambiguation)
        .append(ls)
        .append(indent)
        .append("  LDPC extra OFDM symbol: ")
        .append(ldpcExtraOfdmSymbol)
        .append(ls)
        .append(indent)
        .append("  Beamformed: ")
        .append(beamformed)
        .append(ls)
        .append(indent)
        .append("  2nd MSB of flags: ")
        .append(secondMsbOfFlags)
        .append(ls)
        .append(indent)
        .append("  MSB of flags: ")
        .append(msbOfFlags)
        .append(ls)
        .append(indent)
        .append("  Bandwidth: ")
        .append(bandwidth)
        .append(ls);
    for (int i = 0; i < 4; i++) {
      sb.append(indent).append("  NSS-").append(i).append(": ").append(nsses[i]).append(ls);
    }
    for (int i = 0; i < 4; i++) {
      sb.append(indent).append("  MCS-").append(i).append(": ").append(mcses[i]).append(ls);
    }
    for (int i = 0; i < 4; i++) {
      sb.append(indent).append("  FEC-").append(i).append(": ").append(fecTypes[i]).append(ls);
    }
    sb.append(indent)
        .append("  Group ID: ")
        .append(getGroupIdAsInt())
        .append(ls)
        .append(indent)
        .append("  Partial AID: ")
        .append(getPartialAidAsInt())
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + bandwidth.hashCode();
    result = prime * result + (bandwidthKnown ? 1231 : 1237);
    result = prime * result + (beamformed ? 1231 : 1237);
    result = prime * result + (beamformedKnown ? 1231 : 1237);
    result = prime * result + Arrays.hashCode(fecTypes);
    result = prime * result + (fifthMsbOfKnown ? 1231 : 1237);
    result = prime * result + (fourthMsbOfKnown ? 1231 : 1237);
    result = prime * result + groupId;
    result = prime * result + (groupIdKnown ? 1231 : 1237);
    result = prime * result + (guardIntervalKnown ? 1231 : 1237);
    result = prime * result + (ldpcExtraOfdmSymbol ? 1231 : 1237);
    result = prime * result + (ldpcExtraOfdmSymbolKnown ? 1231 : 1237);
    result = prime * result + Arrays.hashCode(mcses);
    result = prime * result + (msbOfFlags ? 1231 : 1237);
    result = prime * result + (msbOfKnown ? 1231 : 1237);
    result = prime * result + Arrays.hashCode(nsses);
    result = prime * result + partialAid;
    result = prime * result + (partialAidKnown ? 1231 : 1237);
    result = prime * result + (secondMsbOfFlags ? 1231 : 1237);
    result = prime * result + (secondMsbOfKnown ? 1231 : 1237);
    result = prime * result + (seventhMsbOfKnown ? 1231 : 1237);
    result = prime * result + (shortGiNsymDisambiguation ? 1231 : 1237);
    result = prime * result + (shortGiNsymDisambiguationKnown ? 1231 : 1237);
    result = prime * result + (shortGuardInterval ? 1231 : 1237);
    result = prime * result + (sixthMsbOfKnown ? 1231 : 1237);
    result = prime * result + (stbc ? 1231 : 1237);
    result = prime * result + (stbcKnown ? 1231 : 1237);
    result = prime * result + (thirdMsbOfKnown ? 1231 : 1237);
    result = prime * result + (txopPsNotAllowed ? 1231 : 1237);
    result = prime * result + (txopPsNotAllowedKnown ? 1231 : 1237);
    result = prime * result + unusedInCoding;
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    RadiotapDataVht other = (RadiotapDataVht) obj;
    if (!bandwidth.equals(other.bandwidth)) return false;
    if (bandwidthKnown != other.bandwidthKnown) return false;
    if (beamformed != other.beamformed) return false;
    if (beamformedKnown != other.beamformedKnown) return false;
    if (!Arrays.equals(fecTypes, other.fecTypes)) return false;
    if (fifthMsbOfKnown != other.fifthMsbOfKnown) return false;
    if (fourthMsbOfKnown != other.fourthMsbOfKnown) return false;
    if (groupId != other.groupId) return false;
    if (groupIdKnown != other.groupIdKnown) return false;
    if (guardIntervalKnown != other.guardIntervalKnown) return false;
    if (ldpcExtraOfdmSymbol != other.ldpcExtraOfdmSymbol) return false;
    if (ldpcExtraOfdmSymbolKnown != other.ldpcExtraOfdmSymbolKnown) return false;
    if (!Arrays.equals(mcses, other.mcses)) return false;
    if (msbOfFlags != other.msbOfFlags) return false;
    if (msbOfKnown != other.msbOfKnown) return false;
    if (!Arrays.equals(nsses, other.nsses)) return false;
    if (partialAid != other.partialAid) return false;
    if (partialAidKnown != other.partialAidKnown) return false;
    if (secondMsbOfFlags != other.secondMsbOfFlags) return false;
    if (secondMsbOfKnown != other.secondMsbOfKnown) return false;
    if (seventhMsbOfKnown != other.seventhMsbOfKnown) return false;
    if (shortGiNsymDisambiguation != other.shortGiNsymDisambiguation) return false;
    if (shortGiNsymDisambiguationKnown != other.shortGiNsymDisambiguationKnown) return false;
    if (shortGuardInterval != other.shortGuardInterval) return false;
    if (sixthMsbOfKnown != other.sixthMsbOfKnown) return false;
    if (stbc != other.stbc) return false;
    if (stbcKnown != other.stbcKnown) return false;
    if (thirdMsbOfKnown != other.thirdMsbOfKnown) return false;
    if (txopPsNotAllowed != other.txopPsNotAllowed) return false;
    if (txopPsNotAllowedKnown != other.txopPsNotAllowedKnown) return false;
    if (unusedInCoding != other.unusedInCoding) return false;
    return true;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static final class Builder {

    private boolean stbcKnown;
    private boolean txopPsNotAllowedKnown;
    private boolean guardIntervalKnown;
    private boolean shortGiNsymDisambiguationKnown;
    private boolean ldpcExtraOfdmSymbolKnown;
    private boolean beamformedKnown;
    private boolean bandwidthKnown;
    private boolean groupIdKnown;
    private boolean partialAidKnown;
    private boolean seventhMsbOfKnown;
    private boolean sixthMsbOfKnown;
    private boolean fifthMsbOfKnown;
    private boolean fourthMsbOfKnown;
    private boolean thirdMsbOfKnown;
    private boolean secondMsbOfKnown;
    private boolean msbOfKnown;
    private boolean stbc;
    private boolean txopPsNotAllowed;
    private boolean shortGuardInterval;
    private boolean shortGiNsymDisambiguation;
    private boolean ldpcExtraOfdmSymbol;
    private boolean beamformed;
    private boolean secondMsbOfFlags;
    private boolean msbOfFlags;
    private RadiotapVhtBandwidth bandwidth;
    private byte[] mcses;
    private byte[] nsses;
    private RadiotapFecType[] fecTypes;
    private byte unusedInCoding;
    private byte groupId;
    private short partialAid;

    /** */
    public Builder() {}

    private Builder(RadiotapDataVht obj) {
      this.stbcKnown = obj.stbcKnown;
      this.txopPsNotAllowedKnown = obj.txopPsNotAllowedKnown;
      this.guardIntervalKnown = obj.guardIntervalKnown;
      this.shortGiNsymDisambiguationKnown = obj.shortGiNsymDisambiguationKnown;
      this.ldpcExtraOfdmSymbolKnown = obj.ldpcExtraOfdmSymbolKnown;
      this.beamformedKnown = obj.beamformedKnown;
      this.bandwidthKnown = obj.bandwidthKnown;
      this.groupIdKnown = obj.groupIdKnown;
      this.partialAidKnown = obj.partialAidKnown;
      this.seventhMsbOfKnown = obj.seventhMsbOfKnown;
      this.sixthMsbOfKnown = obj.sixthMsbOfKnown;
      this.fifthMsbOfKnown = obj.fifthMsbOfKnown;
      this.fourthMsbOfKnown = obj.fourthMsbOfKnown;
      this.thirdMsbOfKnown = obj.thirdMsbOfKnown;
      this.secondMsbOfKnown = obj.secondMsbOfKnown;
      this.msbOfKnown = obj.msbOfKnown;
      this.stbc = obj.stbc;
      this.txopPsNotAllowed = obj.txopPsNotAllowed;
      this.shortGuardInterval = obj.shortGuardInterval;
      this.shortGiNsymDisambiguation = obj.shortGiNsymDisambiguation;
      this.ldpcExtraOfdmSymbol = obj.ldpcExtraOfdmSymbol;
      this.beamformed = obj.beamformed;
      this.secondMsbOfFlags = obj.secondMsbOfFlags;
      this.msbOfFlags = obj.msbOfFlags;
      this.bandwidth = obj.bandwidth;
      this.mcses = obj.mcses;
      this.nsses = obj.nsses;
      this.fecTypes = obj.fecTypes;
      this.unusedInCoding = obj.unusedInCoding;
      this.groupId = obj.groupId;
      this.partialAid = obj.partialAid;
    }

    /**
     * @param stbcKnown stbcKnown
     * @return this Builder object for method chaining.
     */
    public Builder stbcKnown(boolean stbcKnown) {
      this.stbcKnown = stbcKnown;
      return this;
    }

    /**
     * @param txopPsNotAllowedKnown txopPsNotAllowedKnown
     * @return this Builder object for method chaining.
     */
    public Builder txopPsNotAllowedKnown(boolean txopPsNotAllowedKnown) {
      this.txopPsNotAllowedKnown = txopPsNotAllowedKnown;
      return this;
    }

    /**
     * @param guardIntervalKnown guardIntervalKnown
     * @return this Builder object for method chaining.
     */
    public Builder guardIntervalKnown(boolean guardIntervalKnown) {
      this.guardIntervalKnown = guardIntervalKnown;
      return this;
    }

    /**
     * @param shortGiNsymDisambiguationKnown shortGiNsymDisambiguationKnown
     * @return this Builder object for method chaining.
     */
    public Builder shortGiNsymDisambiguationKnown(boolean shortGiNsymDisambiguationKnown) {
      this.shortGiNsymDisambiguationKnown = shortGiNsymDisambiguationKnown;
      return this;
    }

    /**
     * @param ldpcExtraOfdmSymbolKnown ldpcExtraOfdmSymbolKnown
     * @return this Builder object for method chaining.
     */
    public Builder ldpcExtraOfdmSymbolKnown(boolean ldpcExtraOfdmSymbolKnown) {
      this.ldpcExtraOfdmSymbolKnown = ldpcExtraOfdmSymbolKnown;
      return this;
    }

    /**
     * @param beamformedKnown beamformedKnown
     * @return this Builder object for method chaining.
     */
    public Builder beamformedKnown(boolean beamformedKnown) {
      this.beamformedKnown = beamformedKnown;
      return this;
    }

    /**
     * @param bandwidthKnown bandwidthKnown
     * @return this Builder object for method chaining.
     */
    public Builder bandwidthKnown(boolean bandwidthKnown) {
      this.bandwidthKnown = bandwidthKnown;
      return this;
    }

    /**
     * @param groupIdKnown groupIdKnown
     * @return this Builder object for method chaining.
     */
    public Builder groupIdKnown(boolean groupIdKnown) {
      this.groupIdKnown = groupIdKnown;
      return this;
    }

    /**
     * @param partialAidKnown partialAidKnown
     * @return this Builder object for method chaining.
     */
    public Builder partialAidKnown(boolean partialAidKnown) {
      this.partialAidKnown = partialAidKnown;
      return this;
    }

    /**
     * @param seventhMsbOfKnown seventhMsbOfKnown
     * @return this Builder object for method chaining.
     */
    public Builder seventhMsbOfKnown(boolean seventhMsbOfKnown) {
      this.seventhMsbOfKnown = seventhMsbOfKnown;
      return this;
    }

    /**
     * @param sixthMsbOfKnown sixthMsbOfKnown
     * @return this Builder object for method chaining.
     */
    public Builder sixthMsbOfKnown(boolean sixthMsbOfKnown) {
      this.sixthMsbOfKnown = sixthMsbOfKnown;
      return this;
    }

    /**
     * @param fifthMsbOfKnown fifthMsbOfKnown
     * @return this Builder object for method chaining.
     */
    public Builder fifthMsbOfKnown(boolean fifthMsbOfKnown) {
      this.fifthMsbOfKnown = fifthMsbOfKnown;
      return this;
    }

    /**
     * @param fourthMsbOfKnown fourthMsbOfKnown
     * @return this Builder object for method chaining.
     */
    public Builder fourthMsbOfKnown(boolean fourthMsbOfKnown) {
      this.fourthMsbOfKnown = fourthMsbOfKnown;
      return this;
    }

    /**
     * @param thirdMsbOfKnown thirdMsbOfKnown
     * @return this Builder object for method chaining.
     */
    public Builder thirdMsbOfKnown(boolean thirdMsbOfKnown) {
      this.thirdMsbOfKnown = thirdMsbOfKnown;
      return this;
    }

    /**
     * @param secondMsbOfKnown secondMsbOfKnown
     * @return this Builder object for method chaining.
     */
    public Builder secondMsbOfKnown(boolean secondMsbOfKnown) {
      this.secondMsbOfKnown = secondMsbOfKnown;
      return this;
    }

    /**
     * @param msbOfKnown msbOfKnown
     * @return this Builder object for method chaining.
     */
    public Builder msbOfKnown(boolean msbOfKnown) {
      this.msbOfKnown = msbOfKnown;
      return this;
    }

    /**
     * @param stbc stbc
     * @return this Builder object for method chaining.
     */
    public Builder stbc(boolean stbc) {
      this.stbc = stbc;
      return this;
    }

    /**
     * @param txopPsNotAllowed txopPsNotAllowed
     * @return this Builder object for method chaining.
     */
    public Builder txopPsNotAllowed(boolean txopPsNotAllowed) {
      this.txopPsNotAllowed = txopPsNotAllowed;
      return this;
    }

    /**
     * @param shortGuardInterval shortGuardInterval
     * @return this Builder object for method chaining.
     */
    public Builder shortGuardInterval(boolean shortGuardInterval) {
      this.shortGuardInterval = shortGuardInterval;
      return this;
    }

    /**
     * @param shortGiNsymDisambiguation shortGiNsymDisambiguation
     * @return this Builder object for method chaining.
     */
    public Builder shortGiNsymDisambiguation(boolean shortGiNsymDisambiguation) {
      this.shortGiNsymDisambiguation = shortGiNsymDisambiguation;
      return this;
    }

    /**
     * @param ldpcExtraOfdmSymbol ldpcExtraOfdmSymbol
     * @return this Builder object for method chaining.
     */
    public Builder ldpcExtraOfdmSymbol(boolean ldpcExtraOfdmSymbol) {
      this.ldpcExtraOfdmSymbol = ldpcExtraOfdmSymbol;
      return this;
    }

    /**
     * @param beamformed beamformed
     * @return this Builder object for method chaining.
     */
    public Builder beamformed(boolean beamformed) {
      this.beamformed = beamformed;
      return this;
    }

    /**
     * @param secondMsbOfFlags secondMsbOfFlags
     * @return this Builder object for method chaining.
     */
    public Builder secondMsbOfFlags(boolean secondMsbOfFlags) {
      this.secondMsbOfFlags = secondMsbOfFlags;
      return this;
    }

    /**
     * @param msbOfFlags msbOfFlags
     * @return this Builder object for method chaining.
     */
    public Builder msbOfFlags(boolean msbOfFlags) {
      this.msbOfFlags = msbOfFlags;
      return this;
    }

    /**
     * @param bandwidth bandwidth
     * @return this Builder object for method chaining.
     */
    public Builder bandwidth(RadiotapVhtBandwidth bandwidth) {
      this.bandwidth = bandwidth;
      return this;
    }

    /**
     * @param mcses mcses
     * @return this Builder object for method chaining.
     */
    public Builder mcses(byte[] mcses) {
      this.mcses = mcses;
      return this;
    }

    /**
     * @param nsses nsses
     * @return this Builder object for method chaining.
     */
    public Builder nsses(byte[] nsses) {
      this.nsses = nsses;
      return this;
    }

    /**
     * @param fecTypes fecTypes
     * @return this Builder object for method chaining.
     */
    public Builder fecTypes(RadiotapFecType[] fecTypes) {
      this.fecTypes = fecTypes;
      return this;
    }

    /**
     * @param unusedInCoding unusedInCoding
     * @return this Builder object for method chaining.
     */
    public Builder unusedInCoding(byte unusedInCoding) {
      this.unusedInCoding = unusedInCoding;
      return this;
    }

    /**
     * @param groupId groupId
     * @return this Builder object for method chaining.
     */
    public Builder groupId(byte groupId) {
      this.groupId = groupId;
      return this;
    }

    /**
     * @param partialAid partialAid
     * @return this Builder object for method chaining.
     */
    public Builder partialAid(short partialAid) {
      this.partialAid = partialAid;
      return this;
    }

    /** @return a new RadiotapVht object. */
    public RadiotapDataVht build() {
      return new RadiotapDataVht(this);
    }
  }
}
