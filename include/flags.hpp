#pragma once

#include <cstdint>
#include <memory>
#include <sstream>
#include <type_traits>

enum class FeatureBits : uint64_t {
  // https://emanuelecozzi.net/docs/airplay2/features/
  // https://openairplay.github.io/airplay-spec/features.html
  // https://nto.github.io/AirPlay.html
  Ft00Video = 1ULL << 0,
  Ft01Photo = 1ULL << 1,
  Ft02VideoFairPlay = 1ULL << 2,
  Ft03VideoVolumeCtrl = 1ULL << 3,
  Ft04VideoHTTPLiveStreaming = 1ULL << 4,
  Ft05Slideshow = 1ULL << 5,
  Ft06_Unknown = 1ULL << 6,
  // 07: seems to need NTP
  Ft07ScreenMirroring = 1ULL << 7,
  Ft08ScreenRotate = 1ULL << 8,
  // Ft09 is necessary for iPhones/Music: audio
  Ft09AirPlayAudio = 1ULL << 9,
  Ft10Unknown = 1ULL << 10,
  Ft11AudioRedundant = 1ULL << 11,
  // Feat12: iTunes4Win ends ANNOUNCE with rsaaeskey, does not attempt FPLY
  // auth.
  // also coerces frequent OPTIONS packets (keepalive) from iPhones.
  Ft12FPSAPv2p5_AES_GCM = 1ULL << 12,
  // 13-14 MFi stuff.
  Ft13MFiHardware = 1ULL << 13,
  // Music on iPhones needs this to stream audio
  Ft14MFiSoft_FairPlay = 1ULL << 14,
  // 15-17 not mandatory - faster pairing without
  Ft15AudioMetaCovers = 1ULL << 15,
  Ft16AudioMetaProgress = 1ULL << 16,
  Ft17AudioMetaTxtDAAP = 1ULL << 17,
  // macOS needs 18 to pair
  Ft18ReceiveAudioPCM = 1ULL << 18,
  // macOS needs 19,
  Ft19ReceiveAudioALAC = 1ULL << 19,
  // iOS needs 20,
  Ft20ReceiveAudioAAC_LC = 1ULL << 20,
  Ft21Unknown = 1ULL << 21,
  // Try Ft22 without Ft40 - ANNOUNCE + SDP
  Ft22AudioUnencrypted = 1ULL << 22,
  Ft23RSA_Auth = 1ULL << 23,
  Ft24Unknown = 1ULL << 24,
  // Pairing stalls with longer /auth-setup string w/26,
  // Ft25 seems to require ANNOUNCE
  Ft25iTunes4WEncryption = 1ULL << 25,
  // try Ft26 without Ft40. Ft26 = crypt audio? mutex w/Ft22?
  Ft26Audio_AES_Mfi = 1ULL << 26,
  // 27: connects and works OK
  Ft27LegacyPairing = 1ULL << 27,
  Ft28_Unknown = 1ULL << 28,
  Ft29plistMetaData = 1ULL << 29,
  Ft30UnifiedAdvertisingInfo = 1ULL << 30,
  // Bit 31 Reserved     =  # 1ULL << 31,
  Ft32CarPlay = 1ULL << 32,
  Ft33AirPlayVideoPlayQueue = 1ULL << 33,
  Ft34AirPlayFromCloud = 1ULL << 34,
  Ft35TLS_PSK = 1ULL << 35,
  Ft36_Unknown = 1ULL << 36,
  Ft37CarPlayControl = 1ULL << 37,
  // 38 seems to be implicit with other flags; works with or without 38.
  Ft38ControlChannelEncrypt = 1ULL << 38,
  Ft39_Unknown = 1ULL << 39,
  // 40 absence: requires ANNOUNCE method
  Ft40BufferedAudio = 1ULL << 40,
  Ft41_PTPClock = 1ULL << 41,
  Ft42ScreenMultiCodec = 1ULL << 42,
  // 43,
  Ft43SystemPairing = 1ULL << 43,
  Ft44APValeriaScreenSend = 1ULL << 44,
  // 45: macOS wont connect, iOS will, but dies on play.
  // 45 || 41; seem mutually exclusive.
  // 45 triggers stream type:96 (without ft41, PTP)
  Ft45_NTPClock = 1ULL << 45,
  Ft46HomeKitPairing = 1ULL << 46,
  // 47: For PTP
  Ft47PeerManagement = 1ULL << 47,
  Ft48TransientPairing = 1ULL << 48,
  Ft49AirPlayVideoV2 = 1ULL << 49,
  Ft50NowPlayingInfo = 1ULL << 50,
  Ft51MfiPairSetup = 1ULL << 51,
  Ft52PeersExtendedMessage = 1ULL << 52,
  Ft53_Unknown = 1ULL << 53,
  Ft54SupportsAPSync = 1ULL << 54,
  Ft55SupportsWoL = 1ULL << 55,
  Ft56SupportsWoL = 1ULL << 56,
  Ft57_Unknown = 1ULL << 57,
  Ft58HangdogRemote = 1ULL << 58,
  Ft59AudioStreamConnectionSetup = 1ULL << 59,
  Ft60AudioMediaDataControl = 1ULL << 60,
  Ft61RFC2198Redundant = 1ULL << 61,
  Ft62_Unknown = 1ULL << 62,
};

enum class StatusBits : uint64_t {
  StatusNone = 0,
  ProblemsExist = 1 << 0,
  // Probably a WAC (wireless accessory ctrl) thing:
  Not_yet_configured = 1 << 1,
  // Audio cable attached (legacy): all is well.
  AudioLink = 1 << 2,
  PINmode = 1 << 3,
  PINentry = 1 << 4,
  PINmatch = 1 << 5,
  SupportsAirPlayFromCloud = 1 << 6,
  // Need password to use
  PasswordNeeded = 1 << 7,
  StatusUnknown_08 = 1 << 8,
  // need PIN to pair - client will request PIN based auth
  PairingPIN_aka_OTP = 1 << 9,
  // Note: prevents adding to HomeKit when set.
  Enable_HK_Access_Control = 1 << 10,
  // Shows in logs as relayable. iOS connects to get currently playing track
  RemoteControlRelay = 1 << 11,
  SilentPrimary = 1 << 12,
  TightSyncIsGroupLeader = 1 << 13,
  TightSyncBuddyNotReachable = 1 << 14,
  IsAppleMusicSubscriber = 1 << 15,
  iCloudLibraryIsOn = 1 << 16,
  ReceiverSessionIsActive = 1 << 17,
  StatusUnknown_18 = 1 << 18,
  StatusUnknown_19 = 1 << 19,
};

template <typename T> class FlagsBase {
  static_assert(std::is_enum<T>::value, "Flags requires an enum type");

protected:
  uint64_t defaultFlags_;
  uint64_t mask_;

  FlagsBase(uint64_t mask = 0) : mask_(mask) {};

public:
  void set(T flag) { mask_ |= static_cast<uint64_t>(flag); }
  void clear(T flag) { mask_ &= ~static_cast<uint64_t>(flag); }
  void clearAll() { mask_ = 0; }
  bool has(T flag) { return (mask_ & static_cast<uint64_t>(flag)) != 0; }

  uint64_t get_raw() const { return mask_; }
  std::string get_hex() const {
    std::stringstream s;
    if ((mask_ >> 32) == 0) {
      s << "0x" << std::hex << mask_;
    } else {
      uint32_t lower = static_cast<uint32_t>(mask_ & 0xFFFFFFFF);
      uint32_t upper = static_cast<uint32_t>(mask_ >> 32);

      s << "0x" << std::hex << lower << ",0x" << upper;
    }

    return s.str();
  }
};

class FeatureFlags : public FlagsBase<FeatureBits> {
public:
  FeatureFlags(uint64_t mask = 0);

  /* Default:
   * FeatureBits::Ft48TransientPairing
   * FeatureBits::Ft47PeerManagement
   * FeatureBits::Ft46HomeKitPairing
   * FeatureBits::Ft41_PTPClock
   * FeatureBits::Ft40BufferedAudio
   * FeatureBits::Ft30UnifiedAdvertisingInfo
   * FeatureBits::Ft22AudioUnencrypted
   * FeatureBits::Ft20ReceiveAudioAAC_LC
   * FeatureBits::Ft19ReceiveAudioALAC
   * FeatureBits::Ft18ReceiveAudioPCM
   * FeatureBits::Ft17AudioMetaTxtDAAP
   * FeatureBits::Ft16AudioMetaProgress
   * // FeatureBits::Ft15AudioMetaCovers
   * FeatureBits::Ft14MFiSoft_FairPlay
   * FeatureBits::Ft09AirPlayAudio
   */
  void setDefault();
};

class StatusFlags : public FlagsBase<StatusBits> {
public:
  StatusFlags(uint64_t mask = 0);

  /* Default:
   * StatusBits::AudioLink
   */
  void setDefault();
};

std::shared_ptr<FeatureFlags> create_feature_flags();
std::shared_ptr<StatusFlags> create_status_flags();
