#include "flags.hpp"

FeatureFlags::FeatureFlags(uint64_t mask) : FlagsBase(mask) {
  static constexpr uint64_t defaultFeatureMask =
      // static_cast<uint64_t>(FeatureBits::Ft48TransientPairing) |
      static_cast<uint64_t>(FeatureBits::Ft47PeerManagement) |
      static_cast<uint64_t>(FeatureBits::Ft46HomeKitPairing) |
      static_cast<uint64_t>(FeatureBits::Ft41_PTPClock) |
      static_cast<uint64_t>(FeatureBits::Ft40BufferedAudio) |
      static_cast<uint64_t>(FeatureBits::Ft30UnifiedAdvertisingInfo) |
      static_cast<uint64_t>(FeatureBits::Ft22AudioUnencrypted) |
      static_cast<uint64_t>(FeatureBits::Ft20ReceiveAudioAAC_LC) |
      static_cast<uint64_t>(FeatureBits::Ft19ReceiveAudioALAC) |
      static_cast<uint64_t>(FeatureBits::Ft18ReceiveAudioPCM) |
      static_cast<uint64_t>(FeatureBits::Ft17AudioMetaTxtDAAP) |
      static_cast<uint64_t>(FeatureBits::Ft16AudioMetaProgress) |
      // static_cast<uint64_t>(FeatureBits::Ft15AudioMetaCovers) |
      // static_cast<uint64_t>(FeatureBits::Ft14MFiSoft_FairPlay) |
      static_cast<uint64_t>(FeatureBits::Ft09AirPlayAudio);

  defaultFlags_ = defaultFeatureMask;

  setDefault();
}

void FeatureFlags::setDefault() { mask_ = defaultFlags_; }

StatusFlags::StatusFlags(uint64_t mask) : FlagsBase(mask) {
  defaultFlags_ = static_cast<uint64_t>(StatusBits::AudioLink);

  setDefault();
}

void StatusFlags::setDefault() { mask_ = defaultFlags_; }

std::shared_ptr<FeatureFlags> create_feature_flags() {
  return std::make_shared<FeatureFlags>(0);
}

std::shared_ptr<StatusFlags> create_status_flags() {
  return std::make_shared<StatusFlags>(0);
}
