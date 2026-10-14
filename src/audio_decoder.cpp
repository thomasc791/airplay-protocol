#include "audio_decoder.hpp"

#include <cstring>
#include <iostream>

constexpr std::string tag = "AudioDecoder";

constexpr uint64_t AAC_LC_44100_2 = 1ULL << 22;
constexpr uint64_t AAC_LC_48000_2 = 1ULL << 24;
constexpr uint64_t ALAC_44100_2 = 1ULL << 18;
constexpr uint64_t ALAC_48000_2 = 1ULL << 20;

AudioDecoder::AudioDecoder(uint64_t format) : format_(format) {}

AudioDecoder::~AudioDecoder() {
  swr_free(&swr_);
  av_frame_free(&frame_);
  av_packet_free(&packet_);
  avcodec_free_context(&ctx_);
}

int AudioDecoder::create_context() {
  AVCodecID codecId = AV_CODEC_ID_NONE;
  const uint8_t *extradata_ptr = nullptr;
  size_t extradata_size = 0;

  static const uint8_t alac_44100_16_extradata[] = {
      0x00, 0x00, 0x00, 0x24, 0x61, 0x6c, 0x61, 0x63, // 0-7: size (36), "alac"
      0x00, 0x00, 0x00, 0x00,                         // 8-11: version
      0x00, 0x00, 0x01, 0x60,                         // 12-15: spf (352)
      0x00, 0x10,             // 16: compat (0), 17: ss (16)
      0x28, 0x0a, 0x0e, 0x02, // 18-21: history, init, rice, channels
      0x00, 0xff,             // 22-23: max_run (255)
      0x00, 0x00, 0x00, 0x00, // 24-27: max_coded_frame_size (0)
      0x00, 0x00, 0x00, 0x00, // 28-31: average_bitrate (0)
      0x00, 0x00, 0xac, 0x44  // 32-35: sample_rate (44100)
  };
  ;

  static const uint8_t alac_48000_16_extradata[] = {
      0x00, 0x00, 0x00, 0x24, 0x61, 0x6c, 0x61, 0x63, // 0-7: size (36), "alac"
      0x00, 0x00, 0x00, 0x00,                         // 8-11: version
      0x00, 0x00, 0x01, 0x60,                         // 12-15: spf (352)
      0x00, 0x10,             // 16: compat (0), 17: ss (16)
      0x28, 0x0a, 0x0e, 0x02, // 18-21: history, init, rice, channels
      0x00, 0xff,             // 22-23: max_run (255)
      0x00, 0x00, 0x00, 0x00, // 24-27: max_coded_frame_size (0)
      0x00, 0x00, 0x00, 0x00, // 28-31: average_bitrate (0)
      0x00, 0x00, 0xbb, 0x80  // 32-35: sample_rate (44100)
  };

  static const uint8_t aac_44100_extradata[] = {0x12, 0x10};
  static const uint8_t aac_48000_extradata[] = {0x11, 0x90};

  switch (format_) {
  case AAC_LC_44100_2:
    sampleRate_ = 44100;
    codecId = AV_CODEC_ID_AAC;
    extradata_ptr = aac_44100_extradata;
    extradata_size = sizeof(aac_44100_extradata);
    break;
  case AAC_LC_48000_2:
    sampleRate_ = 48000;
    codecId = AV_CODEC_ID_AAC;
    extradata_ptr = aac_48000_extradata;
    extradata_size = sizeof(aac_48000_extradata);
    break;
  case ALAC_44100_2:
    sampleRate_ = 44100;
    codecId = AV_CODEC_ID_ALAC;
    extradata_ptr = alac_44100_16_extradata;
    extradata_size = sizeof(alac_44100_16_extradata);
    break;
  case ALAC_48000_2:
    sampleRate_ = 48000;
    codecId = AV_CODEC_ID_ALAC;
    extradata_ptr = alac_48000_16_extradata;
    extradata_size = sizeof(alac_48000_16_extradata);
    break;
  default:
    std::cerr << "[AudioDecoder] Unsupported audioFormat: " << format_
              << std::endl;
    return -1;
  }

  codec_ = avcodec_find_decoder(codecId);
  if (!codec_) {
    return -1;
  }

  ctx_ = avcodec_alloc_context3(codec_);
  if (!ctx_) {
    return -1;
  }

  ctx_->sample_rate = sampleRate_;
  av_channel_layout_default(&ctx_->ch_layout, channels_);

  ctx_->extradata = static_cast<uint8_t *>(
      av_mallocz(extradata_size + AV_INPUT_BUFFER_PADDING_SIZE));
  if (!ctx_->extradata) {
    return -1;
  }

  std::memcpy(ctx_->extradata, extradata_ptr, extradata_size);
  ctx_->extradata_size = extradata_size;

  int ret = avcodec_open2(ctx_, codec_, nullptr);
  if (ret < 0) {
    char err[AV_ERROR_MAX_STRING_SIZE];
    av_strerror(ret, err, sizeof(err));
    std::cerr << "[AudioDecoder] avcodec_open2 failed: " << err << std::endl;
    return -1;
  }

  packet_ = av_packet_alloc();
  frame_ = av_frame_alloc();
  if (!packet_ || !frame_) {
    return -1;
  }

  return 1;
}

int AudioDecoder::init_resampler() {
  int ret = swr_alloc_set_opts2(&swr_, &frame_->ch_layout, AV_SAMPLE_FMT_S16,
                                frame_->sample_rate, &frame_->ch_layout,
                                static_cast<AVSampleFormat>(frame_->format),
                                frame_->sample_rate, 0, nullptr);
  if (ret < 0)
    return ret;
  return swr_init(swr_);
}

int AudioDecoder::play_audio(const uint8_t *data, size_t len,
                             std::vector<int16_t> &pcmOut) {
  packet_->data = const_cast<uint8_t *>(data);
  packet_->size = static_cast<int>(len);

  int ret = avcodec_send_packet(ctx_, packet_);
  packet_->data = nullptr;
  packet_->size = 0;
  if (ret < 0)
    return ret;

  while ((ret = avcodec_receive_frame(ctx_, frame_)) >= 0) {
    if (!swr_ && init_resampler() < 0)
      return -1;

    const int ch = frame_->ch_layout.nb_channels;
    const int maxOut = swr_get_out_samples(swr_, frame_->nb_samples);
    const size_t old = pcmOut.size();
    pcmOut.resize(old + static_cast<size_t>(maxOut) * ch);

    uint8_t *outPlane = reinterpret_cast<uint8_t *>(pcmOut.data() + old);
    const int got =
        swr_convert(swr_, &outPlane, maxOut,
                    const_cast<const uint8_t **>(frame_->extended_data),
                    frame_->nb_samples);
    if (got < 0) {
      pcmOut.resize(old);
      return got;
    }
    pcmOut.resize(old + static_cast<size_t>(got) * ch);
    av_frame_unref(frame_);
  }

  return (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF) ? 0 : ret;
}

std::unique_ptr<AudioDecoder> create_audio_decoder(uint64_t format) {
  return std::make_unique<AudioDecoder>(format);
}
