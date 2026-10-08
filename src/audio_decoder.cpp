#include "audio_decoder.hpp"

#include <cstring>
#include <iostream>

constexpr std::string tag = "AudioDecoder";

namespace {
constexpr uint64_t AAC_LC_44100_2 = 1ULL << 22;
constexpr uint64_t AAC_LC_48000_2 = 1ULL << 23;
} // namespace

AudioDecoder::AudioDecoder(uint64_t format) : format_(format) {}

AudioDecoder::~AudioDecoder() {
  swr_free(&swr_);
  av_frame_free(&frame_);
  av_packet_free(&packet_);
  avcodec_free_context(&ctx_);
}

int AudioDecoder::create_context() {
  uint8_t asc[2];
  switch (format_) {
  case AAC_LC_44100_2:
    sampleRate_ = 44100;
    asc[0] = 0x12;
    asc[1] = 0x10;
    break;
  case AAC_LC_48000_2:
    sampleRate_ = 48000;
    asc[0] = 0x11;
    asc[1] = 0x90;
    break;
  default:
    std::cerr << "[AudioDecoder] Unsupported audioFormat: " << format_
              << std::endl;
    return -1;
  }

  codec_ = avcodec_find_decoder(AV_CODEC_ID_AAC);
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
      av_mallocz(sizeof(asc) + AV_INPUT_BUFFER_PADDING_SIZE));
  if (!ctx_->extradata) {
    return -1;
  }

  std::memcpy(ctx_->extradata, asc, sizeof(asc));
  ctx_->extradata_size = sizeof(asc);

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
