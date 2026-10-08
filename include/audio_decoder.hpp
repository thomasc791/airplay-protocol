#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

extern "C" {
#include <libavcodec/avcodec.h>
#include <libavutil/frame.h>
#include <libswresample/swresample.h>
}

class AudioDecoder {
public:
  AudioDecoder(uint64_t format);
  ~AudioDecoder();

  int create_context();
  int setup();
  int play_audio(const uint8_t *plaintext, size_t len,
                 std::vector<int16_t> &pcmOut);

  int sample_rate() const { return sampleRate_; }
  int channels() const { return channels_; }

private:
  uint64_t format_;
  int sampleRate_ = 0;
  int channels_ = 2;
  std::array<uint8_t, 2> extradata_;

  const AVCodec *codec_;
  AVCodecContext *ctx_;
  AVFrame *frame_ = nullptr;
  AVPacket *packet_ = nullptr;
  SwrContext *swr_ = nullptr;

  int init_resampler();
};

std::unique_ptr<AudioDecoder> create_audio_decoder(uint64_t format);
