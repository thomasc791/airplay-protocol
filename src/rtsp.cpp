#include "rtsp.hpp"

#include "airplay_server.hpp"
#include "crypto.hpp"
#include "info_plist.hpp"
#include "plist.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <ostream>
#include <sys/socket.h>

RTSPParser::RTSPParser(int client_fd,
                       std::shared_ptr<CryptoHandler> crypto_handler)
    : client_fd(client_fd), contentLength(), CSeq(), msg{}, plistWriter(),
      header{}, crypto_handler_(crypto_handler) {
  std::cout << "Created RTSP parser, listening to client with ID: " << client_fd
            << std::endl;
}

RTSPParser::~RTSPParser() {}

int RTSPParser::set_client(int currentClient) {
  client_fd = currentClient;
  return 0;
}

int RTSPParser::set_msg(char *tcpMessage, int len) {
  // ESP_LOGI(TAG, "Set message with length: %d", len);
  msg = tcpMessage;
  messageLength = len;
  return 0;
}

int RTSPParser::parse_message() {
  msg[messageLength] = '\0';

  reset_state();

  get_content_length();
  get_cseq();
  get_title();
  get_body();

  if (strstr(msg, "GET /info")) {
    printf("GET /info\n");
    rtsp_get_info();
  } else if (strstr(msg, "OPTIONS *")) {
    printf("OPTIONS\n");
    rtsp_get_options();
  } else if (strstr(msg, "POST /command")) {
    printf("POST /command\n");
    rtsp_post_commands();
  } else if (strstr(msg, "POST /fp-setup")) {
    printf("POST /fp-setup\n");
    rtsp_post_fp_setup();
  } else if (strstr(msg, "POST /pair-setup")) {
    printf("POST /pair-setup\n");
    rtsp_post_pair_setup();
  } else if (strstr(msg, "POST /pair-setup")) {
    printf("POST /pair-setup\n");
    rtsp_post_pair_setup();
  } else if (strstr(msg, "POST /pair-verify")) {
    printf("POST /pair-verify\n");
    rtsp_post_pair_verify();
  }

  memset(msg, 0, MAX_MSG_BUFFER_SIZE);
  messageLength = 0;

  return 0;
}

int RTSPParser::reset_state() {
  CSeq = -1;
  contentLength = -1;

  return 0;
}

std::vector<uint8_t> RTSPParser::create_plist() {
  using V = PlistWriter::Value;

  auto plist = plistWriter.serialize(V::dict({
      {"deviceID", V::string(get_system_mac_address())},
      {"features", V::uint(0x1C340445F8A00)},
      {"flags", V::uint(0x04)},
      {"model", V::string("AudioAccessory6,1")},
      // {"pk", V::string(crypto_handler_->get_public_hex_string())},
      {"pi", V::string("bfbe459e-a7cf-4ef4-b4fd-e646d97c433f")},
      {"protocolVersion", V::string("1.1")},
      {"sourceVersion", V::string("366.0")},
      // {"audioFormats", V::array({V::dict({
      //                      {"type", V::uint(96)},
      //                      {"audioInputFormats", V::uint(0x01000000)},
      //                      {"audioOutputFormats", V::uint(0x01000000)},
      // })})},
  }));
  return plist;
}

int RTSPParser::rtsp_get_options() {
  int header_len = snprintf(header, sizeof(header),
                            "RTSP/1.0 200 OK\r\n"
                            "CSeq: %d\r\n"
                            "Public: OPTIONS, GET, POST, SETUP, ANNOUNCE, "
                            "RECORD, PAUSE, FLUSH, TEARDOWN\r\n"
                            "Server: AirTunes/366.0\r\n"
                            "\r\n",
                            CSeq);

  send(client_fd, header, header_len, 0);

  std::cout << "Send rtsp get options" << std::endl;
  return 0;
}

int RTSPParser::rtsp_post_commands() {

  int header_len = snprintf(header, sizeof(header),
                            "RTSP/1.0 200 OK\r\n"
                            "CSeq: %d\r\n"
                            "Public: OPTIONS, GET, POST, SETUP, ANNOUNCE, "
                            "RECORD, PAUSE, FLUSH, TEARDOWN\r\n"
                            "Server: AirTunes/366.0\r\n"
                            "\r\n",
                            CSeq);

  send(client_fd, header, header_len, 0);
  // int header_len = snprintf(header, sizeof(header),
  //                           "RTSP/1.0 200 OK\r\n"
  //                           "CSeq: %d\r\n"
  //                           "Content-Type:
  //                           application/x-apple-binary-plist\r\n"
  //                           "Content-Length: %d\r\n"
  //                           // "Server: AirTunes/366.0\r\n"
  //                           "\r\n",
  //                           CSeq, empty_bplist_len);

  // ssize_t err = send(client_fd, header, header_len, 0);
  // err = send(client_fd, empty_bplist, empty_bplist_len, 0);
  //
  // if (err <= 0)
  //   printf("Error not printing full message");
  //
  // for (size_t i = 0; i < empty_bplist_len; i++)
  //   printf("%02x", empty_bplist[i]);
  // printf("\n");

  return 0;
}

int RTSPParser::rtsp_post_fp_setup() {
  int header_len = snprintf(header, sizeof(header),
                            "RTSP/1.0 200 OK\r\n"
                            "CSeq: %d\r\n"
                            "Public: OPTIONS, GET, POST, SETUP, ANNOUNCE, "
                            "RECORD, PAUSE, FLUSH, TEARDOWN\r\n"
                            "Server: AirTunes/366.0\r\n"
                            "\r\n",
                            CSeq);

  send(client_fd, header, header_len, 0);
  return 0;
}

int RTSPParser::rtsp_get_info() {
  std::vector<uint8_t> plist = create_plist();

  int header_len = snprintf(header, sizeof(header),
                            "RTSP/1.0 200 OK\r\n"
                            "CSeq: %d\r\n"
                            "Server: AirTunes/366.0\r\n"
                            "Content-Type: application/x-apple-binary-plist\r\n"
                            "Content-Length: %d\r\n"
                            "\r\n",
                            CSeq, (int)plist.size());

  if (send(client_fd, header, header_len, 0) < 0)
    std::cerr << "[RTSPParser] Header not sent correctly!" << std::endl;
  if (send(client_fd, plist.data(), plist.size(), 0) < 0)
    std::cerr << "[RTSPParser] Header not sent correctly!" << std::endl;

  std::cout << header << std::endl;
  for (size_t i = 0; i < plist.size(); i++)
    printf("%02x ", plist[i]);
  std::cout << std::endl;

  return 0;
}

int RTSPParser::get_cseq() {
  const char *cseq = strstr(msg, "CSeq:");

  if (!cseq)
    return -1;

  sscanf(cseq, "CSeq: %d", &CSeq);
  return 0;
}

int RTSPParser::get_content_length() {
  const char *len = strstr(msg, "Content-Length:");

  if (!len)
    return -1;

  sscanf(len, "Content-Length: %d", &contentLength);

  return 0;
}

int RTSPParser::get_title() {
  const char *lineEnd = strstr(msg, "\r\n");
  if (!lineEnd)
    return -1;

  title = std::string((const char *)msg, lineEnd);
  return 0;
}

int RTSPParser::get_body() {
  body = strstr(msg, "\r\n\r\n");
  if (!body)
    return -1;
  body += 4;

  size_t headerLength = body - msg;
  int bodyRead = messageLength - headerLength;
  int remaining = contentLength - bodyRead;

  std::string msgHeader(msg, headerLength);
  std::cout << msgHeader << std::endl;

  if (remaining < 0)
    return -1;

  if (contentLength > MAX_MSG_BUFFER_SIZE) {
    bodyBuffer = (char *)malloc(contentLength);

    memcpy(bodyBuffer, body, bodyRead);
    int receivedSize =
        recv(client_fd, bodyBuffer + bodyRead, remaining, MSG_WAITALL);
    bodyBuffer[contentLength] = '\0';
    body = bodyBuffer;

    free(bodyBuffer);

    remaining -= receivedSize;
  } else if (remaining > 0) {
    int receivedSize = recv(client_fd, body + bodyRead, remaining, MSG_WAITALL);
    remaining -= receivedSize;
    bodyRead += receivedSize;
  }
  for (size_t i = 0; i < uint(bodyRead); i++)
    printf("%02x ", (unsigned char)body[i]);
  printf("\n");

  return 0;
}

int RTSPParser::rtsp_post_pair_setup() {
  // int header_len = snprintf(header, sizeof(header),
  //                           "RTSP/1.0 200 OK\r\n"
  //                           "CSeq: %d\r\n"
  //                           "Server: AirTunes/366.0\r\n"
  //                           "Content-Type:
  //                           application/x-apple-binary-plist\r\n"
  //                           "Content-Length: %d\r\n"
  //                           "\r\n",
  //                           CSeq, (int)plist.size());

  return 0;
};

int RTSPParser::rtsp_post_pair_verify() { return 0; };

std::unique_ptr<RTSPParser>
create_rtsp_parser(int client_fd,
                   std::shared_ptr<CryptoHandler> crypto_handler) {
  return std::make_unique<RTSPParser>(client_fd, crypto_handler);
}
