#include "network/captive.hpp"
#include "socket.hpp"

#include <iostream>
#include <memory>
#include <sstream>
#include <unistd.h>

CaptivePortal::CaptivePortal() {
  auto callback = [this](int id) { this->handle_http_client(id); };
  httpServer_ = std::make_unique<TCPServer>(callback, "CaptivePortal", 80);
}

CaptivePortal::~CaptivePortal() { httpServer_->stop(); }

void CaptivePortal::start() { httpServer_->start(); }
void CaptivePortal::stop() { httpServer_->stop(); }

void CaptivePortal::handle_http_client(int client_fd) {
  char buffer[4096] = {0};
  ssize_t bytesRead = recv(client_fd, buffer, sizeof(buffer) - 1, 0);

  if (bytesRead <= 0) {
    close(client_fd);
    return;
  }

  std::string request(buffer, bytesRead);

  std::cout << request << std::endl;
  if (request.find("POST /configure") != std::string::npos) {
    size_t body_pos = request.find("\r\n\r\n");
    if (body_pos != std::string::npos) {
      std::string body = request.substr(body_pos + 4);

      std::string ssid, password;
      size_t ssid_pos = body.find("ssid=");
      size_t pass_pos = body.find("&password=");

      if (ssid_pos != std::string::npos && pass_pos != std::string::npos) {
        ssid = body.substr(ssid_pos + 5, pass_pos - (ssid_pos + 5));
        password = body.substr(pass_pos + 10);

        std::cout << "[CaptivePortal] Received Credentials!" << std::endl;
        std::cout << "SSID: " << ssid << " | PASS: " << password << std::endl;

        // Send success response
        std::string html = "<html><body><h3>Saved! Connecting to "
                           "network...</h3></body></html>";
        std::ostringstream response;
        response << "HTTP/1.1 200 OK\r\n"
                 << "Content-Type: text/html\r\n"
                 << "Content-Length: " << html.length() << "\r\n"
                 << "Connection: close\r\n\r\n"
                 << html;

        send(client_fd, response.str().c_str(), response.str().length(), 0);
        close(client_fd);

        // TODO: Here you will trigger your libnm code to connect
        // to the new SSID and shut down the AP.
        return;
      }
    }
  }

  std::ostringstream options;
  if (ssidOptions_.empty()) {
    options << "<option value=\"\">No networks found...</option>";
  } else {
    for (const auto &net : ssidOptions_) {
      options << "<option value=\"" << net << "\">" << net << "</option>";
    }
  }
  std::string html =
      "<html><head><meta name=\"viewport\" content=\"width=device-width, "
      "initial-scale=1\"></head>"
      "<body style=\"font-family: sans-serif; padding: 20px;\"><h2>AirPlay "
      "Receiver Setup</h2>"
      "<form action=\"/configure\" method=\"POST\">"
      "<label>Network Name (SSID):</label><br>"
      "<select name=\"ssid\" style=\"width:100%; padding: 10px; margin-bottom: "
      "15px;\">" +
      options.str() +
      "</select><br>"
      "<label>Password:</label><br>"
      "<input type=\"password\" name=\"password\" style=\"width:100%; padding: "
      "10px; margin-bottom: 15px;\"><br>"
      "<input type=\"submit\" value=\"Connect\" style=\"width:100%; padding: "
      "15px; background: #007aff; color: white; border: none; border-radius: "
      "5px;\">"
      "</form></body></html>";

  std::ostringstream response;
  response << "HTTP/1.1 200 OK\r\n"
           << "Content-Type: text/html\r\n"
           << "Content-Length: " << html.length() << "\r\n"
           << "Connection: close\r\n\r\n"
           << html;

  send(client_fd, response.str().c_str(), response.str().length(), 0);
  close(client_fd);
}
