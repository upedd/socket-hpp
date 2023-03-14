/*
** server.cpp -- a stream socket server demo
* Adapted from https://beej.us/guide/bgnet/examples/server.c
*/

#include <iostream>
#include <thread>

#include "../socket.hpp"

constexpr auto PORT = "3490";// the port users will be connecting to

std::expected<Socket, std::runtime_error> make_server() {
  auto address_candidates =
    Socket::get_address_info("", PORT, Socket::Family::IPV4, Socket::Type::STREAM);
  if (!address_candidates) {
    return std::unexpected(address_candidates.error());
  }

  for (auto& address_info : *address_candidates) {
    auto socket = Socket::create(
      address_info.get_family(), address_info.get_type(), address_info.get_protocol()
    );

    if (socket) {
      auto expected = socket->set_option(SO_REUSEADDR, 1)
                        .and_then([&socket, &address_info]() -> auto {
                          return socket->bind(address_info.get_address());
                        })
                        .and_then([&socket]() -> auto { return socket->listen(); });

      // all operations succeeded
      if (expected) return std::move(socket);
    }
  }

  return std::unexpected(std::runtime_error("Couldn't create socket"));
}

int main() {
  auto socket = make_server();

  if (!socket) {
    std::cout << "server: couldn't create socket for server: " << socket.error().what()
              << std::endl;
    return -1;
  }

  std::cout << "server: waiting for connections...\n";

  while (true) {
    auto result = socket->accept();
    if (!result) {
      std::cout << "server: failed to accept: " << result.error().what() << std::endl;
      break;
    }

    auto& [accepted_socket, their_addr] = *result;

    std::cout << "server: got connection from " << their_addr.get_as_inet()->get_as_string()
              << '\n';

    std::jthread t(
      [](const Socket& s) {
        auto result = s.send_all("Hello, world!");
        if (!result) {
          std::cout << "server: failed to send: " << result.error().what() << std::endl;
        }
      },
      std::ref(accepted_socket)
    );
  }
}
