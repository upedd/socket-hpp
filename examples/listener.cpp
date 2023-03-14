/*
** listener.cpp -- a datagram sockets "server" demo
* Adapted from https://beej.us/guide/bgnet/examples/listener.c
*/
#include "../socket.hpp"
#include <iostream>

constexpr const char* PORT = "4950";// the port users will be connecting to

std::expected<Socket, std::runtime_error> make_listener() {
  auto address_candidates =
    Socket::get_address_info("", PORT, Socket::Family::IPV6, Socket::Type::DGRAM);
  if (!address_candidates) {
    return std::unexpected(address_candidates.error());
  }

  for (auto& address_info : *address_candidates) {
    auto socket = Socket::create(
      address_info.get_family(), address_info.get_type(), address_info.get_protocol()
    );

    if (socket) {
      auto expected =
        socket->set_option(SO_REUSEPORT, 1).and_then([&socket, &address_info]() -> auto {
          return socket->bind(address_info.get_address());
        });

      // all operations succeeded
      if (expected) return std::move(socket);
    }
  }

  return std::unexpected(std::runtime_error("Couldn't create socket"));
}

int main() {
  auto socket = make_listener();

  if (!socket) {
    std::cerr << "listener: failed to create socket: " << socket.error().what() << std::endl;
    return -1;
  }

  std::cout << "listener: waiting for data "
            << socket->get_address()->get_as_inet()->get_as_string() << std::endl;

  auto result = socket->receive_from<char>();

  if (!result) {
    std::cerr << "Failed to receive data: " << result.error().what() << std::endl;
    return -1;
  }

  auto& [address, buffer] = *result;

  std::cout << "listener: got packet from " << address.get_as_inet()->get_as_string() << std::endl;
  std::cout << "listener: packet is " << buffer.size() << " bytes long" << std::endl;
  std::cout << "listener: packet contains \"" << std::string(buffer.begin(), buffer.end()) << '\"'
            << std::endl;
}