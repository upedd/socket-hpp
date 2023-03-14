/*
** talker.cpp -- a datagram "client" demo
* Adapted from https://beej.us/guide/bgnet/examples/talker.c
*/
#include "../socket.hpp"
#include <iostream>

constexpr const char* SERVER_PORT = "4950";// the port users will be connecting to

std::expected<std::pair<Socket::AddressInformation, Socket>, std::exception>
make_listener(std::string_view hostname) {
  auto address_candidates =
    Socket::get_address_info(hostname, SERVER_PORT, Socket::Family::IPV6, Socket::Type::DGRAM);
  if (!address_candidates) {
    return std::unexpected(address_candidates.error());
  }

  for (auto& address_info : *address_candidates) {
    auto socket = Socket::create(
      address_info.get_family(), address_info.get_type(), address_info.get_protocol()
    );

    if (socket) {
      return std::make_pair(std::move(address_info), std::move(socket.value()));
    }
  }

  return std::unexpected(std::runtime_error("Couldn't create socket"));
}

int main(int argc, char* argv[]) {
  if (argc != 3) {
    std::cerr << "usage: talker hostname message\n";
    return -1;
  }

  auto address_and_socket = make_listener(argv[1]);

  if (!address_and_socket) {
    std::cerr << "talker: failed to create socket: " << address_and_socket.error().what()
              << std::endl;
    return -1;
  }

  auto& [address_info, socket] = *address_and_socket;

  std::string payload(argv[2]);
  auto bytes_sent = socket.send_to<std::string>(address_info.get_address(), payload, 0);

  if (!bytes_sent) {
    std::cout << "talker: failed to send data: " << bytes_sent.error().what() << std::endl;
    return -1;
  }

  std::cout << "talker: sent " << *bytes_sent << " bytes to " << argv[1] << '\n';
}