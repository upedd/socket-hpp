#include "../socket.hpp"
#include <iostream>

constexpr const char* SERVER_PORT = "3490";

std::expected<Socket, std::exception> make_client(std::string_view hostname) {
  auto address_candidates = Socket::get_address_info(
    hostname, SERVER_PORT, Socket::Family::UNSPECIFIED, Socket::Type::STREAM
  );
  if (!address_candidates) {
    return std::unexpected(address_candidates.error());
  }

  for (auto& address_info : *address_candidates) {
    auto socket = Socket::create(
      address_info.get_family(), address_info.get_type(), address_info.get_protocol()
    );

    if (socket) {
      auto connected = socket->connect(address_info.get_address());

      if (connected) return std::move(socket);
    }
  }

  return std::unexpected(std::runtime_error("Couldn't create socket"));
}


int main(int argc, char* argv[]) {
  if (argc != 2) {
    std::cout << "Usage: /client hostname" << std::endl;
    return -1;
  }

  auto socket = make_client(argv[1]);

  if (!socket) {
    std::cout << "client: couldn't create socket: " << socket.error().what() << std::endl;
    return -1;
  }

  // should better implement error handling
  std::cout << "client: connecting to "
            << socket->get_peer_address()->get_as_inet()->get_as_string() << "..." << std::endl;

  auto received = socket->receive<char>();

  if (!received) {
    std::cout << "client: failed to receive data" << std::endl;
    return -1;
  }

  std::cout << "client: received: \"" << std::string(received->begin(), received->end()) << '\"'
            << std::endl;
}
