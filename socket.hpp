#ifndef BROWSER_SOCKET_H
#define BROWSER_SOCKET_H


#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

// rename macros
#define SHUT_RD SD_RECEIVE
#define SHUT_WR SD_SEND
#define SHUT_RDWR SD_BOTH

// Windows auto init
#if !defined(SOCKETHPP_MANUAL_WINDOWS_INIT)
#include <mutex>

std::once_flag flag;
bool socket_hpp_win_init_dummy = [] {
  std::call_once(flag, [] {
    WSAData data;
    // TODO: handle error
    WSAStartup(MAKEWORD(2, 2), &data);
    std::atexit([] { WSACleanup(); });
  });
  return true;
}();

#endif
#else

#include <arpa/inet.h>
#include <cerrno>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int errno;

#endif

#ifdef USE_EXPECTED_POLYFILL
#include "include/expected.hpp"

// workaround!
namespace std {
using namespace tl;// NOLINT(cert-dcl58-cpp)
}
#else

#include <expected>

#endif

#include <cstring>
#include <memory>
#include <ranges>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

// #TODO support for msghdr?

// type aliasing functions to avoid conflicts with member functions
static constexpr auto platform_send = send;
static constexpr auto platform_socket = socket;
static constexpr auto platform_connect = connect;
static constexpr auto platform_recv = recv;
#if defined(_WIN32)
static constexpr auto platform_close = closesocket;
#else
static constexpr auto platform_close = close;
#endif
static constexpr auto platform_getaddrinfo = getaddrinfo;
static constexpr auto platform_bind = bind;
static constexpr auto platform_listen = listen;
static constexpr auto platform_accept = accept;
static constexpr auto platform_setsockopt = setsockopt;
static constexpr auto platform_getsockopt = getsockopt;
static constexpr auto platform_getnameinfo = getnameinfo;
static constexpr auto platform_getpeername = getpeername;
static constexpr auto platform_ntop = inet_ntop;
static constexpr auto platform_pton = inet_pton;
static constexpr auto platform_recvfrom = recvfrom;
static constexpr auto platform_sendto = sendto;
static constexpr auto platform_getsockname = getsockname;
static constexpr auto platform_shutdown = shutdown;

class Socket {
public:
  class Address;

  class InternetAddress;

  class InternetAddressV4;

  class InternetAddressV6;

  class Error : public std::system_error {
  public:
    using std::system_error::system_error;
  };

  class Address {
  public:
    Address() : storage_(new sockaddr_storage), is_owner_(true){};

    explicit Address(sockaddr_storage* storage, bool transfer_ownership = false)
      : storage_(storage), is_owner_(transfer_ownership){};

    explicit Address(sockaddr* storage, bool transfer_ownership = false)
      : Address(reinterpret_cast<sockaddr_storage*>(storage), transfer_ownership){};

    Address(const Address& address) = delete;

    Address& operator=(const Address&) = delete;

    Address(Address&& address) noexcept
      : storage_(std::exchange(address.storage_, nullptr)),
        is_owner_(std::exchange(address.is_owner_, false)) {}

    Address& operator=(Address&& other) noexcept {
      if (this != &other) {
        if (is_owner_) {
          delete storage_;
        }
        storage_ = std::exchange(other.storage_, nullptr);
        is_owner_ = std::exchange(other.is_owner_, false);
      }
      return *this;
    };

    [[nodiscard]] sockaddr* get_ptr() const {
      return reinterpret_cast<sockaddr*>(storage_);
    }

    [[nodiscard]] inline constexpr static size_t get_size() noexcept {
      return sizeof(sockaddr_storage);
    }

    [[nodiscard]] uint8_t get_family() const {
      return storage_->ss_family;
    }

    [[nodiscard]] std::unique_ptr<InternetAddress> get_as_inet() const {
      if (get_family() == AF_INET) {
        return get_as_v4();
      } else if (get_family() == AF_INET6) {
        return get_as_v6();
      }
      return {};
    };

    [[nodiscard]] std::unique_ptr<InternetAddressV4> get_as_v4() const {
      if (get_family() == AF_INET) {
        return std::make_unique<InternetAddressV4>(storage_);
      }
      return {};
    };

    [[nodiscard]] std::unique_ptr<InternetAddressV6> get_as_v6() const {
      if (get_family() == AF_INET6) {
        return std::make_unique<InternetAddressV6>(storage_);
      }
      return {};
    };

    ~Address() {
      if (is_owner_) {
        delete storage_;
      }
    }

  private:
    sockaddr_storage* storage_;
    bool is_owner_;
  };

  class InternetAddress : public Address {
  public:
    using Address::Address;

    InternetAddress(InternetAddress&& address) noexcept : Address(std::forward<Address>(address)){};

    InternetAddress& operator=(InternetAddress&& other) noexcept = default;

    InternetAddress(InternetAddress&) = delete;
    InternetAddress& operator=(InternetAddress&) = delete;

    virtual std::string get_as_string() = 0;

    virtual void set_port(uint16_t port) = 0;

    [[nodiscard]] virtual uint16_t get_port() const = 0;

    virtual ~InternetAddress() = default;
  };

  class InternetAddressV4 : public InternetAddress {
  public:
    using InternetAddress::InternetAddress;

    InternetAddressV4(InternetAddressV4&& address) noexcept
      : InternetAddress(std::forward<InternetAddress>(address)){};
    InternetAddressV4& operator=(InternetAddressV4&& other) noexcept = default;

    InternetAddressV4(InternetAddressV4&) = delete;
    InternetAddressV4& operator=(InternetAddressV4&) = delete;

    ~InternetAddressV4() override = default;

    static std::optional<InternetAddressV4>
    parse(std::string_view input, uint16_t port = 0) noexcept {
      InternetAddressV4 address{};
      sockaddr_in* inet_ptr = address.get_inet_ptr();
      inet_ptr->sin_port = port;
      const int status = platform_pton(AF_INET, input.data(), &inet_ptr->sin_addr);
      if (status > 0) {
        return address;
      }
      return {};
    }

    std::string get_as_string() override {
      std::array<char, INET_ADDRSTRLEN> buffer{};
      platform_ntop(AF_INET, &get_inet_ptr()->sin_addr, buffer.data(), INET_ADDRSTRLEN);
      return { buffer.data() };
    }

    [[nodiscard]] sockaddr_in* get_inet_ptr() const {
      return reinterpret_cast<sockaddr_in*>(get_ptr());
    }

    void set_port(uint16_t port) noexcept override {
      get_inet_ptr()->sin_port = port;
    }

    [[nodiscard]] uint16_t get_port() const noexcept override {
      return get_inet_ptr()->sin_port;
    }
  };

  class InternetAddressV6 : public InternetAddress {
  public:
    using InternetAddress::InternetAddress;

    InternetAddressV6(InternetAddressV6&& address) noexcept
      : InternetAddress(std::forward<InternetAddress>(address)){};
    InternetAddressV6& operator=(InternetAddressV6&& other) noexcept = default;

    InternetAddressV6(InternetAddressV6&) = delete;
    InternetAddressV6& operator=(InternetAddressV6&) = delete;

    ~InternetAddressV6() override = default;

    static std::optional<InternetAddressV6>
    parse(std::string_view input, uint16_t port = 0) noexcept {
      InternetAddressV6 address{};
      sockaddr_in6* inet_ptr = address.get_inet6_ptr();
      inet_ptr->sin6_port = port;
      const int status = platform_pton(AF_INET6, input.data(), &inet_ptr->sin6_addr);
      if (status > 0) {
        return address;
      }
      return {};
    }

    std::string get_as_string() override {
      std::array<char, INET6_ADDRSTRLEN> buffer{};
      platform_ntop(AF_INET6, &get_inet6_ptr()->sin6_addr, buffer.data(), INET6_ADDRSTRLEN);
      return { buffer.data() };
    }

    [[nodiscard]] sockaddr_in6* get_inet6_ptr() const noexcept {
      return reinterpret_cast<sockaddr_in6*>(get_ptr());
    }

    void set_port(uint16_t port) noexcept override {
      get_inet6_ptr()->sin6_port = port;
    }

    [[nodiscard]] uint16_t get_port() const noexcept override {
      return get_inet6_ptr()->sin6_port;
    }
  };

  enum class Family {
    UNSPECIFIED = AF_UNSPEC,
    IPV4 = AF_INET,
    IPV6 = AF_INET6,
  };

  enum class Type { STREAM = SOCK_STREAM, DGRAM = SOCK_DGRAM };

  enum class Protocol { AUTO = 0, TCP = IPPROTO_TCP, UDP = IPPROTO_UDP };

  /**
   * Wrapper around addrinfo pointer.
   * Stores information about only one address info, and not linked list of
   * addresses like addrinfo struct. Is responsible for deleting pointer to that
   * address.
   */
  class AddressInformation {
  public:
    explicit AddressInformation(addrinfo* address_info) noexcept
      : address_info_(address_info), address_(address_info->ai_addr){};

    // disable copying
    AddressInformation(const AddressInformation&) = delete;

    AddressInformation& operator=(const AddressInformation&) = delete;

    // move constructor
    AddressInformation(AddressInformation&& addressInformation) noexcept
      : address_info_(std::exchange(addressInformation.address_info_, nullptr)),
        address_(std::move(addressInformation.address_)) {}


    AddressInformation& operator=(AddressInformation&& other) noexcept {
      if (this != &other) {
        if (address_info_ != nullptr) {
          address_info_->ai_next = nullptr;
          freeaddrinfo(address_info_);
        }

        address_info_ = std::exchange(other.address_info_, nullptr);
        address_ = std::move(other.address_);
      }
      return *this;
    }

    ~AddressInformation() {
      if (address_info_ != nullptr) {
        // we want to delete only our object and not entire linked list of
        // objects.
        address_info_->ai_next = nullptr;
        freeaddrinfo(address_info_);
      }
    }

    [[nodiscard]] inline Socket::Family get_family() const noexcept {
      return Socket::Family{ address_info_->ai_family };
    }

    [[nodiscard]] inline Socket::Type get_type() const noexcept {
      return Socket::Type{ address_info_->ai_socktype };
    }

    [[nodiscard]] inline Socket::Protocol get_protocol() const noexcept {
      return Socket::Protocol{ address_info_->ai_protocol };
    }

    [[nodiscard]] inline std::string_view get_canonical_name() const noexcept {
      return address_info_->ai_canonname;
    }

    [[nodiscard]] inline const Address& get_address() const noexcept {
      return address_;
    }

  private:
    addrinfo* address_info_;
    Address address_;
  };

  // #TODO check other implementations
  static constexpr int DEFAULT_MAX_BACKLOG = 10;

  Socket(int file_descriptor, Family family, Type type, Protocol protocol = Protocol::AUTO) noexcept
    : fd_(file_descriptor), family_(family), type_(type), protocol_(protocol){};

  [[nodiscard]] static inline std::expected<Socket, Socket::Error>
  create(Family family, Type type, Protocol protocol) noexcept;

  // Disable copying
  Socket(const Socket& socket) = delete;

  Socket& operator=(const Socket&) = delete;

  // Enable moving
  Socket(Socket&& socket) noexcept
    : fd_(std::exchange(socket.fd_, -1)), type_(socket.type_), family_(socket.family_),
      protocol_(socket.protocol_){};

  Socket& operator=(Socket&& other) noexcept {
    if (this != &other) {
      close();

      fd_ = std::exchange(other.fd_, -1);
      type_ = other.type_;
      family_ = other.family_;
      protocol_ = other.protocol_;
    }
    return *this;
  }
  ~Socket();

  [[nodiscard]] inline int get_fd() const noexcept;

  [[nodiscard]] inline std::expected<void, Error> bind(const Socket::Address& address
  ) const noexcept;

  [[nodiscard]] inline std::expected<void, Error> connect(const Socket::Address& address
  ) const noexcept;

  // default max backlog?
  [[nodiscard]] inline std::expected<void, Socket::Error>
  listen(int max_backlog = DEFAULT_MAX_BACKLOG) const noexcept;

  [[nodiscard]] inline std::expected<std::pair<Socket, Socket::Address>, Error>
  accept() const noexcept;

  template<typename T>
    requires std::ranges::contiguous_range<T> && std::ranges::sized_range<T>
  [[nodiscard]] inline std::expected<int, Error> receive(T& buffer, int flags = 0) const noexcept;

  template<typename T>
    requires std::ranges::contiguous_range<T> && std::ranges::sized_range<T>
  [[nodiscard]] inline std::expected<int, Error> send(T& buffer, int flags = 0) const noexcept;

  template<typename T>
    requires std::ranges::contiguous_range<T> && std::ranges::sized_range<T>
  [[nodiscard]] inline std::expected<std::pair<int, Socket::Address>, Error>
  receive_from(T& buffer, int flags = 0) const noexcept;

  template<typename T>
    requires std::ranges::contiguous_range<T> && std::ranges::sized_range<T>
  [[nodiscard]] inline std::expected<int, Error>
  send_to(const Socket::Address& address, T& buffer, int flags = 0) const noexcept;

  template<typename T>
    requires std::ranges::contiguous_range<T> && std::ranges::sized_range<T>
  [[nodiscard]] inline std::expected<int, Error> receive_to_fill(T& buffer, int flags = 0) const noexcept;

  template<typename T>
    requires std::ranges::contiguous_range<T> && std::ranges::sized_range<T>
  [[nodiscard]] inline std::expected<int, Error> receive_to_end(
    T& buffer, size_t chunk_size, int flags = 0
  ) const noexcept;

  template<typename T>
    requires std::ranges::contiguous_range<T> && std::ranges::sized_range<T>
  [[nodiscard]] inline std::expected<int, Error> send_all(
    T& buffer, int flags = 0
  ) const noexcept;

  enum class ShutdownType { READ = SHUT_RD, WRITE = SHUT_WR, ALL = SHUT_RDWR };

  [[nodiscard]] inline std::expected<void, Socket::Error> shutdown(ShutdownType type
  ) const noexcept;

  [[nodiscard]] inline std::expected<void, Socket::Error> close() noexcept;

  template<typename T>
  [[nodiscard]] inline std::expected<void, Socket::Error> set_option(int option, T value) noexcept;

  template<typename T>
  [[nodiscard]] inline std::expected<T, Socket::Error> get_option(int option) const noexcept;

  [[nodiscard]] inline std::expected<Socket::Address, Socket::Error>
  get_peer_address() const noexcept;

  [[nodiscard]] inline std::expected<Socket::Address, Socket::Error> get_address() const noexcept;


  // #TODO codes
  class AddressInfoError : public std::runtime_error {
  public:
    AddressInfoError(auto message, int code) : std::runtime_error(message), code_(code) {}

    [[nodiscard]] inline int get_code() const noexcept {
      return code_;
    }

  private:
    int code_;
  };

  [[nodiscard]] static inline std::
    expected<std::vector<AddressInformation>, Socket::AddressInfoError>
    get_address_info(
      std::string_view address,
      std::string_view port,
      Family family,
      Type type,
      Protocol protocol = Socket::Protocol::AUTO,
      int flags = 0
    ) noexcept;

  class NameInfo {
  public:
    NameInfo(std::string host, std::string service)
      : host_(std::move(host)), service_(std::move(service)) {}

    [[nodiscard]] const std::string& get_host() const noexcept {
      return host_;
    }

    [[nodiscard]] const std::string& get_service() const noexcept {
      return service_;
    }

  private:
    std::string host_;
    std::string service_;
  };


  static constexpr int HOST_STRING_SIZE = 1024;
  static constexpr int SERVICE_STRING_SIZE = 20;

  static inline std::expected<Socket::NameInfo, Socket::Error>
  get_name_info(const Socket::Address& address, int flags = 0) noexcept;

private:
  int fd_;
  Family family_;
  Type type_;
  Protocol protocol_;

  static inline std::unexpected<Socket::Error> make_unexpected_() {
#if defined(_WIN32)
    return std::unexpected(Socket::Error(WSAGetLastError(), std::system_category()));
#else
    return std::unexpected(Socket::Error(errno, std::system_category()));
#endif
  }

  template<typename T>
  static inline std::expected<T, Socket::Error> make_response_(int status, T value) noexcept {
    if (status < 0) {
      return make_unexpected_();
    }
    return { std::forward<T>(value) };
  }


  static inline std::expected<void, Socket::Error> make_response_(int status) {
    if (status < 0) {
      return make_unexpected_();
    }
    return {};
  }
};

inline Socket::~Socket() {
  close();
}

inline std::expected<void, Socket::Error> Socket::bind(const Socket::Address& address
) const noexcept {
  sockaddr* addr = address.get_ptr();
  const int status = platform_bind(fd_, addr, sizeof(sockaddr));
  return make_response_(status);
}

inline std::expected<void, Socket::Error> Socket::connect(const Socket::Address& address
) const noexcept {
  sockaddr* addr = address.get_ptr();
  const int status = platform_connect(fd_, addr, sizeof(sockaddr));
  return make_response_(status);
}

inline std::expected<void, Socket::Error> Socket::listen(int max_backlog) const noexcept {
  const int status = platform_listen(fd_, max_backlog);
  return make_response_(status);
}

inline std::expected<std::pair<Socket, Socket::Address>, Socket::Error>
Socket::accept() const noexcept {
  Socket::Address address;
  sockaddr* addr = address.get_ptr();
  socklen_t storage_size = Socket::Address::get_size();
  const int fd = platform_accept(fd_, addr, &storage_size);

  if (fd == -1) {
    return make_unexpected_();
  }

  Socket accepted_socket(fd, family_, type_, protocol_);
  return { { std::move(accepted_socket), std::move(address) } };
}

inline std::expected<void, Socket::Error> Socket::close() noexcept {
  if (fd_ != -1) {
    const int status = platform_close(fd_);
    fd_ = -1;
    return make_response_(status);
  }
  return {};
}

template<typename T>
inline std::expected<void, Socket::Error> Socket::set_option(int option, T value) noexcept {
#if defined(_WIN32)
  // we need to cast value into char* for windows
  int status = platform_setsockopt(fd_, SOL_SOCKET, option, (char*) &value, sizeof(T));
#else
  int status = platform_setsockopt(fd_, SOL_SOCKET, option, &value, sizeof(T));
#endif
  return make_response_(status);
}

inline std::expected<std::vector<Socket::AddressInformation>, Socket::AddressInfoError>
Socket::get_address_info(
  std::string_view address,
  std::string_view port,
  Family family,
  Type type,
  Protocol protocol,
  int flags
) noexcept {
  const addrinfo hints{
    flags,// flags
    static_cast<int>(family),// family
    static_cast<int>(type),// type
    static_cast<int>(protocol),// protocol, using 0 to automatically get protocol for type
    0,// address length
    nullptr,// canon name
    nullptr,// address
    nullptr// next
  };
  addrinfo* response{};

  const int status = platform_getaddrinfo(address.data(), port.data(), &hints, &response);

  if (status != 0) {
    return std::unexpected(Socket::AddressInfoError(gai_strerror(status), status));
  }

  std::vector<AddressInformation> addresses;

  // iterate over linked list of address and convert them into our platform
  // independent type
  for (addrinfo* current = response; current != nullptr; current = current->ai_next) {
    addresses.emplace_back(current);
  }

  return addresses;
}


inline std::expected<Socket::NameInfo, Socket::Error>
Socket::get_name_info(const Socket::Address& address, int flags) noexcept {
  std::array<char, HOST_STRING_SIZE> host{};
  std::array<char, SERVICE_STRING_SIZE> service{};
  sockaddr* addr = address.get_ptr();

  const int status = platform_getnameinfo(
    addr, sizeof(*addr), host.data(), host.size(), service.data(), service.size(), flags
  );
  return make_response_<Socket::NameInfo>(status, { host.data(), service.data() });
}

inline std::expected<Socket::Address, Socket::Error> Socket::get_peer_address() const noexcept {
  Socket::Address address{};
  socklen_t storage_size = Socket::Address::get_size();
  const int status = platform_getpeername(fd_, address.get_ptr(), &storage_size);
  return make_response_(status, std::move(address));
}

inline std::expected<Socket::Address, Socket::Error> Socket::get_address() const noexcept {
  Socket::Address address{};
  socklen_t storage_size = Socket::Address::get_size();
  const int status = platform_getsockname(fd_, address.get_ptr(), &storage_size);
  return make_response_(status, std::move(address));
}

inline std::expected<void, Socket::Error> Socket::shutdown(ShutdownType type) const noexcept {
  int const status = platform_shutdown(fd_, static_cast<int>(type));
  return make_response_(status);
}

inline int Socket::get_fd() const noexcept {
  return fd_;
}

inline std::expected<Socket, Socket::Error>
Socket::create(Socket::Family family, Socket::Type type, Socket::Protocol protocol) noexcept {
  const int fd =
    platform_socket(static_cast<int>(family), static_cast<int>(type), static_cast<int>(protocol));
  if (fd == -1) {
    return make_unexpected_();
  }
  return Socket{ fd, family, type, protocol };
}
template<typename T>
  requires std::ranges::contiguous_range<T> && std::ranges::sized_range<T>
inline std::expected<int, Socket::Error> Socket::send_all(T& buffer, int flags) const noexcept {
  size_t elements_to_sent = std::ranges::size(buffer) * sizeof(std::ranges::range_value_t<T>);
  size_t elements_sent = 0;

  do {
      auto subrange = std::ranges::subrange(std::ranges::begin(buffer) + elements_sent, std::ranges::end(buffer));
      auto sent = send(subrange, flags);
      if (!sent) {
        return std::unexpected(sent.error());
      }

      elements_sent += *sent;
  } while (elements_sent > elements_to_sent);

  return elements_sent;
}

template<typename T>
  requires std::ranges::contiguous_range<T> && std::ranges::sized_range<T>
inline std::expected<int, Socket::Error> Socket::receive_to_end(T& buffer, size_t chunk_size, int flags)
  const noexcept {
  int total_received_elements = 0;
  int last_received_elements;

  do {
    // resize buffer
    if (buffer.size() == buffer.capacity()) {
      buffer.resize(buffer.capacity() + chunk_size);
    } else {
      buffer.resize(buffer.capacity());
    }
    auto subrange = std::ranges::subrange(buffer.begin() + total_received_elements, buffer.end());
    auto received = receive(subrange, flags);

    if (!received) {
      return std::unexpected(received.error());
    }

    last_received_elements = *received;
    total_received_elements += last_received_elements;
  } while (last_received_elements != 0);

  // shrink buffer to fit
  buffer.resize(total_received_elements - 1);

  return total_received_elements;
}

template<typename T>
  requires std::ranges::contiguous_range<T> && std::ranges::sized_range<T>
inline std::expected<int, Socket::Error> Socket::receive_to_fill(T& buffer, int flags) const noexcept {
  int total_received_elements = 0;
  int last_received_elements = 0;

  do {
    auto subrange = std::ranges::subrange(buffer.begin() + total_received_elements, buffer.end());
    auto received = receive(subrange, flags);

    if (!received) {
      return std::unexpected(received.error());
    }

    last_received_elements = *received;
    total_received_elements += last_received_elements;
  } while (last_received_elements != 0 && total_received_elements < std::ranges::size(buffer));

  return total_received_elements;
}
template<typename T>
  requires std::ranges::contiguous_range<T> && std::ranges::sized_range<T>
inline std::expected<int, Socket::Error>
Socket::send_to(const Socket::Address& address, T& buffer, int flags) const noexcept {
  constexpr size_t element_size = sizeof(std::ranges::range_value_t<T>);
  size_t buffer_size_in_bytes = std::ranges::size(buffer) * element_size;
  int bytes_sent = platform_sendto(
    fd_,
    std::ranges::data(buffer),
    buffer_size_in_bytes,
    flags,
    address.get_ptr(),
    sizeof(sockaddr_in6)
  );
  // return number of elements sent
  return make_response_(bytes_sent, bytes_sent / element_size);
}


template<typename T>
  requires std::ranges::contiguous_range<T> && std::ranges::sized_range<T>
inline std::expected<std::pair<int, Socket::Address>, Socket::Error>
Socket::receive_from(T& buffer, int flags) const noexcept {
  constexpr size_t element_size = sizeof(std::ranges::range_value_t<T>);
  size_t buffer_size_in_bytes = std::ranges::size(buffer) * element_size;

  Socket::Address address{};
  socklen_t size = Socket::Address::get_size();

  int bytes_received = platform_recvfrom(
    fd_, std::ranges::data(buffer), buffer_size_in_bytes, flags, address.get_ptr(), &size
  );

  int num_of_elements_received = bytes_received / element_size;

  // return num of elements we received
  return make_response_(
    bytes_received, std::make_pair(num_of_elements_received, std::move(address))
  );
}

template<typename T>
  requires std::ranges::contiguous_range<T> && std::ranges::sized_range<T>
inline std::expected<int, Socket::Error> Socket::send(T& buffer, int flags) const noexcept {
  constexpr size_t element_size = sizeof(std::ranges::range_value_t<T>);
  size_t buffer_size_in_bytes = std::ranges::size(buffer) * element_size;
  int bytes_sent = platform_send(fd_, std::ranges::data(buffer), buffer_size_in_bytes, flags);
  // return number of elements sent
  return make_response_(bytes_sent, bytes_sent / element_size);
}

template<typename T>
  requires std::ranges::contiguous_range<T> && std::ranges::sized_range<T>
inline std::expected<int, Socket::Error> Socket::receive(T& buffer, int flags) const noexcept {
  constexpr size_t element_size = sizeof(std::ranges::range_value_t<T>);
  size_t buffer_size_in_bytes = std::ranges::size(buffer) * element_size;
  int bytes_received = platform_recv(fd_, std::ranges::data(buffer), buffer_size_in_bytes, flags);

  // return num of elements we received
  return make_response_(bytes_received, bytes_received / element_size);
}

template<typename T>
inline std::expected<T, Socket::Error> Socket::get_option(int option) const noexcept {
  T value;
  size_t size = sizeof(T);
  int status = platform_getsockopt(fd_, SOL_SOCKET, option, &value, &size);

  return make_response_(status, value);
}

#endif// BROWSER_SOCKET_H
