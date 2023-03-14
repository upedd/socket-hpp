# Socket.hpp

`Socket.hpp` is a low level C++23 wrapper around system sockets libraries such as `socket.h` or Winsock2.

> ⚠️ This library is experimental and may contain bugs or breaking API changes may be made.

## Goals
- Only a low-level abstraction around system libraries
- Multiplatform
- C++23 features
- Lowest performance footprint possible
- No external dependencies
- More safe and less code repetition than using system headers directly

## Examples

```c++
#include "socket.hpp"
#include <iostream>

int main() {
    auto candidates = Socket::get_address_info("www.examples.org", "80", Socket::Family::UNSPECIFIED, Socket::Type::STREAM);
    
    // error handling using c++23 std::expected
    if (!candidates) {
        std::cout << "error: " << candidates.error().what();
        return -1;
    }
    
    auto& address_info = candidates->at(0);
    
    auto socket = Socket::create(address_info.get_family(), address_info.get_type(), address_info.get_protocol());
    
    socket->connect(address_info.get_address());
    
    socket->send_all("GET / HTTP/1.0\r\nHost: examples.com\r\n\r\n");
    
    auto received = socket->receive_to_end<char>();
        
    std::cout << std::string(received->begin(), received->end());
}
```
For examples with proper error handling and address candidates handling look into [/examples](/examples) folder.

## References
- [Rust socket2 crate](https://docs.rs/socket2/latest/socket2/index.html)
- [Python sockets](https://docs.python.org/3/library/socket.html#socket-objects)
- [Beej's Guide to Network Programming](https://beej.us/guide/bgnet/html/)
- [Windows Sockets 2](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-start-page-2)

## License

[MIT](https://choosealicense.com/licenses/mit/)
