//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#ifdef USE_MIMALLOC

#ifdef MI_OVERRIDE
#	include <mimalloc.h>
#else
#	include <mimalloc-new-delete.h>
#endif

#ifdef _WIN32
#	include <mimalloc-new-delete.h>
#endif

#endif // USE_MIMALLOC

#include <concepts>
#include <iostream>
#include <iterator>
#include <algorithm>
#include <functional>
#include <filesystem>
#include <tuple>
#include <utility>
#include <array>
#include <vector>
#include <streambuf>
#include <fstream>
#include <type_traits>
#include <any>
#include <cstdlib>
#include <string>
#include <memory>
#include <chrono>
#include <exception>
#include <system_error>
#include <stdexcept>
#include <thread>
#include <numeric>
#include <optional>
#include <random>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>
#include <cstring>
#include <variant>
#include <cinttypes>
#include <map>

using std::chrono::steady_clock;
using time_point = std::chrono::time_point<steady_clock>;


#ifdef _MSC_VER
#	pragma warning(push)
#	pragma warning(disable: 4702 4459)
#endif // _MSC_VER

#ifdef __clang__
#	pragma clang diagnostic push
#	pragma clang diagnostic ignored "-Wunused-private-field"
#endif

#include <boost/asio/io_context.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/defer.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/network_v4.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/buffer.hpp>

#include <boost/asio/ssl.hpp>
#include <boost/beast/ssl.hpp>

using tcp = boost::asio::ip::tcp;	// from <boost/asio/ip/tcp.hpp>
using udp = boost::asio::ip::udp;	// from <boost/asio/ip/udp.hpp>

using asio_timer = boost::asio::steady_timer;

#ifdef __clang__
#	pragma clang diagnostic pop
#endif // __clang__

#ifdef __GNUC__
#	pragma GCC diagnostic push
#	pragma GCC diagnostic ignored "-Warray-bounds"
#endif

#ifdef __clang__
#	pragma clang diagnostic push
#	pragma clang diagnostic ignored "-Warray-bounds"
#endif

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>

namespace websocket = boost::beast::websocket;
using ws_stream = websocket::stream<tcp::socket>;

#ifdef __GNUC__
#	pragma GCC diagnostic pop
#endif

#ifdef __clang__
#	pragma clang diagnostic pop
#endif

#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/find.hpp>

#ifdef _MSC_VER
#	pragma warning(pop)
#endif

#include <boost/smart_ptr/local_shared_ptr.hpp>
#include <boost/smart_ptr/make_local_shared.hpp>

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/mem_fun.hpp>
#include <boost/multi_index/hashed_index.hpp>

#include <boost/logic/tribool.hpp>
#include <boost/logic/tribool_io.hpp>

#include <boost/process.hpp>
