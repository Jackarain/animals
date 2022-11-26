//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include "utils/internal.hpp"

#include "utils/url_view.hpp"

// trim 一个string_view对象.
std::string_view string_trim(std::string_view sv);
std::string_view string_trim_left(std::string_view sv);
std::string_view string_trim_right(std::string_view sv);

// 将一个string_view转成16进制的字符串.
std::string to_hex(std::string_view data);
std::string to_hex_prefixed(std::string_view data);

// 将1个16进制字符串转成vector<uint8_t>
bool from_hexstring(std::string_view src, std::vector<uint8_t>& result);

// 转换成字符串类型.
std::string to_string(const boost::posix_time::ptime& t);
std::string to_string(float v, int width, int precision = 3);

// base58编解码.
std::string base58_decode(std::string_view input);
std::string base58_encode(std::string_view input);

// base64编解码.
std::string base64_decode(std::string_view input);
std::string base64_encode(std::string_view input);

// 百分编码解码.
bool unescape_path(const std::string& in, std::string& out);

// 转换成存储单位.
std::string add_suffix(float val, char const* suffix = nullptr);

// 获取进程id.
uint64_t get_process_id();

// 随机字符串相关.
int gen_random_int(int start, int end);
std::string gen_unique_string(const unsigned int len);
uint32_t gen_unique_number();
std::string gen_uuid();

// 设置线程名.
void set_thread_name(const char* name);
void set_thread_name(std::thread* thread, const char* name);

// 用于解析listen使用的endpoint.
bool parse_endpoint_string(std::string_view str,
	std::string& host, std::string& port, bool& ipv6only);
bool make_listen_endpoint(const std::string& address,
	tcp::endpoint& endp, boost::system::error_code& ec);
bool make_listen_endpoint(const std::string& address,
	udp::endpoint& endp, boost::system::error_code& ec);
