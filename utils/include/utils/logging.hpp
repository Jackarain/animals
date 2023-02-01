﻿//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once
#include <version>
#include <codecvt>
#include <clocale>
#include <fstream>
#include <chrono>
#include <list>
#include <mutex>
#include <memory>
#include <string>
#include <tuple>
#include <version>
#include <thread>
#include <functional>
#include <filesystem>
#include <system_error>
#include <atomic>
#include <deque>
#include <csignal>
#include <condition_variable>

#ifndef LOGGING_DISABLE_ASIO_ENDPOINT
#	if __has_include(<boost/asio.hpp>)
#		include <boost/asio/ip/tcp.hpp>
#		include <boost/asio/ip/udp.hpp>
#		include <boost/asio/ip/address.hpp>
#		include <boost/asio/ip/basic_endpoint.hpp>
#	else
#		define LOGGING_DISABLE_ASIO_ENDPOINT
#	endif
#endif // !LOGGING_DISABLE_ASIO_ENDPOINT

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/nowide/convert.hpp>
#include <boost/utility/string_view.hpp>

//////////////////////////////////////////////////////////////////////////
#if defined(_WIN32) || defined(WIN32)
#	ifndef WIN32_LEAN_AND_MEAN
#		define WIN32_LEAN_AND_MEAN
#	endif // !WIN32_LEAN_AND_MEAN
#	include <windows.h>
#endif // _WIN32

#ifdef USE_SYSTEMD_LOGGING
#if __has_include(<systemd/sd-journal.h>)
#	include <systemd/sd-journal.h>
#else
#error "systemd/sd-journal.h not found"
#endif
#endif

//////////////////////////////////////////////////////////////////////////
#if defined(__has_include)
#	if __has_include(<zlib.h>)
#		include <zlib.h>
#		ifndef LOGGING_COMPRESS_LOGS
#			define LOGGING_COMPRESS_LOGS
#		endif
#	endif
#else
#	ifdef LOGGING_COMPRESS_LOGS
#		include <zlib.h>
#	endif
#endif

#if defined(__cpp_lib_format)
#	include <format>
#endif

#if !defined(__cpp_lib_format)
#ifdef _MSC_VER
#	pragma warning(push)
#	pragma warning(disable: 4244 4127)
#endif // _MSC_VER

#ifdef __clang__
#	pragma clang diagnostic push
#	pragma clang diagnostic ignored "-Wexpansion-to-defined"
#endif

#include <fmt/ostream.h>
#include <fmt/printf.h>
#include <fmt/format.h>

namespace std {
	using ::fmt::format;
	using ::fmt::format_to;
	using ::fmt::vformat;
	using ::fmt::vformat_to;
	using ::fmt::make_format_args;
}

#ifdef __clang__
#	pragma clang diagnostic pop
#endif

#ifdef _MSC_VER
#	pragma warning(pop)
#endif
#endif


//////////////////////////////////////////////////////////////////////////
//
// User customization function for hook log, function signature:
//
// bool logger_writer(logger_tag,
//   int64_t time, const int& level, const std::string& message);
//

struct logger_tag
{};

namespace util {

#ifndef LOGGING_DISABLE_ASIO_ENDPOINT
	namespace net = boost::asio;
#endif

#ifndef LOG_APPNAME
#	define LOG_APPNAME "application"
#endif

#ifndef LOG_MAXFILE_SIZE
#	define LOG_MAXFILE_SIZE (-1)
#endif // LOG_MAXFILE_SIZE


#ifdef LOGGING_COMPRESS_LOGS

namespace logging_compress__ {

	const inline std::string LOGGING_GZ_SUFFIX = ".gz";
	const inline size_t LOGGING_GZ_BUFLEN = 65536;

	inline std::mutex& compress_lock()
	{
		static std::mutex lock;
		return lock;
	}

	inline bool do_compress_gz(const std::string& infile)
	{
		std::string outfile = infile + LOGGING_GZ_SUFFIX;

		gzFile out = gzopen(outfile.c_str(), "wb6f");
		if (!out)
			return false;
		typedef typename std::remove_pointer<gzFile>::type gzFileType;
		std::unique_ptr<gzFileType,
			decltype(&gzclose)> gz_closer(out, &gzclose);

		FILE* in = fopen(infile.c_str(), "rb");
		if (!in)
			return false;
		std::unique_ptr<FILE, decltype(&fclose)> FILE_closer(in, &fclose);

		std::unique_ptr<char[]> bufs(new char[LOGGING_GZ_BUFLEN]);
		char* buf = bufs.get();
		int len;

		for (;;) {
			len = (int)fread(buf, 1, sizeof(buf), in);
			if (ferror(in))
				return false;

			if (len == 0)
				break;

			int total = 0;
			int ret;
			while (total < len) {
				ret = gzwrite(out, buf + total, (unsigned)len - total);
				if (ret <= 0) {
					// detail error information see gzerror(out, &ret);
					return false;
				}
				total += ret;
			}
		}

		return true;
	}

}

#endif

inline bool global_logging___ = true;

namespace logger_aux__ {

	constexpr long long epoch___ = 0x19DB1DED53E8000LL;

	inline int64_t gettime()
	{
#ifdef WIN32
		static std::tuple<LONGLONG, LONGLONG, LONGLONG>
			static_start = []() ->
			std::tuple<LONGLONG, LONGLONG, LONGLONG>
		{
			LARGE_INTEGER f;
			QueryPerformanceFrequency(&f);

			FILETIME ft;
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN8)
			GetSystemTimePreciseAsFileTime(&ft);
#else
			GetSystemTimeAsFileTime(&ft);
#endif
			auto now = (((static_cast<long long>(ft.dwHighDateTime)) << 32)
				+ static_cast<long long>(ft.dwLowDateTime) - epoch___)
				/ 10000;

			LARGE_INTEGER start;
			QueryPerformanceCounter(&start);

			return { f.QuadPart / 1000, start.QuadPart, now };
		}();

		auto [freq, start, now] = static_start;

		LARGE_INTEGER current;
		QueryPerformanceCounter(&current);

		auto elapsed = current.QuadPart - start;
		elapsed /= freq;

		return static_cast<int64_t>(now + elapsed);
#else
		using std::chrono::system_clock;
		auto now = system_clock::now() -
			system_clock::time_point(std::chrono::milliseconds(0));

		return std::chrono::duration_cast<
			std::chrono::milliseconds>(now).count();
#endif
	}

	namespace internal {
		template <typename T = void>
		struct Null {};
		inline Null<> localtime_r(...) { return Null<>(); }
		inline Null<> localtime_s(...) { return Null<>(); }
		inline Null<> gmtime_r(...) { return Null<>(); }
		inline Null<> gmtime_s(...) { return Null<>(); }
	}

	// Thread-safe replacement for std::localtime
	inline bool localtime(std::time_t time, std::tm& tm)
	{
		struct LocalTime {
			std::time_t time_;
			std::tm tm_;

			LocalTime(std::time_t t) : time_(t) {}

			bool run() {
				using namespace internal;
				return handle(localtime_r(&time_, &tm_));
			}

			bool handle(std::tm* tm) { return tm != nullptr; }

			bool handle(internal::Null<>) {
				using namespace internal;
				return fallback(localtime_s(&tm_, &time_));
			}

			bool fallback(int res) { return res == 0; }

			bool fallback(internal::Null<>) {
				using namespace internal;
				std::tm* tm = std::localtime(&time_);
				if (tm) tm_ = *tm;
				return tm != nullptr;
			}
		};

		LocalTime lt(time);
		if (lt.run()) {
			tm = lt.tm_;
			return true;
		}

		return false;
	}

	inline uint32_t decode(uint32_t* state, uint32_t* codep, uint32_t byte)
	{
		static constexpr uint8_t utf8d[] =
{
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 00..1f
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 20..3f
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 40..5f
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 60..7f
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9, // 80..9f
	7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7, // a0..bf
	8,8,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, // c0..df
	0xa,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x4,0x3,0x3, // e0..ef
	0xb,0x6,0x6,0x6,0x5,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8, // f0..ff
	0x0,0x1,0x2,0x3,0x5,0x8,0x7,0x1,0x1,0x1,0x4,0x6,0x1,0x1,0x1,0x1, // s0..s0
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,0,1,0,1,1,1,1,1,1, // s1..s2
	1,2,1,1,1,1,1,2,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,1, // s3..s4
	1,2,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1,3,1,3,1,1,1,1,1,1, // s5..s6
	1,3,1,1,1,1,1,3,1,3,1,1,1,1,1,1,1,3,1,1,1,1,1,1,1,1,1,1,1,1,1,1, // s7..s8
};

		uint32_t type = utf8d[byte];

		*codep = (*state != 0) ?
			(byte & 0x3fu) | (*codep << 6) :
			(0xff >> type) & (byte);

		*state = utf8d[256 + *state * 16 + type];
		return *state;
	}

	inline bool utf8_check_is_valid(const std::string& str)
	{
		uint32_t codepoint;
		uint32_t state = 0;
		uint8_t* s = (uint8_t*)str.c_str();
		uint8_t* end = s + str.size();

		for (; s != end; ++s)
			if (decode(&state, &codepoint, *s) == 1)
				return false;

		return state == 0;
	}

	inline std::string from_u8string(const std::string& s)
	{
		return s;
	}

	inline std::string from_u8string(std::string&& s)
	{
		return s;
	}

#if defined(__cpp_lib_char8_t)
	inline std::string from_u8string(const std::u8string& s)
	{
		return std::string(s.begin(), s.end());
	}
#endif

#if 0
	inline bool utf8_check_is_valid(const std::string& str)
	{
		int c, i, ix, n, j;
		for (i = 0, ix = static_cast<int>(str.size()); i < ix; i++)
		{
			c = (unsigned char)str[i];
			// is_printable_ascii
			//if (c==0x09 || c==0x0a || c==0x0d ||
			// (0x20 <= c && c <= 0x7e)) n = 0;
			if (0x00 <= c && c <= 0x7f) n = 0; // 0bbbbbbb
			else if ((c & 0xE0) == 0xC0) n = 1; // 110bbbbb
			else if (c == 0xed && i < (ix - 1) &&
				((unsigned char)str[i + 1] & 0xa0) == 0xa0)
				return false; // U+d800 to U+dfff
			else if ((c & 0xF0) == 0xE0) n = 2; // 1110bbbb
			else if ((c & 0xF8) == 0xF0) n = 3; // 11110bbb
			// 111110bb //byte 5, unnecessary in 4 byte UTF-8
			//else if (($c & 0xFC) == 0xF8) n=4;
			// 1111110b //byte 6, unnecessary in 4 byte UTF-8
			//else if (($c & 0xFE) == 0xFC) n=5;
			else return false;
			// n bytes matching 10bbbbbb follow ?
			for (j = 0; j < n && i < ix; j++)
			{
				if ((++i == ix) || (((unsigned char)str[i] & 0xC0) != 0x80))
					return false;
			}
		}
		return true;
	}
#endif

	inline bool wide_string(const std::wstring& src, std::string& str)
	{
		std::locale sys_locale("");

		const wchar_t* data_from = src.c_str();
		const wchar_t* data_from_end = src.c_str() + src.size();
		const wchar_t* data_from_next = 0;

		int wchar_size = 4;
		std::unique_ptr<char> buffer(new char[(src.size() + 1) * wchar_size]);
		char* data_to = buffer.get();
		char* data_to_end = data_to + (src.size() + 1) * wchar_size;
		char* data_to_next = 0;

		memset(data_to, 0, (src.size() + 1) * wchar_size);

		typedef std::codecvt<wchar_t, char, mbstate_t> convert_facet;
		mbstate_t out_state;
		auto result = std::use_facet<convert_facet>(sys_locale).out(
			out_state, data_from, data_from_end, data_from_next,
			data_to, data_to_end, data_to_next);
		if (result == convert_facet::ok)
		{
			str = data_to;
			return true;
		}

		return false;
	}

#ifdef WIN32
	inline bool string_wide(const std::string& src, std::wstring& wstr)
	{
		auto len = MultiByteToWideChar(CP_ACP, 0, src.c_str(), -1, NULL, 0);
		if (len > 0)
		{
			wchar_t* tmp = (wchar_t*)malloc(sizeof(wchar_t) * len);
			if (!tmp)
				return false;
			MultiByteToWideChar(CP_ACP, 0, src.c_str(), -1, tmp, len);
			wstr.assign(tmp);
			free(tmp);
			return true;
		}
		return false;
	}
#else
	inline bool string_wide(const std::string& src, std::wstring& wstr)
	{
		std::locale sys_locale("");
		const char* data_from = src.c_str();
		const char* data_from_end = src.c_str() + src.size();
		const char* data_from_next = 0;

		std::vector<wchar_t> buffer(src.size() + 1, 0);
		wchar_t* data_to = buffer.data();
		wchar_t* data_to_end = data_to + src.size() + 1;
		wchar_t* data_to_next = 0;

		wmemset(data_to, 0, src.size() + 1);

		typedef std::codecvt<wchar_t, char, mbstate_t> convert_facet;
		mbstate_t in_state;
		auto result = std::use_facet<convert_facet>(sys_locale).in(
			in_state, data_from, data_from_end, data_from_next,
			data_to, data_to_end, data_to_next);
		if (result == convert_facet::ok)
		{
			wstr = data_to;
			return true;
		}

		return false;
	}
#endif

	inline std::string string_utf8(const std::string& str)
	{
		if (!logger_aux__::utf8_check_is_valid(str))
		{
			std::wstring wres;
			if (logger_aux__::string_wide(str, wres))
				return boost::nowide::narrow(wres);
		}

		return str;
	}

	template <class Lock>
	Lock& lock_single()
	{
		static Lock lock_instance;
		return lock_instance;
	}

	template <class Writer>
	Writer& writer_single(std::string log_path = "")
	{
		static Writer writer_instance(log_path);
		return writer_instance;
	}

	inline struct tm* time_to_string(char* buffer, int64_t time)
	{
		std::time_t rawtime = time / 1000;
		thread_local struct tm ptm;

		if (!localtime(rawtime, ptm))
			return nullptr;

		if (!buffer)
			return &ptm;

		std::format_to(buffer,
			"{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
			ptm.tm_year + 1900, ptm.tm_mon + 1, ptm.tm_mday,
			ptm.tm_hour, ptm.tm_min, ptm.tm_sec, (int)(time % 1000)
		);

		return &ptm;
	}
}


class auto_logger_file__
{
	// c++11 noncopyable.
	auto_logger_file__(const auto_logger_file__&) = delete;
	auto_logger_file__& operator=(const auto_logger_file__&) = delete;

public:
	auto_logger_file__(std::string log_path = "")
	{
		if (!log_path.empty())
			m_log_path = log_path;

		m_log_path = m_log_path / (LOG_APPNAME + std::string(".log"));

		if (!global_logging___)
			return;

		std::error_code ignore_ec;
		if (!std::filesystem::exists(m_log_path, ignore_ec))
			std::filesystem::create_directories(
				m_log_path.parent_path(), ignore_ec);
	}
	~auto_logger_file__()
	{
		m_last_time = 0;
	}

	typedef std::shared_ptr<std::ofstream> ofstream_ptr;

	void open(const char* path)
	{
		m_log_path = path;

		if (!global_logging___)
			return;

		std::error_code ignore_ec;
		if (!std::filesystem::exists(m_log_path, ignore_ec))
			std::filesystem::create_directories(
				m_log_path.parent_path(), ignore_ec);
	}

	std::string log_path() const
	{
		return m_log_path.string();
	}

	void logging(bool disable) noexcept
	{
		m_disable_write = disable;
	}

	void write([[maybe_unused]] int64_t time,
		const char* str, std::streamsize size)
	{
		if (m_disable_write)
			return;

		bool condition = false;
		auto hours = time / 1000 / 3600;
		auto last_hours = m_last_time / 1000 / 3600;

		if (static_cast<int>(m_log_size) > LOG_MAXFILE_SIZE &&
			LOG_MAXFILE_SIZE > 0)
			condition = true;

		if (last_hours != hours && LOG_MAXFILE_SIZE < 0)
			condition = true;

		while (condition) {
			if (m_last_time == -1) {
				m_last_time = time;
				break;
			}

			auto ptm = logger_aux__::time_to_string(nullptr, m_last_time);

			m_ofstream->close();
			m_ofstream.reset();

			auto logpath = std::filesystem::path(m_log_path.parent_path());
			std::filesystem::path filename;

			if constexpr (LOG_MAXFILE_SIZE <= 0) {
				auto logfile = std::format("{:04d}{:02d}{:02d}-{:02d}.log",
					ptm->tm_year + 1900,
					ptm->tm_mon + 1,
					ptm->tm_mday,
					ptm->tm_hour);
				filename = logpath / logfile;
			} else {
				auto utc_time = std::mktime(ptm);
				auto logfile = std::format("{:04d}{:02d}{:02d}-{}.log",
					ptm->tm_year + 1900,
					ptm->tm_mon + 1,
					ptm->tm_mday,
					utc_time);
				filename = logpath / logfile;
			}

			m_last_time = time;

			std::error_code ec;
			if (!std::filesystem::copy_file(m_log_path, filename, ec))
				break;

			std::filesystem::resize_file(m_log_path, 0, ec);
			m_log_size = 0;

#ifdef LOGGING_COMPRESS_LOGS
			auto fn = filename.string();
			std::thread th([fn]()
				{
					std::error_code ignore_ec;
					std::mutex& m = logging_compress__::compress_lock();
					std::lock_guard lock(m);
					if (!logging_compress__::do_compress_gz(fn))
					{
						auto file = fn + logging_compress__::LOGGING_GZ_SUFFIX;
						std::filesystem::remove(file, ignore_ec);
						if (ignore_ec)
							std::cerr
								<< "delete log failed: " << file
								<< ", error code: " << ignore_ec.message()
								<< std::endl;
						return;
					}

					std::filesystem::remove(fn, ignore_ec);
				});
			th.detach();
#endif
			break;
		}

		if (!m_ofstream) {
			m_ofstream.reset(new std::ofstream);
			auto& ofstream = *m_ofstream;
			ofstream.open(m_log_path.string().c_str(),
				std::ios_base::out | std::ios_base::app);
			ofstream.sync_with_stdio(false);
		}

		if (m_ofstream->is_open()) {
			m_log_size += size;
			m_ofstream->write(str, size);
			m_ofstream->flush();
		}
	}

private:
	std::filesystem::path m_log_path{"./logs"};
	ofstream_ptr m_ofstream;
	int64_t m_last_time{ -1 };
	std::size_t m_log_size{ 0 };
	bool m_disable_write{ false };
};

#ifndef DISABLE_LOGGER_THREAD_SAFE
#define LOGGER_LOCKS_() std::lock_guard \
	lock(logger_aux__::lock_single<std::mutex>())
#else
#define LOGGER_LOCKS_() ((void)0)
#endif // LOGGER_THREAD_SAFE

#ifndef LOGGER_DBG_VIEW_
#if defined(WIN32) && \
	(defined(LOGGER_DBG_VIEW) || \
	defined(DEBUG) || \
	defined(_DEBUG))
#define LOGGER_DBG_VIEW_(x)                \
	do {                                   \
		::OutputDebugStringW((x).c_str()); \
	} while (0)
#else
#define LOGGER_DBG_VIEW_(x) ((void)0)
#endif // WIN32 && LOGGER_DBG_VIEW
#endif // LOGGER_DBG_VIEW_

const inline int _logger_debug_id__ = 0;
const inline int _logger_info_id__ = 1;
const inline int _logger_warn_id__ = 2;
const inline int _logger_error_id__ = 3;
const inline int _logger_file_id__ = 4;

const inline std::string _LOGGER_DEBUG_STR__ = "DEBUG";
const inline std::string _LOGGER_INFO_STR__ = "INFO";
const inline std::string _LOGGER_WARN_STR__ = "WARNING";
const inline std::string _LOGGER_ERR_STR__ = "ERROR";
const inline std::string _LOGGER_FILE_STR__ = "FILE";

inline void logger_output_console__([[maybe_unused]] bool disable_cout,
	[[maybe_unused]] const int& level,
	[[maybe_unused]] const std::string& prefix,
	[[maybe_unused]] const std::string& message) noexcept
{
#if defined(WIN32)

#if !defined(DISABLE_LOGGER_TO_CONSOLE) || !defined(DISABLE_LOGGER_TO_DBGVIEW)
	std::wstring title = boost::nowide::widen(prefix);
	std::wstring msg = boost::nowide::widen(message);
#endif

#if !defined(DISABLE_LOGGER_TO_CONSOLE)
	if (!disable_cout)
	{
		HANDLE handle_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
		CONSOLE_SCREEN_BUFFER_INFO csbi;
		GetConsoleScreenBufferInfo(handle_stdout, &csbi);
		if (level == _logger_info_id__)
			SetConsoleTextAttribute(handle_stdout,
				FOREGROUND_GREEN);
		else if (level == _logger_debug_id__)
			SetConsoleTextAttribute(handle_stdout,
				FOREGROUND_GREEN | FOREGROUND_INTENSITY);
		else if (level == _logger_warn_id__)
			SetConsoleTextAttribute(handle_stdout,
				FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY);
		else if (level == _logger_error_id__)
			SetConsoleTextAttribute(handle_stdout,
				FOREGROUND_RED | FOREGROUND_INTENSITY);

		WriteConsoleW(handle_stdout,
			title.data(), (DWORD)title.size(), nullptr, nullptr);
		SetConsoleTextAttribute(handle_stdout,
			FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_BLUE);

		WriteConsoleW(handle_stdout,
			msg.data(), (DWORD)msg.size(), nullptr, nullptr);
		SetConsoleTextAttribute(handle_stdout, csbi.wAttributes);
	}
#endif

#if !defined(DISABLE_LOGGER_TO_DBGVIEW)
	LOGGER_DBG_VIEW_(title + msg);
#endif

#elif !defined(DISABLE_LOGGER_TO_CONSOLE)
	if (!disable_cout)
	{
		std::string out;
		if (level == _logger_info_id__)
			std::format_to(std::back_inserter(out),
				"\033[32m{}\033[0m{}", prefix, message);
		else if (level == _logger_debug_id__)
			std::format_to(std::back_inserter(out),
				"\033[1;32m{}\033[0m{}", prefix, message);
		else if (level == _logger_warn_id__)
			std::format_to(std::back_inserter(out),
				"\033[1;33m{}\033[0m{}", prefix, message);
		else if (level == _logger_error_id__)
			std::format_to(std::back_inserter(out),
				"\033[1;31m{}\033[0m{}", prefix, message);
		std::cout << out;
		std::cout.flush();
	}
#endif
}

#ifdef USE_SYSTEMD_LOGGING
inline void logger_output_systemd__(
	const int& level, const std::string& message) noexcept
{
	if (level == _logger_info_id__)
		sd_journal_print(LOG_INFO, "%s", message.c_str());
	else if (level == _logger_debug_id__)
		sd_journal_print(LOG_DEBUG, "%s", message.c_str());
	else if (level == _logger_warn_id__)
		sd_journal_print(LOG_WARNING, "%s", message.c_str());
	else if (level == _logger_error_id__)
		sd_journal_print(LOG_ERR, "%s", message.c_str());
}
#endif // USE_SYSTEMD_LOGGING

inline const std::string& logger_level_string__(const int& level) noexcept
{
	switch (level)
	{
	case _logger_debug_id__:
		return _LOGGER_DEBUG_STR__;
	case _logger_info_id__:
		return _LOGGER_INFO_STR__;
	case _logger_warn_id__:
		return _LOGGER_WARN_STR__;
	case _logger_error_id__:
		return _LOGGER_ERR_STR__;
	case _logger_file_id__:
		return _LOGGER_FILE_STR__;
	}

	BOOST_ASSERT(false && "invalid logging level!");
	return _LOGGER_DEBUG_STR__;
}

struct access {
	template <class... T>
	static bool logger_writer(logger_tag, T...) noexcept
	{
		return false;
	}
};

template <class T>
inline bool logger_writer(T tag
	, int64_t time, const int& level, const std::string& message) noexcept
{
	return access::logger_writer(tag
		, time, level, message
	);
}

template<class T>
inline bool logger_writer_adl(T tag
	, int64_t time, const int& level, const std::string& message) noexcept
{
	return logger_writer(std::forward<T>(tag),
		time, level, message);
}

inline void logger_writer__(int64_t time, const int& level,
	const std::string& message,
	[[maybe_unused]] bool disable_cout = false) noexcept
{
	LOGGER_LOCKS_();
	static auto& logger = util::logger_aux__::writer_single<
		util::auto_logger_file__>();
	char ts[64] = { 0 };
	[[maybe_unused]] auto ptm = logger_aux__::time_to_string(ts, time);
	std::string prefix = ts + std::string(" [") +
		logger_level_string__(level) + std::string("]: ");
	std::string tmp = message + "\n";
	std::string whole = prefix + tmp;

	// User log hook.
	if (logger_writer_adl(logger_tag(), time, level, message))
		return;

#ifndef DISABLE_WRITE_LOGGING
	logger.write(time, whole.c_str(), whole.size());
#endif // !DISABLE_WRITE_LOGGING
	logger_output_console__(disable_cout, level, prefix, tmp);
#ifdef USE_SYSTEMD_LOGGING
	logger_output_systemd__(level, message);
#endif // USE_SYSTEMD_LOGGING
}

#if defined(_WIN32) || defined(WIN32)
static LONG WINAPI unexpectedExceptionHandling(EXCEPTION_POINTERS* info);
#endif
void signalHandler(int);

namespace logger_aux__ {
	using namespace std::chrono_literals;

	class async_logger___
	{
		struct internal_message
		{
			int level_;
			int64_t time_;
			std::string message_;
			bool disable_cout_;
		};

		// c++11 noncopyable.
		async_logger___(const async_logger___&) = delete;
		async_logger___& operator=(const async_logger___&) = delete;

	public:
		async_logger___()
		{
			// 实现Crash handler以接管在crash时
			// 不会漏写日志.

#if defined(_WIN32) || defined(WIN32)
			m_unexpected_exception_handler =
				SetUnhandledExceptionFilter(unexpectedExceptionHandling);
#endif
			signal(SIGTERM, signalHandler);
			signal(SIGABRT, signalHandler);
			signal(SIGFPE, signalHandler);
			signal(SIGSEGV, signalHandler);
			signal(SIGILL, signalHandler);
		}
		~async_logger___()
		{
			m_abort = true;
			if (m_bg_thread.joinable())
				m_bg_thread.join();
		}

	public:
#if defined(_WIN32) || defined(WIN32)
		LPTOP_LEVEL_EXCEPTION_FILTER oldUnhandledExceptionFilter()
		{
			return m_unexpected_exception_handler;
		}
#endif

		void stop()
		{
			m_abort = true;
		}

		void internal_work()
		{
			while (!m_abort || !m_messages.empty())
			{
				std::unique_lock lock(m_bg_mutex);

				if (m_messages.empty())
					m_bg_cv.wait_for(lock, 128ms);

				while (!m_messages.empty())
				{
					auto message = std::move(m_messages.front());
					m_messages.pop_front();

					logger_writer__(message.time_,
						message.level_,
						message.message_,
						message.disable_cout_);
				}
			}
		}

		void post_log(const int& level,
			std::string&& message, bool disable_cout = false)
		{
			[[maybe_unused]] static auto runthread =
				&(m_bg_thread = std::thread([this]()
					{
						internal_work();
					}));

			auto time = logger_aux__::gettime();
			std::unique_lock lock(m_bg_mutex);

			m_messages.emplace_back(
				internal_message
				{
				.level_ = level,
				.time_ = time,
				.message_ = std::move(message),
				.disable_cout_ = disable_cout
				}
			);
			lock.unlock();

			m_bg_cv.notify_one();
		}

	private:
		std::thread m_bg_thread;
		std::mutex m_bg_mutex;
		std::condition_variable m_bg_cv;
		std::deque<internal_message> m_messages;
		std::atomic_bool m_abort{ false };
#if defined(_WIN32) || defined(WIN32)
		LPTOP_LEVEL_EXCEPTION_FILTER m_unexpected_exception_handler{ nullptr };
#endif
	};
}

inline std::shared_ptr<logger_aux__::async_logger___> global_logger_obj___ =
	std::make_shared<logger_aux__::async_logger___>();

#if defined(_WIN32) || defined(WIN32)
static LONG WINAPI unexpectedExceptionHandling(EXCEPTION_POINTERS* e)
{
	if (!global_logger_obj___)
		return EXCEPTION_CONTINUE_SEARCH;

	auto old = global_logger_obj___->oldUnhandledExceptionFilter();
	SetUnhandledExceptionFilter(old);

	global_logger_obj___.reset();

	return old(e);
}
#endif

inline void signalHandler(int)
{
	global_logger_obj___.reset();
}

inline void init_logging(const std::string& path = "")
{
	logger_aux__::writer_single<util::auto_logger_file__>(path);
}

inline std::string log_path()
{
	auto_logger_file__& file =
		logger_aux__::writer_single<util::auto_logger_file__>();
	return file.log_path();
}

inline void shutdown_logging()
{
	auto& log_obj = global_logger_obj___;
	if (log_obj) {
		log_obj->stop();
		log_obj.reset();
	}
}

inline void toggle_logging()
{
	global_logging___ = !global_logging___;
}

inline void toggle_write_logging(bool disable)
{
	auto_logger_file__& file =
		logger_aux__::writer_single<util::auto_logger_file__>();
	file.logging(disable);
}

struct auto_init_async_logger
{
	auto_init_async_logger() {
		init_logging();
	}
	~auto_init_async_logger() {
		shutdown_logging();
	}
};

class logger___
{
	// c++11 noncopyable.
	logger___(const logger___&) = delete;
	logger___& operator=(const logger___&) = delete;
public:
	logger___(const int& level,
		bool async = false, bool disable_cout = false)
		: level_(level)
		, async_(async)
		, disable_cout_(disable_cout)
	{
		if (!global_logging___)
			return;
	}
	~logger___()
	{
		if (!global_logging___)
			return;

		std::string message = logger_aux__::string_utf8(out_);

		// if global_logger_obj___ is nullptr, fallback to
		// synchronous operation.
		if (async_ && global_logger_obj___)
			global_logger_obj___->post_log(
				level_, std::move(message), disable_cout_);
		else
			logger_writer__(logger_aux__::gettime(),
				level_, message, disable_cout_);
	}

	template <class... Args>
	inline logger___& format_to(std::string_view fmt, Args&&... args)
	{
		if (!global_logging___)
			return *this;
		out_ += std::vformat(fmt,
			std::make_format_args(std::forward<Args>(args)...));
		return *this;
	}

	template <class T>
	inline logger___& strcat_impl(T const& v) noexcept
	{
		if (!global_logging___)
			return *this;
		std::format_to(std::back_inserter(out_), "{}", v);
		return *this;
	}

	inline logger___& operator<<(bool v)
	{
		return strcat_impl(v);
	}
	inline logger___& operator<<(char v)
	{
		return strcat_impl(v);
	}
	inline logger___& operator<<(short v)
	{
		return strcat_impl(v);
	}
	inline logger___& operator<<(unsigned short v)
	{
		return strcat_impl(v);
	}
	inline logger___& operator<<(int v)
	{
		return strcat_impl(v);
	}
	inline logger___& operator<<(unsigned int v)
	{
		return strcat_impl(v);
	}
	inline logger___& operator<<(unsigned long long v)
	{
		return strcat_impl(v);
	}
	inline logger___& operator<<(long v)
	{
		return strcat_impl(v);
	}
	inline logger___& operator<<(long long v)
	{
		return strcat_impl(v);
	}
	inline logger___& operator<<(float v)
	{
		return strcat_impl(v);
	}
	inline logger___& operator<<(double v)
	{
		return strcat_impl(v);
	}
	inline logger___& operator<<(long double v)
	{
		return strcat_impl(v);
	}
	inline logger___& operator<<(unsigned long int v)
	{
		return strcat_impl(v);
	}
	inline logger___& operator<<(const std::string& v)
	{
		return strcat_impl(v);
	}
	inline logger___& operator<<(const std::wstring& v)
	{
		return strcat_impl(boost::nowide::narrow(v));
	}
	inline logger___& operator<<(const std::u16string& v)
	{
		return strcat_impl(boost::nowide::narrow(v));
	}
	inline logger___& operator<<(const std::string_view& v)
	{
		return strcat_impl(v);
	}
	inline logger___& operator<<(const boost::string_view& v)
	{
		return strcat_impl(std::string_view{v.data(), v.length()});
	}
	inline logger___& operator<<(const char* v)
	{
		return strcat_impl(v);
	}
	inline logger___& operator<<(const wchar_t* v)
	{
		return strcat_impl(boost::nowide::narrow(v));
	}
	inline logger___& operator<<(const void *v)
	{
		if (!global_logging___)
			return *this;
		std::format_to(std::back_inserter(out_), "{:#010x}", (std::size_t)v);
		return *this;
	}
	inline logger___& operator<<(const std::chrono::nanoseconds& v)
	{
		if (!global_logging___)
			return *this;
		std::format_to(std::back_inserter(out_), "{}ns", v.count());
		return *this;
	}
	inline logger___& operator<<(const std::chrono::microseconds& v)
	{
		if (!global_logging___)
			return *this;
		std::format_to(std::back_inserter(out_), "{}us", v.count());
		return *this;
	}
	inline logger___& operator<<(const std::chrono::milliseconds& v)
	{
		if (!global_logging___)
			return *this;
		std::format_to(std::back_inserter(out_), "{}ms", v.count());
		return *this;
	}
	inline logger___& operator<<(const std::chrono::seconds& v)
	{
		if (!global_logging___)
			return *this;
		std::format_to(std::back_inserter(out_), "{}s", v.count());
		return *this;
	}
	inline logger___& operator<<(const std::chrono::minutes& v)
	{
		if (!global_logging___)
			return *this;
		std::format_to(std::back_inserter(out_), "{}min", v.count());
		return *this;
	}
	inline logger___& operator<<(const std::chrono::hours& v)
	{
		if (!global_logging___)
			return *this;
		std::format_to(std::back_inserter(out_), "{}h", v.count());
		return *this;
	}

#ifndef LOGGING_DISABLE_ASIO_ENDPOINT
	inline logger___& operator<<(const net::ip::tcp::endpoint& v)
	{
		if (!global_logging___)
			return *this;
		if (v.address().is_v6())
			std::format_to(std::back_inserter(out_),
				"[{}]:{}", v.address().to_string(), v.port());
		else
			std::format_to(std::back_inserter(out_),
				"{}:{}", v.address().to_string(), v.port());
		return *this;
	}
	inline logger___& operator<<(const net::ip::udp::endpoint& v)
	{
		if (!global_logging___)
			return *this;
		if (v.address().is_v6())
			std::format_to(std::back_inserter(out_),
				"[{}]:{}", v.address().to_string(), v.port());
		else
			std::format_to(std::back_inserter(out_),
				"{}:{}", v.address().to_string(), v.port());
		return *this;
	}
#endif

#if (__cplusplus >= 202002L)
	inline logger___& operator<<(const std::chrono::days& v)
	{
		if (!global_logging___)
			return *this;
		std::format_to(std::back_inserter(out_), "{}d", v.count());
		return *this;
	}
	inline logger___& operator<<(const std::chrono::weeks& v)
	{
		if (!global_logging___)
			return *this;
		std::format_to(std::back_inserter(out_), "{}weeks", v.count());
		return *this;
	}
	inline logger___& operator<<(const std::chrono::years& v)
	{
		if (!global_logging___)
			return *this;
		std::format_to(std::back_inserter(out_), "{}years", v.count());
		return *this;
	}
	inline logger___& operator<<(const std::chrono::months& v)
	{
		if (!global_logging___)
			return *this;
		std::format_to(std::back_inserter(out_), "{}months", v.count());
		return *this;
	}
	inline logger___& operator<<(const std::chrono::weekday& v)
	{
		if (!global_logging___)
			return *this;
		switch (v.c_encoding())
		{
#if 0
		case 0:	out_ = "Sunday"; break;
		case 1:	out_ = "Monday"; break;
		case 2:	out_ = "Tuesday"; break;
		case 3:	out_ = "Wednesday"; break;
		case 4:	out_ = "Thursday"; break;
		case 5:	out_ = "Friday"; break;
		case 6:	out_ = "Saturday"; break;
#else
		case 0:	out_ = logger_aux__::from_u8string(u8"周日"); break;
		case 1:	out_ = logger_aux__::from_u8string(u8"周一"); break;
		case 2:	out_ = logger_aux__::from_u8string(u8"周二"); break;
		case 3:	out_ = logger_aux__::from_u8string(u8"周三"); break;
		case 4:	out_ = logger_aux__::from_u8string(u8"周四"); break;
		case 5:	out_ = logger_aux__::from_u8string(u8"周五"); break;
		case 6:	out_ = logger_aux__::from_u8string(u8"周六"); break;
#endif
		}
		return *this;
	}
	inline logger___& operator<<(const std::chrono::year& v)
	{
		if (!global_logging___)
			return *this;
#if 0
		std::format_to(std::back_inserter(out_),
			"{:04}", static_cast<int>(v));
#else
		std::format_to(std::back_inserter(out_),
			"{:04}{}", static_cast<int>(v),
				logger_aux__::from_u8string(u8"年"));
#endif
		return *this;
	}
	inline logger___& operator<<(const std::chrono::month& v)
	{
		if (!global_logging___)
			return *this;
		switch (static_cast<unsigned int>(v))
		{
#if 0
		case  1: out_ = "January"; break;
		case  2: out_ = "February"; break;
		case  3: out_ = "March"; break;
		case  4: out_ = "April"; break;
		case  5: out_ = "May"; break;
		case  6: out_ = "June"; break;
		case  7: out_ = "July"; break;
		case  8: out_ = "August"; break;
		case  9: out_ = "September"; break;
		case 10: out_ = "October"; break;
		case 11: out_ = "November"; break;
		case 12: out_ = "December"; break;
#else
		case  1: out_ = logger_aux__::from_u8string(u8"01月"); break;
		case  2: out_ = logger_aux__::from_u8string(u8"02月"); break;
		case  3: out_ = logger_aux__::from_u8string(u8"03月"); break;
		case  4: out_ = logger_aux__::from_u8string(u8"04月"); break;
		case  5: out_ = logger_aux__::from_u8string(u8"05月"); break;
		case  6: out_ = logger_aux__::from_u8string(u8"06月"); break;
		case  7: out_ = logger_aux__::from_u8string(u8"07月"); break;
		case  8: out_ = logger_aux__::from_u8string(u8"08月"); break;
		case  9: out_ = logger_aux__::from_u8string(u8"09月"); break;
		case 10: out_ = logger_aux__::from_u8string(u8"10月"); break;
		case 11: out_ = logger_aux__::from_u8string(u8"11月"); break;
		case 12: out_ = logger_aux__::from_u8string(u8"12月"); break;
#endif
		}
		return *this;
	}
	inline logger___& operator<<(const std::chrono::day& v)
	{
		if (!global_logging___)
			return *this;
#if 0
		std::format_to(std::back_inserter(out_),
			"{:02}", static_cast<int>(v));
#else
		std::format_to(std::back_inserter(out_),
			"{:02}{}", static_cast<unsigned int>(v),
				logger_aux__::from_u8string(u8"日"));
#endif
		return *this;
	}
#endif
	inline logger___& operator<<(const boost::posix_time::ptime& p) noexcept
	{
		if (!global_logging___)
			return *this;

		if (!p.is_not_a_date_time())
		{
			auto date = p.date().year_month_day();
			auto time = p.time_of_day();

			std::format_to(std::back_inserter(out_),
				"{:04}", static_cast<unsigned int>(date.year));
			std::format_to(std::back_inserter(out_),
				"-{:02}", date.month.as_number());
			std::format_to(std::back_inserter(out_),
				"-{:02}", date.day.as_number());

			std::format_to(std::back_inserter(out_),
				" {:02}", time.hours());
			std::format_to(std::back_inserter(out_),
				":{:02}", time.minutes());
			std::format_to(std::back_inserter(out_),
				":{:02}", time.seconds());

			auto ms = time.total_milliseconds() % 1000;		// milliseconds.
			if (ms != 0)
				std::format_to(std::back_inserter(out_),
					".{:03}", ms);
		}
		else
		{
			BOOST_ASSERT("Not a date time" && false);
			out_ += "NOT A DATE TIME";
		}

		return *this;
	}
	inline logger___& operator<<(const std::thread::id& id) noexcept
	{
		std::ostringstream oss;
		oss << id;
		out_ += oss.str();
		return *this;
	}

	std::string out_;
	const int& level_;
	bool async_;
	bool disable_cout_;
};

class empty_logger___
{
public:
	template <class T>
	empty_logger___& operator<<(T const&/*v*/)
	{
		return *this;
	}
};
} // namespace util

#undef LOG_DBG
#undef LOG_INFO
#undef LOG_WARN
#undef LOG_ERR
#undef LOG_FILE

#undef LOG_FMT
#undef LOG_IFMT
#undef LOG_WFMT
#undef LOG_EFMT
#undef LOG_FFMT

#undef ASYNC_LOGDBG
#undef ASYNC_LOGINFO
#undef ASYNC_LOGWARN
#undef ASYNC_LOGERR
#undef ASYNC_LOGFILE

#undef ASYNC_LOGFMT
#undef ASYNC_LOGIFMT
#undef ASYNC_LOGWFMT
#undef ASYNC_LOGEFMT
#undef ASYNC_LOGFFMT

#if (defined(DEBUG) || defined(_DEBUG) || \
	defined(ENABLE_LOGGER)) && !defined(DISABLE_LOGGER)

#define LOG_DBG util::logger___(util::_logger_debug_id__)
#define LOG_INFO util::logger___(util::_logger_info_id__)
#define LOG_WARN util::logger___(util::_logger_warn_id__)
#define LOG_ERR util::logger___(util::_logger_error_id__)
#define LOG_FILE util::logger___(util::_logger_file_id__, false, true)

#define LOG_FMT(...) util::logger___( \
		util::_logger_debug_id__).format_to(__VA_ARGS__)
#define LOG_IFMT(...) util::logger___( \
		util::_logger_info_id__).format_to(__VA_ARGS__)
#define LOG_WFMT(...) util::logger___( \
		util::_logger_warn_id__).format_to(__VA_ARGS__)
#define LOG_EFMT(...) util::logger___( \
		util::_logger_error_id__).format_to(__VA_ARGS__)
#define LOG_FFMT(...) util::logger___( \
		util::_logger_file_id__, false, true).format_to(__VA_ARGS__)

#define ASYNC_LOGDBG util::logger___(util::_logger_debug_id__, true)
#define ASYNC_LOGINFO util::logger___(util::_logger_info_id__, true)
#define ASYNC_LOGWARN util::logger___(util::_logger_warn_id__, true)
#define ASYNC_LOGERR util::logger___(util::_logger_error_id__, true)
#define ASYNC_LOGFILE util::logger___(util::_logger_file_id__, true, true)

#define ASYNC_LOGFMT(...) util::logger___( \
		util::_logger_debug_id__, true).format_to(__VA_ARGS__)
#define ASYNC_LOGIFMT(...) util::logger___( \
		util::_logger_info_id__, true).format_to(__VA_ARGS__)
#define ASYNC_LOGWFMT(...) util::logger___( \
		util::_logger_warn_id__, true).format_to(__VA_ARGS__)
#define ASYNC_LOGEFMT(...) util::logger___( \
		util::_logger_error_id__, true).format_to(__VA_ARGS__)
#define ASYNC_LOGFFMT(...) util::logger___( \
		util::_logger_file_id__, true, true).format_to(__VA_ARGS__)

#define ASYNC_VLOGDBG ASYNC_LOGDBG \
	<< "(" << __FILE__ << ":" << __LINE__ << "): "
#define ASYNC_VLOGINFO ASYNC_LOGINFO \
	<< "(" << __FILE__ << ":" << __LINE__ << "): "
#define ASYNC_VLOGWARN ASYNC_LOGWARN \
	<< "(" << __FILE__ << ":" << __LINE__ << "): "
#define ASYNC_VLOGERR ASYNC_LOGERR \
	<< "(" << __FILE__ << ":" << __LINE__ << "): "
#define ASYNC_VLOGFILE ASYNC_LOGFILE \
	<< "(" << __FILE__ << ":" << __LINE__ << "): "

#define ASYNC_VLOGFMT(...) (ASYNC_LOGDBG << "(" \
		<< __FILE__ << ":" << __LINE__ << "): ").format_to(__VA_ARGS__)
#define ASYNC_VLOGIFMT(...) (ASYNC_LOGINFO << "(" \
		<< __FILE__ << ":" << __LINE__ << "): ").format_to(__VA_ARGS__)
#define ASYNC_VLOGWFMT(...) (ASYNC_LOGWARN << "(" \
		<< __FILE__ << ":" << __LINE__ << "): ").format_to(__VA_ARGS__)
#define ASYNC_VLOGEFMT(...) (ASYNC_LOGERR << "(" \
		<< __FILE__ << ":" << __LINE__ << "): ").format_to(__VA_ARGS__)
#define ASYNC_VLOGFFMT(...) (ASYNC_LOGFILE << "(" \
		<< __FILE__ << ":" << __LINE__ << "): ").format_to(__VA_ARGS__)

#define VLOG_DBG LOG_DBG << "(" << __FILE__ << ":" << __LINE__ << "): "
#define VLOG_INFO LOG_INFO << "(" << __FILE__ << ":" << __LINE__ << "): "
#define VLOG_WARN LOG_WARN << "(" << __FILE__ << ":" << __LINE__ << "): "
#define VLOG_ERR LOG_ERR << "(" << __FILE__ << ":" << __LINE__ << "): "
#define VLOG_FILE LOG_FILE << "(" << __FILE__ << ":" << __LINE__ << "): "

#define VLOG_FMT(...) (LOG_DBG << "(" \
		<< __FILE__ << ":" << __LINE__ << "): ").format_to(__VA_ARGS__)
#define VLOG_IFMT(...) (LOG_INFO << "(" \
		<< __FILE__ << ":" << __LINE__ << "): ").format_to(__VA_ARGS__)
#define VLOG_WFMT(...) (LOG_WARN << "(" \
		<< __FILE__ << ":" << __LINE__ << "): ").format_to(__VA_ARGS__)
#define VLOG_EFMT(...) (LOG_ERR << "(" \
		<< __FILE__ << ":" << __LINE__ << "): ").format_to(__VA_ARGS__)
#define VLOG_FFMT(...) (LOG_FILE << "(" \
		<< __FILE__ << ":" << __LINE__ << "): ").format_to(__VA_ARGS__)


#define INIT_ASYNC_LOGGING() [[maybe_unused]] \
		util::auto_init_async_logger ____init_logger____

#else

#define LOG_DBG util::empty_logger___()
#define LOG_INFO util::empty_logger___()
#define LOG_WARN util::empty_logger___()
#define LOG_ERR util::empty_logger___()
#define LOG_FILE util::empty_logger___()

#define LOG_FMT(...) util::empty_logger___()
#define LOG_IFMT(...) util::empty_logger___()
#define LOG_WFMT(...) util::empty_logger___()
#define LOG_EFMT(...) util::empty_logger___()
#define LOG_FFMT(...) util::empty_logger___()

#define VLOG_DBG(...) util::empty_logger___()
#define VLOG_INFO(...) util::empty_logger___()
#define VLOG_WARN(...) util::empty_logger___()
#define VLOG_ERR(...) util::empty_logger___()
#define VLOG_FILE(...) util::empty_logger___()

#define VLOG_FMT(...) util::empty_logger___()
#define VLOG_IFMT(...) util::empty_logger___()
#define VLOG_WFMT(...) util::empty_logger___()
#define VLOG_EFMT(...) util::empty_logger___()
#define VLOG_FFMT(...) util::empty_logger___()

#define ASYNC_LOGDBG util::empty_logger___()
#define ASYNC_LOGINFO util::empty_logger___()
#define ASYNC_LOGWARN util::empty_logger___()
#define ASYNC_LOGERR util::empty_logger___()
#define ASYNC_LOGFILE util::empty_logger___()

#define ASYNC_LOGFMT(...) util::empty_logger___()
#define ASYNC_LOGIFMT(...) util::empty_logger___()
#define ASYNC_LOGWFMT(...) util::empty_logger___()
#define ASYNC_LOGEFMT(...) util::empty_logger___()
#define ASYNC_LOGFFMT(...) util::empty_logger___()

#define ASYNC_VLOGDBG LOG_DBG
#define ASYNC_VLOGINFO LOG_INFO
#define ASYNC_VLOGWARN LOG_WARN
#define ASYNC_VLOGERR LOG_ERR
#define ASYNC_VLOGFILE LOG_FILE

#define ASYNC_VLOGFMT LOG_FMT
#define ASYNC_VLOGIFMT LOG_IFMT
#define ASYNC_VLOGWFMT LOG_WFMT
#define ASYNC_VLOGEFMT LOG_EFMT
#define ASYNC_VLOGFFMT LOG_FFMT

#define INIT_ASYNC_LOGGING() void

#endif

