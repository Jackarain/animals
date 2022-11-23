//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "utils/misc.hpp"
#include "utils/logging.hpp"
#include "utils/scoped_exit.hpp"

#include <iostream>
#include <iterator>
#include <algorithm>
#include <random>

#ifdef __linux__

#	include <unistd.h>
#	include <sys/prctl.h>
#	include <sys/resource.h>

#	include <sys/types.h>
#	include <pwd.h>

#elif __APPLE__

#	include <sys/types.h>
#	include <unistd.h>
#	include <sys/types.h>
#	include <pwd.h>

#elif _WIN32

#	include <fcntl.h>
#	include <io.h>

#	include <windows.h>
#	include <shlwapi.h>
#	include <ntsecapi.h>

#	include <ws2tcpip.h>
#	include <iphlpapi.h>
#	include <setupapi.h>
// #	include <winternl.h>

#	include <cfgmgr32.h>
#	include <devguid.h>

#	include <shellapi.h>
#	include <ipexport.h>
#	include <sddl.h>
#	include <winefs.h>

#	pragma comment(lib, "Ws2_32.lib")
#	pragma comment(lib, "Iphlpapi.lib")
#	pragma comment(lib, "Shlwapi.lib")
#	pragma comment(lib, "Setupapi.lib")


#endif

#include <boost/algorithm/string.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/format.hpp>
#include <boost/algorithm/string/regex.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <boost/date_time/c_local_time_adjustor.hpp>

#ifdef _MSC_VER
#	pragma warning(disable: 4191)
#endif // _MSC_VER

namespace fs = std::filesystem;

//////////////////////////////////////////////////////////////////////////

inline bool is_space(const char c)
{
	if (c == ' ' ||
		c == '\f' ||
		c == '\n' ||
		c == '\r' ||
		c == '\t' ||
		c == '\v')
		return true;
	return false;
}

std::string_view string_trim(std::string_view sv)
{
	const char* b = sv.data();
	const char* e = b + sv.size();

	for (; b != e; b++)
	{
		if (!is_space(*b))
			break;
	}

	for (; e != b; )
	{
		if (!is_space(*(--e)))
		{
			++e;
			break;
		}
	}

	return std::string_view(b, e - b);
}

std::string_view string_trim_left(std::string_view sv)
{
	const char* b = sv.data();
	const char* e = b + sv.size();

	for (; b != e; b++)
	{
		if (!is_space(*b))
			break;
	}

	return std::string_view(b, e - b);
}

std::string_view string_trim_right(std::string_view sv)
{
	const char* b = sv.data();
	const char* e = b + sv.size();

	for (; e != b; )
	{
		if (!is_space(*(--e)))
		{
			++e;
			break;
		}
	}

	return std::string_view(b, e - b);
}

//////////////////////////////////////////////////////////////////////////

template <class Iterator>
std::string to_hex(Iterator it, Iterator end, std::string const& prefix)
{
	using traits = std::iterator_traits<Iterator>;
	static_assert(sizeof(typename traits::value_type) == 1, "to_hex needs byte-sized element type");

	static char const* hexdigits = "0123456789abcdef";
	size_t off = prefix.size();
	std::string hex(std::distance(it, end) * 2 + off, '0');
	hex.replace(0, off, prefix);
	for (; it != end; it++)
	{
		hex[off++] = hexdigits[(*it >> 4) & 0x0f];
		hex[off++] = hexdigits[*it & 0x0f];
	}
	return hex;
}

// template <class T> std::string to_hex(T const& data)
// {
// 	return to_hex(data.begin(), data.end(), "");
// }

std::string to_hex(std::string_view data)
{
	return to_hex(data.begin(), data.end(), "");
}

std::string to_hex_prefixed(std::string_view data)
{
	return to_hex(data.begin(), data.end(), "0x");
}

char from_hex_char(char c) noexcept
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

bool from_hexstring(std::string_view src, std::vector<uint8_t>& result)
{
	unsigned s = (src.size() >= 2 && src[0] == '0' && src[1] == 'x') ? 2 : 0;
	result.reserve((src.size() - s + 1) / 2);

	if (src.size() % 2)
	{
		auto h = from_hex_char(src[s++]);
		if (h != static_cast<char>(-1))
			result.push_back(h);
		else
			return false;
	}
	for (unsigned i = s; i < src.size(); i += 2)
	{
		int h = from_hex_char(src[i]);
		int l = from_hex_char(src[i + 1]);

		if (h != -1 && l != -1)
		{
			result.push_back((uint8_t)(h * 16 + l));
			continue;
		}
		return false;
	}

	return true;
}

bool is_hexstring(std::string const& src) noexcept
{
	auto it = src.begin();
	if (src.compare(0, 2, "0x") == 0)
		it += 2;
	return std::all_of(it, src.end(),
		[](char c) { return from_hex_char(c) != static_cast<char>(-1); });
}

std::string to_string(std::vector<uint8_t> const& data)
{
	return std::string((char const*)data.data(), (char const*)(data.data() + data.size()));
}

std::string to_string(const boost::posix_time::ptime& t)
{
	if (t.is_not_a_date_time())
		return "";

	return boost::posix_time::to_iso_extended_string(t);
}

std::string to_string(float v, int width, int precision /*= 3*/)
{
	char buf[20] = { 0 };
	std::sprintf(buf, "%*.*f", width, precision, v);
	return std::string(buf);
}

bool valid_utf(unsigned char* string, int length)
{
	static const unsigned char utf8_table[] =
	{
	  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	  2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
	  3,3,3,3,3,3,3,3,4,4,4,4,5,5,5,5
	};

	unsigned char* p;

	if (length < 0)
	{
		for (p = string; *p != 0; p++);
		length = (int)(p - string);
	}

	for (p = string; length-- > 0; p++)
	{
		unsigned char ab, c, d;

		c = *p;
		if (c < 128) continue;                /* ASCII character */

		if (c < 0xc0)                         /* Isolated 10xx xxxx byte */
			return false;

		if (c >= 0xfe)                        /* Invalid 0xfe or 0xff bytes */
			return false;

		ab = utf8_table[c & 0x3f];            /* Number of additional bytes */
		if (length < ab)
			return false;
		length -= ab;                         /* Length remaining */

		/* Check top bits in the second byte */
		if (((d = *(++p)) & 0xc0) != 0x80)
			return false;

		/* For each length, check that the remaining bytes start with the 0x80 bit
		   set and not the 0x40 bit. Then check for an overlong sequence, and for the
		   excluded range 0xd800 to 0xdfff. */
		switch (ab)
		{
			/* 2-byte character. No further bytes to check for 0x80. Check first byte
			   for for xx00 000x (overlong sequence). */
		case 1:
			if ((c & 0x3e) == 0)
				return false;
			break;
		case 2:
			if ((*(++p) & 0xc0) != 0x80)     /* Third byte */
				return false;
			if (c == 0xe0 && (d & 0x20) == 0)
				return false;
			if (c == 0xed && d >= 0xa0)
				return false;
			break;

			/* 4-byte character. Check 3rd and 4th bytes for 0x80. Then check first 2
			   bytes for for 1111 0000, xx00 xxxx (overlong sequence), then check for a
			   character greater than 0x0010ffff (f4 8f bf bf) */
		case 3:
			if ((*(++p) & 0xc0) != 0x80)     /* Third byte */
				return false;
			if ((*(++p) & 0xc0) != 0x80)     /* Fourth byte */
				return false;
			if (c == 0xf0 && (d & 0x30) == 0)
				return false;
			if (c > 0xf4 || (c == 0xf4 && d > 0x8f))
				return false;
			break;

			/* 5-byte and 6-byte characters are not allowed by RFC 3629, and will be
			   rejected by the length test below. However, we do the appropriate tests
			   here so that overlong sequences get diagnosed, and also in case there is
			   ever an option for handling these larger code points. */

			   /* 5-byte character. Check 3rd, 4th, and 5th bytes for 0x80. Then check for
				  1111 1000, xx00 0xxx */
		case 4:
			if ((*(++p) & 0xc0) != 0x80)     /* Third byte */
				return false;
			if ((*(++p) & 0xc0) != 0x80)     /* Fourth byte */
				return false;
			if ((*(++p) & 0xc0) != 0x80)     /* Fifth byte */
				return false;
			if (c == 0xf8 && (d & 0x38) == 0)
				return false;
			break;

			/* 6-byte character. Check 3rd-6th bytes for 0x80. Then check for
			   1111 1100, xx00 00xx. */
		case 5:
			if ((*(++p) & 0xc0) != 0x80)     /* Third byte */
				return false;
			if ((*(++p) & 0xc0) != 0x80)     /* Fourth byte */
				return false;
			if ((*(++p) & 0xc0) != 0x80)     /* Fifth byte */
				return false;
			if ((*(++p) & 0xc0) != 0x80)     /* Sixth byte */
				return false;
			if (c == 0xfc && (d & 0x3c) == 0)
				return false;
			break;
		}

		/* Character is valid under RFC 2279, but 4-byte and 5-byte characters are
		   excluded by RFC 3629. The pointer p is currently at the last byte of the
		   character. */
		if (ab > 3)
			return false;
	}

	return true;
}


//////////////////////////////////////////////////////////////////////////
static const char* base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const int8_t base58_map[256] =
{
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
	-1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
	22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
	-1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
	47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
};

std::string base58_decode(std::string_view input)
{
	auto psz = input.data();
	// Skip leading spaces.
	while (*psz && *psz == ' ')
		psz++;
	// Skip and count leading '1's.
	int zeroes = 0;
	int length = 0;
	while (*psz == '1') {
		zeroes++;
		psz++;
	}
	// Allocate enough space in big-endian base256 representation.
	auto size = strlen(psz) * 733 / 1000 + 1; // log(58) / log(256), rounded up.
	std::vector<uint8_t> bin256(size, 0);
	// Process the characters.
	static_assert(sizeof(base58_map) / sizeof(base58_map[0]) == 256,
		"mapBase58.size() should be 256"); // guarantee not out of range
	while (*psz && !(*psz == ' ')) {
		// Decode base58 character
		int carry = base58_map[(uint8_t)*psz];
		if (carry == -1)  // Invalid b58 character
			return {};
		int i = 0;
		for (std::vector<unsigned char>::reverse_iterator it =
			bin256.rbegin(); (carry != 0 || i < length) && (it != bin256.rend());
			++it, ++i) {
			carry += 58 * (*it);
			*it = carry % 256;
			carry /= 256;
		}
		assert(carry == 0);
		length = i;
		psz++;
	}
	// Skip trailing spaces.
	while ((*psz == ' '))
		psz++;
	if (*psz != 0)
		return {};

	return to_hex({ (char*)bin256.data(), bin256.size() });
}

std::string base58_encode(std::string_view input)
{
	// Skip & count leading zeroes.
	int zeroes = 0;
	int length = 0;
	while (input.size() > 0 && input[0] == 0) {
		input = input.substr(1);
		zeroes++;
	}
	// Allocate enough space in big-endian base58 representation.
	auto size = input.size() * 138 / 100 + 1; // log(256) / log(58), rounded up.
	std::vector<unsigned char> b58(size);
	// Process the bytes.
	while (input.size() > 0) {
		int carry = (unsigned char)input[0];
		int i = 0;
		// Apply "b58 = b58 * 256 + ch".
		for (auto it = b58.rbegin();
			(carry != 0 || i < length) && (it != b58.rend());
			it++, i++)
		{
			carry += 256 * (*it);
			*it = carry % 58;
			carry /= 58;
		}
		assert(carry == 0);
		length = i;
		input = input.substr(1);
	}
	// Skip leading zeroes in base58 result.
	auto it = b58.begin() + (size - length);
	while (it != b58.end() && *it == 0)
		it++;
	// Translate the result into a string.
	std::string str;
	str.reserve(zeroes + (b58.end() - it));
	str.assign(zeroes, '1');
	while (it != b58.end())
		str += base58_chars[*(it++)];
	return str;
}

//////////////////////////////////////////////////////////////////////////

bool unescape_path(const std::string& in, std::string& out)
{
	out.clear();
	out.reserve(in.size());
	for (std::size_t i = 0; i < in.size(); ++i)
	{
		switch (in[i])
		{
		case '%':
			if (i + 3 <= in.size())
			{
				unsigned int value = 0;
				for (std::size_t j = i + 1; j < i + 3; ++j)
				{
					switch (in[j])
					{
					case '0': case '1': case '2': case '3': case '4':
					case '5': case '6': case '7': case '8': case '9':
						value += in[j] - '0';
						break;
					case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
						value += in[j] - 'a' + 10;
						break;
					case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
						value += in[j] - 'A' + 10;
						break;
					default:
						return false;
					}
					if (j == i + 1)
						value <<= 4;
				}
				out += static_cast<char>(value);
				i += 2;
			}
			else
				return false;
			break;
		case '+':
			out += ' ';
			break;
		case '-': case '_': case '.': case '!': case '~': case '*':
		case '\'': case '(': case ')': case ':': case '@': case '&':
		case '=': case '$': case ',': case '/': case ';':
			out += in[i];
			break;
		default:
			if (!std::isalnum((unsigned char)in[i]))
				return false;
			out += in[i];
			break;
		}
	}
	return true;
}

std::string add_suffix(float val, char const* suffix /*= nullptr*/)
{
	std::string ret;

	const char* prefix[] = { "kB", "MB", "GB", "TB" };
	for (auto& i : prefix)
	{
		val /= 1024.f;
		if (std::fabs(val) < 1024.f)
		{
			ret = to_string(val, 4);
			ret += i;
			if (suffix) ret += suffix;
			return ret;
		}
	}
	ret = to_string(val, 4);
	ret += "PB";
	if (suffix) ret += suffix;
	return ret;
}


//////////////////////////////////////////////////////////////////////////

inline std::string uuid_to_string(boost::uuids::uuid const& u)
{
	std::string result;
	result.reserve(36);

	std::size_t i = 0;
	boost::uuids::uuid::const_iterator it_data = u.begin();
	for (; it_data != u.end(); ++it_data, ++i)
	{
		const size_t hi = ((*it_data) >> 4) & 0x0F;
		result += boost::uuids::detail::to_char(hi);

		const size_t lo = (*it_data) & 0x0F;
		result += boost::uuids::detail::to_char(lo);
	}
	return result;
}

int gen_random_int(int start, int end)
{
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(start, end);

	return dis(gen);
}

std::string gen_unique_string(const unsigned int len)
{
	static const char acsii_table[] = {
		'a', 'b', 'c', 'd', 'e',
		'f', 'g', 'h', 'i', 'j',
		'k', 'l', 'm', 'n', 'o',
		'p', 'q', 'r', 's', 't',
		'u', 'v', 'w', 'x', 'y',
		'z', '1', '2', '3', '4',
		'5', '6', '7', '8', '9',
		'0'
	};
	static const int table_len = sizeof(acsii_table) / sizeof(char);

	std::string str;
	for (unsigned int i = 0; i < len; i++) {

		int index = gen_random_int(0, table_len - 1);
		str.append(1, acsii_table[index]);
	}

	return str;
}

uint32_t gen_unique_number()
{
	static std::atomic_uint32_t base = static_cast<uint32_t>(
		std::chrono::duration_cast<std::chrono::microseconds>(
			std::chrono::system_clock::now().time_since_epoch()).count());
	return base++;
}

std::string gen_uuid()
{
	boost::uuids::uuid guid = boost::uuids::random_generator()();
	return uuid_to_string(guid);
}

//////////////////////////////////////////////////////////////////////////

#ifdef WIN32

inline void utf8_utf16(const std::string& utf8, std::wstring& utf16)
{
	auto len = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, NULL, 0);
	if (len > 0)
	{
		wchar_t* tmp = (wchar_t*)malloc(sizeof(wchar_t) * len);
		MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, tmp, len);
		utf16.assign(tmp);
		free(tmp);
	}
}

inline void utf16_utf8(const std::wstring& utf16, std::string& utf8)
{
	auto len = WideCharToMultiByte(CP_UTF8, 0, utf16.c_str(), -1, NULL, 0, 0, 0);
	if (len > 0)
	{
		char* tmp = (char*)malloc(sizeof(char) * len);
		WideCharToMultiByte(CP_UTF8, 0, utf16.c_str(), -1, tmp, len, 0, 0);
		utf8.assign(tmp);
		free(tmp);
	}
}

std::string utf8_from_astring(const std::string& str)
{
	wchar_t* wstring;
	int char_count;

	// convert "ANSI code page" string to UTF-16.
	char_count = MultiByteToWideChar(CP_ACP, 0, str.c_str(), (int)str.size(), NULL, 0);
	std::string result(char_count * sizeof(wchar_t) * 10, 0);
	wstring = (wchar_t*)(result.data() + (char_count * sizeof(wchar_t) * 5));
	MultiByteToWideChar(CP_ACP, 0, str.c_str(), (int)str.size(), wstring, char_count);

	// convert UTF-16 to MAME string (UTF-8).
	char_count = WideCharToMultiByte(CP_UTF8, 0, wstring, char_count, NULL, 0, NULL, NULL);
	WideCharToMultiByte(CP_UTF8, 0, wstring, char_count, (char*)result.data(), char_count, NULL, NULL);
	result.resize(char_count);

	return result;
}

inline std::string error_format(DWORD err)
{
	// Retrieve the system error message for the last-error code
	LPVOID lpMsgBuf;

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		err,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	// Display the error message and exit the process.
	std::string error_msg;
#ifdef UNICODE
	std::wstring tmp((LPTSTR)lpMsgBuf);
	utf16_utf8(tmp, error_msg);
#else
	error_msg.assign((char*)lpMsgBuf);
#endif // UNICODE

	LocalFree(lpMsgBuf);
	boost::trim(error_msg);

	return error_msg;
}

uint64_t get_process_id()
{
	return GetCurrentProcessId();
}

//////////////////////////////////////////////////////////////////////////

#if defined(__MINGW32__)  /* Rest of file */
/*
 * These are 'static __inline' function in MinGW.org's <ws2tcpip.h>.
 * But in other MinGW distribution they are not. In any case they are part
 * of 'libws2_32.a' even though 'gai_strerror[A|W]' is not part of the
 * system 'ws2_32.dll'. So for 'libwsock_trace.a' to be a replacement for
 * 'libws2_32.a', we must also add these functions to it.
 *
 * But tracing these calls would be difficult since the needed functions
 * for that is in wsock_trace.c.
 */
#define FORMAT_FLAGS (FORMAT_MESSAGE_FROM_SYSTEM    | \
                      FORMAT_MESSAGE_IGNORE_INSERTS | \
                      FORMAT_MESSAGE_MAX_WIDTH_MASK)

#undef gai_strerrorA
#undef gai_strerrorW

#define DIM(x)          (int) (sizeof(x) / sizeof((x)[0]))

 /*
  * These are also in common.c. But since this module is not part of
  * the wsock_trace_mw.dll (only added to libwsock_trace.a), these
  * function must also be here.
  */
char* str_rip(char* s)
{
	char* p;

	if ((p = strrchr(s, '\n')) != NULL) *p = '\0';
	if ((p = strrchr(s, '\r')) != NULL) *p = '\0';
	return (s);
}

wchar_t* str_ripw(wchar_t* s)
{
	wchar_t* p;

	if ((p = wcsrchr(s, L'\n')) != NULL) *p = L'\0';
	if ((p = wcsrchr(s, L'\r')) != NULL) *p = L'\0';
	return (s);
}


char* gai_strerrorA(int err)
{
	static char err_buf[512];

	err_buf[0] = '\0';
	FormatMessageA(FORMAT_FLAGS, NULL, err, LANG_NEUTRAL,
		err_buf, sizeof(err_buf) - 1, NULL);
	return str_rip(err_buf);
}

wchar_t* gai_strerrorW(int err)
{
	static wchar_t err_buf[512];

	err_buf[0] = L'\0';
	FormatMessageW(FORMAT_FLAGS, NULL, err, LANG_NEUTRAL,
		err_buf, DIM(err_buf) - 1, NULL);
	return str_ripw(err_buf);
}

#endif  /* __MINGW32__ */



const DWORD MS_VC_EXCEPTION = 0x406D1388;

#pragma pack(push,8)
typedef struct tagTHREADNAME_INFO
{
	DWORD dwType; // Must be 0x1000.
	LPCSTR szName; // Pointer to name (in user addr space).
	DWORD dwThreadID; // Thread ID (-1=caller thread).
	DWORD dwFlags; // Reserved for future use, must be zero.
} THREADNAME_INFO;
#pragma pack(pop)

void SetThreadName(uint32_t dwThreadID, const char* threadName)
{
#if __MINGW32__
	(void)dwThreadID;
	(void)threadName;
#else
	THREADNAME_INFO info;
	info.dwType = 0x1000;
	info.szName = threadName;
	info.dwThreadID = dwThreadID;
	info.dwFlags = 0;

	__try
	{
		RaiseException(MS_VC_EXCEPTION, 0, sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR*)&info);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{}
#endif
}

void set_thread_name(const char* name)
{
	SetThreadName(GetCurrentThreadId(), name);
}

void set_thread_name(std::thread* thread, const char* name)
{
	DWORD threadId = ::GetThreadId((HANDLE)(thread->native_handle()));
	SetThreadName(threadId, name);
}

#elif __linux__

uint64_t get_process_id()
{
	return (uint64_t)getpid();
}

void set_thread_name(std::thread* thread, const char* name)
{
	auto handle = thread->native_handle();
	pthread_setname_np(handle, name);
}

void set_thread_name(const char* name)
{
	prctl(PR_SET_NAME, name, 0, 0, 0);
}


#elif defined(__APPLE__)

uint64_t get_process_id()
{
	return (uint64_t)getpid();
}

void set_thread_name(std::thread*, const char*)
{
}

void set_thread_name(const char*/* name*/)
{
}


#elif defined(__OpenBSD__)

uint64_t get_process_id()
{
	return (uint64_t)getpid();
}

void set_thread_name(std::thread* thread, const char* name)
{
	auto handle = thread->native_handle();
	pthread_set_name_np(handle, name);
}

void set_thread_name(const char*/* name*/)
{
}

#else

uint64_t get_process_id()
{
	return (uint64_t)getpid();
}

void set_thread_name(std::thread*, const char*)
{
}

void set_thread_name(const char*/* name*/)
{
}

#endif


//////////////////////////////////////////////////////////////////////////

bool parse_endpoint_string(std::string_view str,
	std::string& host, std::string& port, bool& ipv6only)
{
	ipv6only = false;

	auto address_string = string_trim(str);
	auto it = address_string.begin();

	bool is_ipv6_address = *it == '[';
	if (is_ipv6_address)
	{
		auto host_end = std::find(it, address_string.end(), ']');
		if (host_end == address_string.end())
			return false;

		it++;
		for (auto first = it; first != host_end; first++)
			host.push_back(*first);

		std::advance(it, host_end - it);
		it++;
	}
	else
	{
		auto host_end = std::find(it, address_string.end(), ':');
		if (host_end == address_string.end())
			return false;

		for (auto first = it; first != host_end; first++)
			host.push_back(*first);

		// Skip host.
		std::advance(it, host_end - it);
	}

	if (*it != ':')
		return false;

	it++;
	for (; it != address_string.end(); it++)
	{
		if (*it >= '0' && *it <= '9')
		{
			port.push_back(*it);
			continue;
		}

		break;
	}

	if (it != address_string.end())
	{
#ifdef __cpp_lib_to_address
		auto opt = std::string_view(std::to_address(it), address_string.end() - it);
#else
		auto opt = std::string(it, address_string.end());
#endif
		if (opt == "ipv6only" || opt == "-ipv6only")
			ipv6only = true;
	}

	return true;
}

// 解析下列用于listen格式的endpoint
// [::]:443
// [::1]:443
// [::0]:443
// 0.0.0.0:443
bool make_listen_endpoint(const std::string& address, tcp::endpoint& endp, boost::system::error_code& ec)
{
	std::string host, port;
	bool ipv6only = false;
	if (!parse_endpoint_string(address, host, port, ipv6only))
	{
		ec.assign(boost::system::errc::bad_address, boost::system::generic_category());
		return ipv6only;
	}

	if (host.empty() || port.empty())
	{
		ec.assign(boost::system::errc::bad_address, boost::system::generic_category());
		return ipv6only;
	}

	endp.address(boost::asio::ip::address::from_string(host, ec));
	endp.port(static_cast<unsigned short>(std::atoi(port.data())));

	return ipv6only;
}

bool make_listen_endpoint(const std::string& address, udp::endpoint& endp, boost::system::error_code& ec)
{
	std::string host, port;
	bool ipv6only = false;
	if (!parse_endpoint_string(address, host, port, ipv6only))
	{
		ec.assign(boost::system::errc::bad_address, boost::system::generic_category());
		return ipv6only;
	}

	if (host.empty() || port.empty())
	{
		ec.assign(boost::system::errc::bad_address, boost::system::generic_category());
		return ipv6only;
	}

	endp.address(boost::asio::ip::address::from_string(host, ec));
	endp.port(static_cast<unsigned short>(std::atoi(port.data())));

	return ipv6only;
}
