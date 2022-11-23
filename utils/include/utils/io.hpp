//
// io.hpp
// ~~~~~~
//
// Copyright (c) 2013 Jack (jack dot wgm at gmail dot com)
// Copyright (c) 2003, Arvid Norberg
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#include <string>
#include <algorithm>
#include <cassert>

namespace stream_endian {

	//////////////////////////////////////////////////////////////////////////

	template <class T> struct type {};

	// reads an integer from a byte stream in big endian byte order and converts
	// it to native endianess
	template <class T, class InIt>
	inline T read_impl(InIt& start, type<T>)
	{
		T ret = 0;
		for (int i = 0; i < (int)sizeof(T); ++i)
		{
			ret <<= 8;
			ret |= static_cast<uint8_t>(*start);
			++start;
		}
		return ret;
	}

	template <class InIt>
	uint8_t read_impl(InIt& start, type<uint8_t>)
	{
		return static_cast<uint8_t>(*start++);
	}

	template <class InIt>
	int8_t read_impl(InIt& start, type<int8_t>)
	{
		return static_cast<int8_t>(*start++);
	}

	template <class T, class OutIt>
	inline void write_impl(T val, OutIt& start)
	{
		for (int i = (int)sizeof(T)-1; i >= 0; --i)
		{
			*start = static_cast<uint8_t>((val >> (i * 8)) & 0xff);
			++start;
		}
	}

	// -- adaptors

	template <class InIt>
	int64_t read_int64(InIt& start)
	{ return read_impl(start, type<int64_t>()); }

	template <class InIt>
	uint64_t read_uint64(InIt& start)
	{ return read_impl(start, type<uint64_t>()); }

	template <class InIt>
	uint32_t read_uint32(InIt& start)
	{ return read_impl(start, type<uint32_t>()); }

	template <class InIt>
	int32_t read_int32(InIt& start)
	{ return read_impl(start, type<int32_t>()); }

	template <class InIt>
	int16_t read_int16(InIt& start)
	{ return read_impl(start, type<int16_t>()); }

	template <class InIt>
	uint16_t read_uint16(InIt& start)
	{ return read_impl(start, type<uint16_t>()); }

	template <class InIt>
	int8_t read_int8(InIt& start)
	{ return read_impl(start, type<int8_t>()); }

	template <class InIt>
	uint8_t read_uint8(InIt& start)
	{ return read_impl(start, type<uint8_t>()); }

	template <class OutIt>
	void write_uint64(uint64_t val, OutIt& start)
	{ write_impl(val, start); }

	template <class OutIt>
	void write_int64(int64_t val, OutIt& start)
	{ write_impl(val, start); }

	template <class OutIt>
	void write_uint32(uint32_t val, OutIt& start)
	{ write_impl(val, start); }

	template <class OutIt>
	void write_int32(int32_t val, OutIt& start)
	{ write_impl(val, start); }

	template <class OutIt>
	void write_uint16(uint16_t val, OutIt& start)
	{ write_impl(val, start); }

	template <class OutIt>
	void write_int16(int16_t val, OutIt& start)
	{ write_impl(val, start); }

	template <class OutIt>
	void write_uint8(uint8_t val, OutIt& start)
	{ write_impl(val, start); }

	template <class OutIt>
	void write_int8(int8_t val, OutIt& start)
	{ write_impl(val, start); }

	inline void write_string(std::string const& str, char*& start)
	{
		std::memcpy((void*)start, str.c_str(), str.size());
		start += str.size();
	}

	template <class OutIt>
	void write_string(std::string const& str, OutIt& start)
	{
		std::copy(str.begin(), str.end(), start);
	}

	template <class OutIt>
	inline void write_string(std::string_view sv, OutIt& start)
	{
		std::memcpy((void*)start, sv.data(), sv.size());
		start += sv.size();
	}

	//////////////////////////////////////////////////////////////////////////

	// from webrtc rtc_base/bit_buffer.{h|cc}
	class bitstream
	{
		// Returns the lowest (right-most) |bit_count| bits in |byte|.
		inline uint8_t LowestBits(uint8_t byte, size_t bit_count)
		{
			return byte & ((1 << bit_count) - 1);
		}

		// Returns the highest (left-most) |bit_count| bits in |byte|, shifted
		// to the lowest bits (to the right).
		inline uint8_t HighestBits(uint8_t byte, size_t bit_count)
		{
			uint8_t shift = 8 - static_cast<uint8_t>(bit_count);
			uint8_t mask = 0xFF << shift;
			return (byte & mask) >> shift;
		}

		// Returns the highest byte of |val| in a uint8_t.
		inline uint8_t HighestByte(uint64_t val)
		{
			return static_cast<uint8_t>(val >> 56);
		}

		// Returns the result of writing partial data from |source|, of
		// |source_bit_count| size in the highest bits, to |target| at
		// |target_bit_offset| from the highest bit.
		inline uint8_t WritePartialByte(uint8_t source,
			size_t source_bit_count,
			uint8_t target,
			size_t target_bit_offset)
		{
			uint8_t mask =
				// The number of bits we want, in the most significant bits...
				static_cast<uint8_t>(0xFF << (8 - source_bit_count))
				// ...shifted over to the target offset from the most signficant
				// bit.
				>> target_bit_offset;

			// We want the target, with the bits we'll overwrite masked off,
			// or'ed with the bits from the source we want.
			return (target & ~mask) | (source >> target_bit_offset);
		}

		// Counts the number of bits used in the binary representation of val.
		inline size_t CountBits(uint64_t val)
		{
			size_t bit_count = 0;
			while (val != 0)
			{
				bit_count++;
				val >>= 1;
			}
			return bit_count;
		}

		// c++11 noncopyable.
		bitstream(const bitstream&) = delete;
		bitstream& operator=(const bitstream&) = delete;
		bitstream() = delete;

	public:
		inline bitstream(const uint8_t* bytes, size_t byte_count)
			: bytes_(bytes)
			, byte_count_(byte_count)
			, writable_bytes_((uint8_t*)bytes)
		{}

		inline bitstream(uint8_t* bytes, size_t byte_count)
			: bytes_(bytes), byte_count_(byte_count), writable_bytes_(bytes)
		{}

		// Gets the current offset, in bytes/bits, from the start of the buffer.
		// Thebit offset is the offset into the current byte, in the range
		// [0,7].
		inline void
		GetCurrentOffset(size_t* out_byte_offset, size_t* out_bit_offset)
		{
			*out_byte_offset = byte_offset_;
			*out_bit_offset = bit_offset_;
		}

		// The remaining bits in the byte buffer.
		inline uint64_t RemainingBitCount() const
		{
			return (static_cast<uint64_t>(byte_count_) - byte_offset_) * 8
				- bit_offset_;
		}

		// Reads byte-sized values from the buffer. Returns false if there isn't
		// enough data left for the specified type.
		inline bool ReadUInt8(uint8_t* val)
		{
			uint32_t bit_val;
			if (!ReadBits(&bit_val, sizeof(uint8_t) * 8))
				return false;
			*val = static_cast<uint8_t>(bit_val);
			return true;
		}

		inline bool ReadUInt16(uint16_t* val)
		{
			uint32_t bit_val;
			if (!ReadBits(&bit_val, sizeof(uint16_t) * 8))
				return false;

			*val = static_cast<uint16_t>(bit_val);
			return true;
		}

		inline bool ReadUInt32(uint32_t* val)
		{
			return ReadBits(val, sizeof(uint32_t) * 8);
		}

		// Reads bit-sized values from the buffer. Returns false if there isn't
		// enough data left for the specified bit count..
		inline bool ReadBits(uint32_t* val, size_t bit_count)
		{
			return PeekBits(val, bit_count) && ConsumeBits(bit_count);
		}

		// Peeks bit-sized values from the buffer. Returns false if there isn't
		// enough data left for the specified number of bits. Doesn't move the
		// current offset.
		inline bool PeekBits(uint32_t* val, size_t bit_count)
		{
			if (!val || bit_count > RemainingBitCount() || bit_count > 32)
				return false;

			const uint8_t* bytes = bytes_ + byte_offset_;
			size_t remaining_bits_in_current_byte = 8 - bit_offset_;
			uint32_t bits = LowestBits(*bytes++,
				remaining_bits_in_current_byte);

			// If we're reading fewer bits than what's left in the current byte,
			// just return the portion of this byte that we need.
			if (bit_count < remaining_bits_in_current_byte)
			{
				*val = HighestBits((uint8_t)bits, bit_offset_ + bit_count);
				return true;
			}

			// Otherwise, subtract what we've read from the bit count and read
			// as many full bytes as we can into bits.
			bit_count -= remaining_bits_in_current_byte;
			while (bit_count >= 8)
			{
				bits = (bits << 8) | *bytes++;
				bit_count -= 8;
			}

			// Whatever we have left is smaller than a byte, so grab just the
			// bits we need and shift them into the lowest bits.
			if (bit_count > 0)
			{
				bits <<= bit_count;
				bits |= HighestBits(*bytes, bit_count);
			}
			*val = bits;

			return true;
		}

		// Reads the exponential golomb encoded value at the current offset.
		// Exponential golomb values are encoded as:
		// 1) x = source val + 1
		// 2) In binary, write [countbits(x) - 1] 0s, then x
		// To decode, we count the number of leading 0 bits, read that many + 1
		// bits, and increment the result by 1.
		// Returns false if there isn't enough data left for the specified type,
		// or if the value wouldn't fit in a uint32_t.
		inline bool ReadExponentialGolomb(uint32_t* val)
		{
			if (!val)
				return false;

			// Store off the current byte/bit offset, in case we want to restore
			// them due to a failed parse.
			size_t original_byte_offset = byte_offset_;
			size_t original_bit_offset = bit_offset_;

			// Count the number of leading 0 bits by peeking/consuming them one
			// at a time.
			size_t zero_bit_count = 0;
			uint32_t peeked_bit;
			while (PeekBits(&peeked_bit, 1) && peeked_bit == 0)
			{
				zero_bit_count++;
				ConsumeBits(1);
			}

			// We should either be at the end of the stream, or the next bit
			// should be 1.

			// The bit count of the value is the number of zeros + 1. Make sure
			// that many bits fits in a uint32_t and that we have enough bits
			// left for it, and then read the value.
			size_t value_bit_count = zero_bit_count + 1;
			if (value_bit_count > 32 || !ReadBits(val, value_bit_count))
			{
				Seek(original_byte_offset, original_bit_offset);
				return false;
			}
			*val -= 1;

			return true;
		}

		// Reads signed exponential golomb values at the current offset. Signed
		// exponential golomb values are just the unsigned values mapped to the
		// sequence 0, 1, -1, 2, -2, etc. in order.
		inline bool ReadSignedExponentialGolomb(int32_t* val)
		{
			uint32_t unsigned_val;
			if (!ReadExponentialGolomb(&unsigned_val))
				return false;

			if ((unsigned_val & 1) == 0)
				*val = -static_cast<int32_t>(unsigned_val / 2);
			else
				*val = (unsigned_val + 1) / 2;

			return true;
		}

		// Moves current position |byte_count| bytes forward. Returns false if
		// there aren't enough bytes left in the buffer.
		inline bool ConsumeBytes(size_t byte_count)
		{
			return ConsumeBits(byte_count * 8);
		}

		// Moves current position |bit_count| bits forward. Returns false if
		// there aren't enough bits left in the buffer.
		inline bool ConsumeBits(size_t bit_count)
		{
			if (bit_count > RemainingBitCount())
				return false;

			byte_offset_ += (bit_offset_ + bit_count) / 8;
			bit_offset_ = (bit_offset_ + bit_count) % 8;

			return true;
		}

		// Sets the current offset to the provied byte/bit offsets. The bit
		// offset is from the given byte, in the range [0,7].
		inline bool Seek(size_t byte_offset, size_t bit_offset)
		{
			if (byte_offset > byte_count_ || bit_offset > 7 ||
				(byte_offset == byte_count_ && bit_offset > 0))
				return false;

			byte_offset_ = byte_offset;
			bit_offset_ = bit_offset;

			return true;
		}

		// Writes byte-sized values from the buffer. Returns false if there
		// isn't enough data left for the specified type.
		inline bool WriteUInt8(uint8_t val)
		{
			return WriteBits(val, sizeof(uint8_t) * 8);
		}

		inline bool WriteUInt16(uint16_t val)
		{
			return WriteBits(val, sizeof(uint16_t) * 8);
		}

		inline bool WriteUInt32(uint32_t val)
		{
			return WriteBits(val, sizeof(uint32_t) * 8);
		}

		// Writes bit-sized values to the buffer. Returns false if there isn't
		// enough room left for the specified number of bits.
		inline bool WriteBits(uint64_t val, size_t bit_count)
		{
			if (bit_count > RemainingBitCount())
				return false;

			size_t total_bits = bit_count;

			// For simplicity, push the bits we want to read from val to the
			// highest bits.
			val <<= (sizeof(uint64_t) * 8 - bit_count);

			uint8_t* bytes = writable_bytes_ + byte_offset_;

			// The first byte is relatively special; the bit offset to write to
			// may put us in the middle of the byte, and the total bit count to
			// write may require we save the bits at the end of the byte.
			size_t remaining_bits_in_current_byte = 8 - bit_offset_;
			size_t bits_in_first_byte =
				std::min(bit_count, remaining_bits_in_current_byte);
			*bytes = WritePartialByte(
				HighestByte(val), bits_in_first_byte, *bytes, bit_offset_);
			if (bit_count <= remaining_bits_in_current_byte)
				return ConsumeBits(total_bits);	// Nothing left to write, so
												// quit early.

			// Subtract what we've written from the bit count, shift it off the
			// value, and write the remaining full bytes.
			val <<= bits_in_first_byte;
			bytes++;
			bit_count -= bits_in_first_byte;
			while (bit_count >= 8)
			{
				*bytes++ = HighestByte(val);
				val <<= 8;
				bit_count -= 8;
			}

			// Last byte may also be partial, so write the remaining bits from
			// the top of val.
			if (bit_count > 0)
				*bytes = WritePartialByte(HighestByte(val),
					bit_count, *bytes, 0);

			// All done! Consume the bits we've written.
			return ConsumeBits(total_bits);
		}

		// Writes the exponential golomb encoded version of the supplied value.
		// Returns false if there isn't enough room left for the value.
		inline bool WriteExponentialGolomb(uint32_t val)
		{
			// We don't support reading UINT32_MAX, because it doesn't fit in a
			// uint32_t when encoded, so don't support writing it either.
			if (val == std::numeric_limits<uint32_t>::max())
				return false;

			uint64_t val_to_encode = static_cast<uint64_t>(val) + 1;

			// We need to write CountBits(val+1) 0s and then val+1. Since val
			// (as a uint64_t) has leading zeros, we can just write the total
			// golomb encoded size worth of bits, knowing the value will appear
			// last.
			return WriteBits(val_to_encode, CountBits(val_to_encode) * 2 - 1);
		}

		// Writes the signed exponential golomb version of the supplied value.
		// Signed exponential golomb values are just the unsigned values mapped
		// to the sequence 0, 1, -1, 2, -2, etc. in order.
		inline bool WriteSignedExponentialGolomb(int32_t val)
		{
			if (val == 0)
				return WriteExponentialGolomb(0);

			if (val > 0)
			{
				uint32_t signed_val = val;
				return WriteExponentialGolomb((signed_val * 2) - 1);
			}

			if (val == std::numeric_limits<int32_t>::min())
				return false;  // Not supported, would cause overflow.

			uint32_t signed_val = -val;
			return WriteExponentialGolomb(signed_val * 2);
		}

		inline bool WriteTail()
		{
			size_t byte_offset;
			size_t bit_offset;
			GetCurrentOffset(&byte_offset, &bit_offset);

			if (bit_offset > 0)
			{
				if (!WriteBits(0, 8 - bit_offset))
					return false;

				GetCurrentOffset(&byte_offset, &bit_offset);
				if (bit_offset != 0)
					return false;
			}

			return true;
		}

		inline bool ReadTail()
		{
			size_t byte_offset;
			size_t bit_offset;
			GetCurrentOffset(&byte_offset, &bit_offset);

			if (bit_offset > 0)
			{
				uint32_t tmp = 0;
				if (!ReadBits(&tmp, 8 - bit_offset))
					return false;

				GetCurrentOffset(&byte_offset, &bit_offset);
				if (bit_offset != 0)
					return false;
			}

			return true;
		}

		inline bool WriteString(const char* str, size_t size)
		{
			if (!WriteTail())
				return false;

			auto remainder = RemainingBitCount() / 8;
			if (size > remainder)
				return false;

			uint8_t* bytes = writable_bytes_ + byte_offset_;
			std::memcpy((void*)bytes, (const void*)str, size);
			byte_offset_ += size;

			return true;
		}

		inline bool ReadString(char* str, size_t size)
		{
			if (!ReadTail())
				return false;

			auto remainder = RemainingBitCount() / 8;
			if (size > remainder)
				return false;

			const uint8_t* bytes = bytes_ + byte_offset_;
			std::memcpy((void*)str, (const void*)bytes, size);
			byte_offset_ += size;

			return true;
		}

		// 2Bit	Length	Usable Bits	Range
		// 00	1	6	0-63
		// 01	2	14	0-16383
		// 10	4	30	0-1073741823
		// 11	8	62	0-4611686018427387903
		inline bool WriteVariantInt(uint64_t val, uint64_t expand = 0)
		{
			if (!WriteTail())
				return false;

			auto remainder = RemainingBitCount() / 8;
			if (remainder < 1)
				return false;

			if (expand == 0)
				expand = val;
			uint8_t* bytes = writable_bytes_ + byte_offset_;

			if (expand < 64)
			{
				*bytes = static_cast<uint8_t>(val);
				byte_offset_ += 1;
			}
			else if (expand < 16384)
			{
				if (remainder < 2)
					return false;

				*(bytes + 0) = static_cast<uint8_t>((val >> 8) & 0xff);
				*(bytes + 1) = static_cast<uint8_t>((val >> 0) & 0xff);
				*bytes |= 0x40;

				byte_offset_ += 2;
			}
			else if (expand < 1073741824)
			{
				if (remainder < 4)
					return false;

				*(bytes + 0) = static_cast<uint8_t>((val >> 24) & 0xff);
				*(bytes + 1) = static_cast<uint8_t>((val >> 16) & 0xff);
				*(bytes + 2) = static_cast<uint8_t>((val >>  8) & 0xff);
				*(bytes + 3) = static_cast<uint8_t>((val >>  0) & 0xff);
				*bytes |= 0x80;

				byte_offset_ += 4;
			}
			else
			{
				if (remainder < 8)
					return false;

				assert(val < 4611686018427387904ULL);

				*(bytes + 0) = static_cast<uint8_t>((val >> 56) & 0xff);
				*(bytes + 1) = static_cast<uint8_t>((val >> 48) & 0xff);
				*(bytes + 2) = static_cast<uint8_t>((val >> 40) & 0xff);
				*(bytes + 3) = static_cast<uint8_t>((val >> 32) & 0xff);
				*(bytes + 4) = static_cast<uint8_t>((val >> 24) & 0xff);
				*(bytes + 5) = static_cast<uint8_t>((val >> 16) & 0xff);
				*(bytes + 6) = static_cast<uint8_t>((val >>  8) & 0xff);
				*(bytes + 7) = static_cast<uint8_t>((val >>  0) & 0xff);

				*bytes |= 0xc0;

				byte_offset_ += 8;
			}

			return true;
		}

		// 2Bit	Length	Usable Bits	Range
		// 00	1	6	0-63
		// 01	2	14	0-16383
		// 10	4	30	0-1073741823
		// 11	8	62	0-4611686018427387903
		inline bool ReadVariantInt(uint64_t& val)
		{
			if (!ReadTail())
				return false;

			auto remainder = RemainingBitCount() / 8;
			if (remainder < 1)
				return false;

			const uint8_t* bytes = bytes_ + byte_offset_;
			auto len = static_cast<size_t>((uint8_t)(1u << (*bytes >> 6)));
			assert(len <= 8);

			if (remainder < len)
				return false;

			val = static_cast<uint8_t>(*bytes++ & 0x3f);

			for (size_t n = 1; n < len; n++)
			{
				val <<= 8;
				val |= static_cast<uint8_t>(*bytes++);
			}

			byte_offset_ += len;

			return true;
		}

		inline size_t ByteOffset() const
		{
			return byte_offset_;
		}

		inline size_t BitOffset() const
		{
			return bit_offset_;
		}

		inline const uint8_t* GetOriginPtr() const
		{
			return bytes_;
		}

		inline void Reset(uint8_t* bytes, size_t byte_count)
		{
			bytes_ = (const uint8_t*)bytes;
			writable_bytes_ = bytes;

			byte_count_ = byte_count;
			byte_offset_ = 0;
			bit_offset_ = 0;
		}

		inline size_t AllSize() const
		{
			return byte_count_;
		}

	protected:
		const uint8_t* bytes_;
		// The total size of |bytes_|.
		size_t byte_count_;
		// The current offset, in bytes, from the start of |bytes_|.
		size_t byte_offset_{ 0 };
		// The current offset, in bits, into the current byte.
		size_t bit_offset_{ 0 };
		// The buffer, as a writable array.
		uint8_t* writable_bytes_{ nullptr };
	};


#if defined(___STREAM_ENDIAN_TEST___)
	uint8_t golomb_bits[256] = { 0 };
	stream_endian::bitstream writer(golomb_bits, 256);
	writer.WriteExponentialGolomb(6);
	writer.WriteExponentialGolomb(1420);
	writer.WriteExponentialGolomb(10000);
	writer.WriteExponentialGolomb(50);
	writer.WriteExponentialGolomb(30);
	writer.WriteExponentialGolomb(20);
	writer.WriteExponentialGolomb(4500);

	size_t byte_offset;
	size_t bit_offset;
	writer.GetCurrentOffset(&byte_offset, &bit_offset);

	if (bit_offset > 0)
	{
		writer.WriteBits(0, 8 - bit_offset);
		writer.GetCurrentOffset(&byte_offset, &bit_offset);
	}

	stream_endian::bitstream reader(golomb_bits, 256);
	uint32_t out = 0;
	reader.ReadExponentialGolomb(&out);
	assert(out == 6);
	reader.ReadExponentialGolomb(&out);
	assert(out == 1420);
	reader.ReadExponentialGolomb(&out);
	assert(out == 10000);
	reader.ReadExponentialGolomb(&out);
	assert(out == 50);
	reader.ReadExponentialGolomb(&out);
	assert(out == 30);
	reader.ReadExponentialGolomb(&out);
	assert(out == 20);
	reader.ReadExponentialGolomb(&out);
	assert(out == 4500);
#endif
}
