//
// asio_util.hpp
// ~~~~~~~~~~~~~~
//
// Copyright (c) 2019 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#include <boost/type_traits.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>


namespace asio_util {
	namespace net = boost::asio;

	//////////////////////////////////////////////////////////////////////////

	inline size_t default_max_transfer_size = 1024 * 1024;

	class transfer_at_least_t
	{
	public:
		typedef std::size_t result_type;

		explicit transfer_at_least_t(std::size_t minimum)
			: minimum_(minimum)
		{
		}

		template <typename Error>
		std::size_t operator()(const Error& err, std::size_t bytes_transferred)
		{
			return (!!err || bytes_transferred >= minimum_)
				? 0 : default_max_transfer_size;
		}

	private:
		std::size_t minimum_;
	};

	inline transfer_at_least_t transfer_at_least(std::size_t minimum)
	{
		return transfer_at_least_t(minimum);
	}


	//////////////////////////////////////////////////////////////////////////

	struct uawaitable_t
	{
		inline net::redirect_error_t<
			typename boost::decay<decltype(net::use_awaitable)>::type>
			operator[](boost::system::error_code& ec) const noexcept
		{
			return net::redirect_error(net::use_awaitable, ec);
		}
	};
}

//
// uawaitable usage:
//
// boost::system::error_code ec;
// stream.async_read(buffer, uawaitable[ec]);
//

[[maybe_unused]] inline constexpr asio_util::uawaitable_t uawaitable;

