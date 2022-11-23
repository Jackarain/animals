#include "animals/animals.hpp"
namespace net = boost::asio;

int main()
{
	net::io_context ioc;

	net::co_spawn(ioc,
		[&]() mutable -> net::awaitable<void>
		{
			animals::goat g(ioc.get_executor());

			animals::http_request req{ boost::beast::http::verb::get, "/", 11 };
			req.set(boost::beast::http::field::host, "www.boost.org");
			req.set(boost::beast::http::field::user_agent, ANIMALS_VERSION_STRING);

			boost::system::error_code ec;
			auto resp = co_await g.async_perform(
				"https://www.boost.org", req, uawaitable[ec]);
			if (ec)
			{
				LOG_ERR << "http got: " << ec.message();
				co_return;
			}

			if (resp.result() != boost::beast::http::status::ok)
				std::cout << resp << std::endl;
			else
				std::cout << boost::beast::buffers_to_string(resp.body().data()) << std::endl;

			co_return;
		}, net::detached);

	ioc.run();
}

