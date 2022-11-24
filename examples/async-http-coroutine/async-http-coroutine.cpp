#include "animals/animals.hpp"
namespace net = boost::asio;

int main()
{
	net::io_context ioc;

	net::co_spawn(ioc,
		[&]() mutable -> net::awaitable<void>
		{
			animals::goat g(ioc.get_executor());

			animals::http_request req{ animals::http::verb::get, "/", 11 };
			req.set(animals::http::field::host, "www.boost.org");
			req.set(animals::http::field::user_agent, ANIMALS_VERSION_STRING);

			boost::system::error_code ec;
			auto resp = co_await g.async_perform(
				"https://www.boost.org", req, net_awaitable[ec]);
			if (ec)
			{
				LOG_ERR << "http got: " << ec.message();
				co_return;
			}

			if (resp.result() != animals::http::status::ok)
				std::cout << resp << std::endl;
			else
				std::cout << animals::buffers_to_string(resp.body().data()) << std::endl;

			co_return;
		}, net::detached);

	ioc.run();
}

