#include "utils/logging.hpp"

#include "animals/animals.hpp"
namespace net = boost::asio;

int main()
{
	net::io_context ioc;

	net::co_spawn(ioc,
		[&]() mutable -> net::awaitable<void>
		{
			animals::uncia ws(ioc.get_executor());

			animals::http_request req{ animals::http::verb::get, "", 11 };
			req.set(animals::http::field::host, "echo.websocket.events");
			req.set(animals::http::field::user_agent, ANIMALS_VERSION_STRING);

			boost::system::error_code ec;
			auto resp = co_await ws.async_perform(
				"wss://echo.websocket.events/", req, net_awaitable[ec]);
			if (ec)
			{
				LOG_ERR << "http got: " << ec.message();
				co_return;
			}

			for (int i = 0; ; i++)
			{
				std::string text = "message " + std::to_string(i);
				co_await ws.async_write(net::buffer(text), net_awaitable[ec]);
				if (ec)
					break;

				boost::beast::flat_buffer buf;
				auto bytes = co_await ws.async_read(buf, net_awaitable[ec]);
				if (ec)
					break;

				LOG_DBG << animals::buffers_to_string(buf.data());

				net::steady_timer timer(ioc, std::chrono::seconds(2));
				co_await timer.async_wait(net_awaitable[ec]);
			}

			co_return;
		}, net::detached);

	ioc.run();
}

