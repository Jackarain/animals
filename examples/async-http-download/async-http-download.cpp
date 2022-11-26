#include "utils/logging.hpp"

#include "animals/animals.hpp"
#include "utils/url_view.hpp"
namespace net = boost::asio;

int main(int argc, char** argv)
{
	if (argc != 2)
	{
		std::cerr << "Usage: " << argv[0] << " <url>\n";
		return EXIT_FAILURE;
	}

	std::string_view url(argv[1]);

	try {
		urls::url_view{ url };
	}
	catch (const std::exception& e)
	{
		std::cerr << "Url: " << url << " is invalid url\n";
		return EXIT_FAILURE;
	}

	net::io_context ioc;

	net::co_spawn(ioc,
		[&]() mutable -> net::awaitable<void>
		{
			animals::goat g(ioc.get_executor());

			animals::http_request req{ animals::http::verb::get, "", 11 };
			req.set(animals::http::field::user_agent, ANIMALS_VERSION_STRING);

			g.download_cb([](auto data, auto size)
				{
					std::cout.write((const char*)data, size);
				});

			g.dump("file.dump");

			boost::system::error_code ec;
			auto resp = co_await g.async_perform(
				std::string(url), req, net_awaitable[ec]);
			if (ec)
			{
				LOG_ERR << "http got: " << ec.message();
				co_return;
			}

			if (resp.result() != animals::http::status::ok)
				std::cout << resp << std::endl;

			co_return;
		}, net::detached);

	ioc.run();
}

