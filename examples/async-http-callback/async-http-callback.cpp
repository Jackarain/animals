#include "utils/logging.hpp"

#include "animals/animals.hpp"
namespace net = boost::asio;

int main()
{
	net::io_context ioc;

	animals::http_request req{ animals::http::verb::get, "", 11 };
	req.set(animals::http::field::host, "www.boost.org");
	req.set(animals::http::field::user_agent, ANIMALS_VERSION_STRING);

	animals::goat g(ioc.get_executor());
	g.async_perform("https://www.boost.org/LICENSE_1_0.txt", req,
		[](boost::system::error_code ec, animals::http_response resp) mutable
		{
			if (ec)
			{
				LOG_ERR << "http got: " << ec.message();
				return;
			}

			if (resp.result() != animals::http::status::ok)
				std::cout << resp << std::endl;
			else
				std::cout << animals::buffers_to_string(resp.body().data()) << std::endl;
		});

	ioc.run();

	return EXIT_SUCCESS;
}
