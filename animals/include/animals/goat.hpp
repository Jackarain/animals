//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include "utils/misc.hpp"
#include "utils/async_connect.hpp"
#include "utils/default_cert.hpp"

#include "proxy/socks_client.hpp"
#include "proxy/http_proxy_client.hpp"

#include "animals/http_last_modified.hpp"

#include "animals/animals.hpp"

#include <boost/variant2.hpp>

#include <boost/smart_ptr/local_shared_ptr.hpp>
#include <boost/smart_ptr/make_local_shared.hpp>

#include <boost/url.hpp>

#ifndef ANIMALS_VERSION_STRING
#  define ANIMALS_VERSION_STRING         "animals/1.0"
#endif

#ifdef ANIMALS_USE_FLAT_BUFFER
#  define ANIMALS_RECEIVE_BODY_MAX       (200 * 1024 * 1024)
#  define ANIMALS_RECEIVE_BUFFER_SIZE    (5 * 1024 * 1024)
#endif


namespace animals
{
	namespace net = boost::asio;			// from <boost/asio.hpp>
	namespace beast = boost::beast;			// from <boost/beast.hpp>
	namespace http = beast::http;           // from <boost/beast/http.hpp>

	using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

	namespace urls = boost::urls;			// form <boost/url.hpp>

	using namespace std::literals;
	using namespace std::chrono;

	using http_request = http::request<http::string_body>;
	using http_response = http::response<http::dynamic_body>;

	using beast::buffers_to_string;

	static const std::string chrome_user_agent = R"(Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36)";
	static const std::string edge_user_agent = R"(Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/18.17763)";
	static const std::string ie_user_agent = R"(Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko)";
	static const std::string curl_user_agent = R"(curl/7.64.0)";

	template<class ... T> inline constexpr bool always_false = false;

	template <typename Executor = net::any_io_executor>
	class basic_goat
	{
		using ssl_stream = beast::ssl_stream<beast::tcp_stream>;
		using ssl_stream_ptr = boost::local_shared_ptr<ssl_stream>;
		using tcp_stream = beast::tcp_stream;
		using tcp_stream_ptr = boost::local_shared_ptr<tcp_stream>;
		using variant_stream = boost::variant2::variant<tcp_stream_ptr, ssl_stream_ptr>;
		using download_handler = std::function<void(const void*, std::size_t)>;

	public:
		using executor_type = Executor;

		basic_goat(const executor_type& executor, bool check_cert = true)
			: m_executor(executor)
			, m_check_certificate(check_cert)
		{}
		~basic_goat() = default;


	public:
		// 检查和设置证书认证是否启用.
		inline bool check_certificate() const
		{
			return m_check_certificate;
		}

		inline void check_certificate(bool check)
		{
			m_check_certificate = check;
		}

		// 加载证书文件路径或证书文件，证书数据.
		inline void load_certificate_path(const std::string& path)
		{
			m_cert_path = path;
		}

		inline void load_certificate_file(const std::string& path)
		{
			m_cert_file = path;
		}

		inline void load_root_certificates(const std::string& data)
		{
			m_cert_data = data;
		}

		// 保存到文件.
		inline void dump(const std::string& file)
		{
			m_dump_file = file;
		}

		// 下载百分比.
		inline std::optional<double> percent()
		{
			return m_download_percent;
		}

		// 下载剩余大小, 如果服务器提供了内容长度.
		inline std::optional<std::size_t> content_length_remaining()
		{
			return m_content_lentgh_remaining;
		}

		// 下载内容大小, 如果服务器提供了内容长度.
		inline std::optional<std::size_t> content_length()
		{
			return m_content_lentgh;
		}

		// 返回当前url.
		inline const std::string& url() const
		{
			return m_url;
		}

		// 设置下载数据回调.
		inline void download_cb(download_handler cb)
		{
			m_download_handler = cb;
		}

		// 重置, 用于重复使用应该对象.
		inline void reset()
		{
			m_stream = variant_stream{};
			m_dump_file.clear();
			m_download_percent = {};
			m_content_lentgh = {};
			m_content_lentgh_remaining = {};
			m_download_handler = download_handler{};
			m_url.clear();
		}

		inline executor_type get_executor() noexcept
		{
			return m_executor;
		}


		// 异步执行一个url请求, 请求参数由req指定, 请求返回通过error_code 或 http_response
		// 得到, 如果发生错误, 则会得到error_code, 若请求正常则返回http_response.
		// Handler 函数签名为: void(boost::system::error_code, http_response)
		template<class Handler>
		auto async_perform(const std::string& url,
			http_request& req, Handler&& handler)
		{
			return net::async_initiate<Handler,
				void(boost::system::error_code, http_response)>(
					[this](auto&& handler,
						std::string url,
						std::string proxy,
						http_request* req) mutable
					{
						initiate_do_perform(
							std::forward<decltype(handler)>(handler),
							url,
							proxy,
							req);
					}, handler, url, "", &req);
		}

		// 异步执行一个url请求, 请求参数由req指定, 请求返回通过error_code 或 http_response
		// 得到, 如果发生错误, 则会得到error_code, 若请求正常则返回http_response.
		// 可指定sock5/http proxy, 如 socks5://127.0.0.1:1080, http://127.0.0.1:1080
		// Handler 函数签名为: void(boost::system::error_code, http_response)
		template<class Handler>
		auto async_perform(const std::string& url,
			const std::string& proxy, http_request& req, Handler&& handler)
		{
			return net::async_initiate<Handler,
				void(boost::system::error_code, http_response)>(
					[this](auto handler,
						std::string url,
						std::string proxy,
						http_request* req) mutable
					{
						initiate_do_perform(
							std::forward<decltype(handler)>(handler),
							url,
							proxy,
							req);
					}, handler, url, proxy, &req);
		}

		// 关闭http底层调用, 强制返回.
		inline void close()
		{
			boost::variant2::visit([](auto p) mutable
				{
					boost::system::error_code ec;
					if (p)
					{
						auto& s = beast::get_lowest_layer(*p);
						s.socket().close(ec);
					}
				}, m_stream);
		}

	private:
		template <typename Handler>
		void initiate_do_perform(Handler&& handler,
			std::string url, std::string proxy, http_request* req)
		{
			net::co_spawn(m_executor,
				[this,
				handler = std::forward<Handler>(handler),
				url,
				proxy,
				req]
			() mutable->net::awaitable<void>
			{
				http_response result;
				auto ec =
					co_await do_async_perform(*req,
						result,
						url,
						proxy);
				handler(ec, result);
				co_return;
			}
			, net::detached);
		}

		net::awaitable<boost::system::error_code>
			do_async_perform(http_request& req, http_response& result,
				const std::string& url, std::string proxy_url)
		{
			boost::system::error_code ec;
			m_url = url;

			auto rv = boost::urls::parse_uri(url);
			if (!rv)
			{
				ec = net::error::make_error_code(
					net::error::invalid_argument);
				co_return ec;
			}

			auto uv = rv.value();
			std::string host(uv.host());

			// check request params.
			auto host_it = req.find(http::field::host);
			if (host_it == req.end())
				req.set(http::field::host, host);

			if (req.method() == http::verb::unknown)
				req.method(http::verb::get);

			auto user_agent_it = req.find(http::field::user_agent);
			if (user_agent_it == req.end())
				req.set(http::field::user_agent, ANIMALS_VERSION_STRING);

			if (req.target() == "")
			{
				std::string query;
				if (uv.query() != "")
				{
					auto q = std::string(uv.query());
					if (q[0] == '?')
						query = std::string(uv.query());
					else
						query = "?" + std::string(uv.query());
				}

				if (std::string(uv.path()) == "")
					req.target("/" + query);
				else
					req.target(std::string(uv.path()) + query);
			}
			if (req.method() == http::verb::post)
			{
				if (!req.has_content_length() && !req.body().empty())
					req.content_length(req.body().size());
			}

			if (beast::iequals(uv.scheme(), "https"))
			{
				m_ssl_ctx = std::make_unique<
					net::ssl::context>(net::ssl::context::sslv23_client);

				if (m_check_certificate)
				{
					bool load_cert = false;
					m_ssl_ctx->set_verify_mode(net::ssl::verify_peer);

					const char* dir;
					dir = getenv(X509_get_default_cert_dir_env());
					if (!dir)
						dir = X509_get_default_cert_dir();
					if (std::filesystem::exists(dir))
					{
						m_ssl_ctx->add_verify_path(dir, ec);
						if (ec)
							co_return ec;
					}

					if (!m_cert_path.empty())
					{
						load_cert = true;
						m_ssl_ctx->add_verify_path(m_cert_path, ec);
						if (ec)
							co_return ec;
					}
					if (!m_cert_file.empty())
					{
						load_cert = true;
						m_ssl_ctx->load_verify_file(m_cert_file, ec);
						if (ec)
							co_return ec;
					}
					if (!m_cert_data.empty())
					{
						load_cert = true;
						m_ssl_ctx->add_certificate_authority(
							net::buffer(m_cert_data.data(),
								m_cert_data.size()),
							ec);
						if (ec)
							co_return ec;
					}
					if (!load_cert)
					{
						auto cert = default_root_certificates();
						m_ssl_ctx->add_certificate_authority(
							net::buffer(cert.data(), cert.size()),
							ec);
						if (ec)
							co_return ec;
					}

					m_ssl_ctx->set_verify_callback(
						net::ssl::rfc2818_verification(host), ec);
					if (ec)
						co_return ec;
				}

				variant_stream newsocket(
					boost::make_local_shared<ssl_stream>(
						m_executor, *m_ssl_ctx));
				m_stream.swap(newsocket);

				auto& stream = *(boost::variant2::get<ssl_stream_ptr>(m_stream));

				std::string port(uv.port());
				if (port.empty())
					port = "443";

				tcp::resolver resolver(m_executor);

				// Look up the domain name
				auto const results =
					co_await resolver.async_resolve(
						host,
						port,
						net_awaitable[ec]);
				if (ec)
					co_return ec;

				// Set the timeout.
				beast::get_lowest_layer(stream).expires_after(
					std::chrono::seconds(30));

				if (!proxy_url.empty())
				{
					ec = co_await do_proxy(
						stream,
						proxy_url,
						host,
						port);
					if (ec)
						co_return ec;

					net::socket_base::keep_alive option(true);
					get_lowest_layer(stream).socket().set_option(option, ec);
				}
				else
				{
					// Make the connection on the IP address we get from a lookup
					co_await asio_util::async_connect(
						get_lowest_layer(stream).socket(),
						results, net_awaitable[ec]);
					if (ec)
						co_return ec;

					net::socket_base::keep_alive option(true);
					get_lowest_layer(stream).socket().set_option(option, ec);
				}

				// Set SNI Hostname (many hosts need this to handshake successfully)
				if (!SSL_set_tlsext_host_name(
					stream.native_handle(), host.c_str()))
				{
					ec.assign(static_cast<int>(
						::ERR_get_error()), net::error::get_ssl_category());
					co_return ec;
				}

				// Perform the SSL handshake
				co_await stream.async_handshake(
					net::ssl::stream_base::client, net_awaitable[ec]);
				if (ec)
					co_return ec;

				// Set the timeout.
				beast::get_lowest_layer(stream).expires_after(
					std::chrono::seconds(30));
			}
			else if (beast::iequals(uv.scheme(), "http"))
			{
				std::string port(uv.port());
				if (port.empty())
					port = "80";

				// These objects perform our I/O
				tcp::resolver resolver(m_executor);

				// Look up the domain name
				auto const results = co_await resolver.async_resolve(
					host, port, net_awaitable[ec]);
				if (ec)
					co_return ec;

				variant_stream newsocket(
					boost::make_local_shared<tcp_stream>(m_executor));
				m_stream.swap(newsocket);

				// Get stream object ref.
				auto& stream = *(boost::variant2::get<tcp_stream_ptr>(m_stream));

				// Set the timeout.
				beast::get_lowest_layer(stream).expires_after(30s);

				if (!proxy_url.empty())
				{
					ec = co_await do_proxy(stream, proxy_url, host, port);
					if (ec)
						co_return ec;

					net::socket_base::keep_alive option(true);
					stream.socket().set_option(option, ec);
				}
				else
				{
					// Make the connection on the IP address we get from a lookup
					co_await asio_util::async_connect(
						stream.socket(), results, net_awaitable[ec]);
					if (ec)
						co_return ec;

					net::socket_base::keep_alive option(true);
					stream.socket().set_option(option, ec);
				}

				// Set the timeout.
				beast::get_lowest_layer(stream).expires_after(
					std::chrono::seconds(30));
			}
			else
			{
				BOOST_ASSERT(false && "not supported scheme!");
				ec = net::error::make_error_code(
					net::error::invalid_argument);
				co_return ec;
			}

			if (auto tsp = boost::variant2::get_if<tcp_stream_ptr>(&m_stream))
			{
				ec = co_await do_perform(**tsp, req, result);
			}
			else if (auto ssp = boost::variant2::get_if<ssl_stream_ptr>(&m_stream))
			{
				ec = co_await do_perform(**ssp, req, result);
			}
			else
			{
				BOOST_ASSERT(false && "variant stream is null!");
			}

			co_return ec;
		}

		template<class S, class B>
		net::awaitable<boost::system::error_code> async_read_http(
			S& stream, B& buffer, http_response& msg)
		{
			http::response_parser<
				http_response::body_type> p(std::move(msg));
			boost::system::error_code ec;

			p.body_limit(std::numeric_limits<std::size_t>::max());
			std::size_t total = 0;

			std::ofstream file;
			std::filesystem::path dumppath(m_dump_file);
			bool dump_to_file = false;

			if (!m_dump_file.empty())
			{
				// create file or directorys.
				if (dumppath.has_parent_path() &&
					!std::filesystem::exists(dumppath.parent_path()))
				{
					std::error_code ignore_ec;
					std::filesystem::create_directories(
						dumppath.parent_path(), ignore_ec);
				}
			}

			do {
				beast::get_lowest_layer(stream).expires_after(30s);
				[[maybe_unused]] auto bytes =
					co_await http::async_read_some(
						stream, buffer, p, net_awaitable[ec]);
				if (ec)
					co_return ec;

				auto& body = p.get().body();
				auto bodysize = body.size();

				total += bodysize;

				auto length = p.content_length();
				if (length)
				{
					m_content_lentgh = *length;

					auto remaining = p.content_length_remaining();
					if (remaining)
						m_content_lentgh_remaining = *remaining;

					if (*length > 0)
					{
						m_download_percent = 1.0 -
							(*m_content_lentgh_remaining /
								static_cast<double>(*length));
					}
				}

				if (p.is_header_done() && !dump_to_file)
				{
					if (!m_dump_file.empty() &&
						p.get().result() == boost::beast::http::status::ok)
					{
						{
							std::error_code ignore_ec;
							std::filesystem::remove(dumppath, ignore_ec);
						}

						file.open(dumppath,
							std::ios_base::binary | std::ios_base::trunc);
						if (file.good())
							dump_to_file = true;
					}
				}

				if ((m_download_handler || dump_to_file) && bodysize > 0)
				{
					for (auto const buf
						: boost::beast::buffers_range(body.data()))
					{
						auto bufsize = buf.size();
						auto bufptr = static_cast<const char*>(buf.data());

						if (dump_to_file)
							file.write(bufptr, bufsize);

						if (m_download_handler)
							m_download_handler(bufptr, bufsize);
					}

					body.consume(body.size());
				}
			} while (!p.is_done());

			// Transfer ownership of the message container in the parser to the caller.
			msg = p.release();

			// Last write time.
			if (dump_to_file)
			{
				file.close();

				auto lm = msg.find(http::field::last_modified);
				if (lm != msg.end())
				{
					auto tm = http_parse_last_modified(
						std::string(lm->value()));

					if (tm != -1)
					{
						using std::filesystem::file_time_type;

						std::error_code ignore_ec;
						auto ctm = system_clock::from_time_t(tm);
						file_time_type ftt{
							file_time_type::duration{
								ctm.time_since_epoch()} };
						std::filesystem::last_write_time(
							dumppath,
							ftt,
							ignore_ec);
					}
				}
			}

			co_return ec;
		}

		template<class S>
		net::awaitable<boost::system::error_code> do_perform(S& stream,
			http_request& req,
			http_response& result)
		{
			boost::system::error_code ec;

			// Send the HTTP request to the remote host
			co_await http::async_write(
				stream, req, net_awaitable[ec]);
			if (ec)
				co_return ec;

			// This buffer is used for reading and must be persisted
#ifdef ANIMALS_USE_FLAT_BUFFER
			beast::flat_buffer b(ANIMALS_RECEIVE_BODY_MAX);
			b.reserve(ANIMALS_RECEIVE_BUFFER_SIZE);
#else
			beast::multi_buffer b;
#endif

			// Receive the HTTP response
			ec = co_await async_read_http(
				stream, b, result);
			if (ec)
				co_return ec;

			// Gracefully close the socket
			if constexpr (std::is_same_v<std::decay_t<S>, ssl_stream>)
			{
				beast::get_lowest_layer(stream).expires_after(
					std::chrono::seconds(30));

				boost::system::error_code ignore_ec;
				co_await stream.async_shutdown(
					net_awaitable[ignore_ec]);
			}
			else if constexpr (std::is_same_v<std::decay_t<S>, tcp_stream>)
			{
				stream.socket().shutdown(
					tcp::socket::shutdown_both);
			}
			else
			{
				static_assert(always_false<S>, "non-exhaustive visitor!");
			}

			co_return ec;
		}

		template<class S>
		net::awaitable<boost::system::error_code>
			do_proxy(S& stream, const std::string& proxy_url,
				const std::string& host, const std::string& port)
		{
			boost::system::error_code ec;

			auto rv = boost::urls::parse_uri(proxy_url);
			if (!rv)
			{
				ec = net::error::make_error_code(
					net::error::invalid_argument);
				co_return ec;
			}

			auto url = rv.value();
			auto scheme = url.scheme();

			if (!scheme.starts_with("socks") && !scheme.starts_with("http"))
			{
				ec = net::error::make_error_code(
					net::error::invalid_argument);
				co_return ec;
			}

			std::string proxy_host(url.host());
			std::string proxy_port(url.port());
			if (proxy_port.empty())
				proxy_port = "1080";

			// These objects perform our I/O
			tcp::resolver resolver(m_executor);

			auto const socks_results =
				co_await resolver.async_resolve(
					proxy_host, proxy_port, net_awaitable[ec]);
			if (ec)
				co_return ec;

			auto& socket = get_lowest_layer(stream).socket();

			co_await asio_util::async_connect(
				socket,
				socks_results,
				net_awaitable[ec]);
			if (ec)
				co_return ec;

			if (url.scheme().starts_with("socks"))
			{
				proxy::socks_client_option opt;

				opt.target_host = host;
				opt.target_port = std::atoi(port.c_str());
				opt.proxy_hostname = true;
				opt.username = url.user();
				opt.password = url.password();

				if (url.scheme() == "socks5")
					opt.version = proxy::socks5_version;
				else if (url.scheme() == "socks4")
					opt.version = proxy::socks4_version;
				else if (url.scheme() == "socks4a")
					opt.version = proxy::socks4a_version;

				co_await proxy::async_socks_handshake(
					socket, opt, net_awaitable[ec]);

				co_return ec;
			}
			else if (proxy_url.starts_with("http"))
			{
				proxy::http_proxy_client_option opt;

				opt.target_host = host;
				opt.target_port = std::atoi(port.c_str());
				opt.username = url.user();
				opt.password = url.password();

				co_await proxy::async_http_proxy_handshake(
					socket, opt, net_awaitable[ec]);

				co_return ec;
			}

			ec = net::error::make_error_code(
				net::error::invalid_argument);
			co_return ec;
		}


	private:
		executor_type m_executor;
		variant_stream m_stream;
		std::unique_ptr<net::ssl::context> m_ssl_ctx;
		bool m_check_certificate;
		std::string m_cert_path;
		std::string m_cert_file;
		std::string m_cert_data;
		std::string m_dump_file;
		std::optional<double> m_download_percent;
		std::optional<std::size_t> m_content_lentgh;
		std::optional<std::size_t> m_content_lentgh_remaining;
		download_handler m_download_handler;
		std::string m_url;
	};

	using goat = basic_goat<>;
}
