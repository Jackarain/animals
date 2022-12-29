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

#include "proxy/http_proxy_client.hpp"
#include "proxy/socks_client.hpp"

#include "animals/animals.hpp"

#include <boost/variant2.hpp>
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
	namespace beast = boost::beast;         // from <boost/beast.hpp>
	namespace http = beast::http;           // from <boost/beast/http.hpp>
	namespace websocket = beast::websocket; // from <boost/beast/websocket.hpp>
	using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

	using http_request = http::request<http::string_body>;

	using namespace std::literals;
	using namespace std::chrono;

	template <typename Executor = net::any_io_executor>
	class basic_uncia
	{
		using ssl_stream = beast::ssl_stream<beast::tcp_stream>;
		using tcp_stream = beast::tcp_stream;

		using ws_stream = websocket::stream<tcp_stream>;
		using wss_stream = websocket::stream<ssl_stream>;

		using ws_stream_ptr = std::unique_ptr<ws_stream>;
		using wss_stream_ptr = std::unique_ptr<wss_stream>;

		using variant_stream = boost::variant2::variant<
			ws_stream_ptr, wss_stream_ptr>;

	public:
		using executor_type = Executor;

		basic_uncia(const executor_type& executor, bool check_cert = true)
			: m_executor(executor)
			, m_check_certificate(check_cert)
		{}
		~basic_uncia() = default;

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

		// 返回当前url.
		inline const std::string& url() const
		{
			return m_url;
		}

		// 重置, 用于重复使用应该对象.
		inline void reset()
		{
			m_stream = variant_stream{};
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
		auto async_perform(const std::string& ws,
			http_request& req, Handler&& handler)
		{
			return net::async_initiate<Handler,
				void(boost::system::error_code, http_response)>(
					[this](auto&& handler,
						std::string ws,
						std::string proxy,
						http_request* req) mutable
					{
						initiate_do_perform(
							std::forward<decltype(handler)>(handler),
							ws,
							proxy,
							req);
					}, handler, ws, "", &req);
		}

		// 异步执行一个ws请求, 请求参数由req指定, 请求返回通过error_code 或 http_response
		// 得到, 如果发生错误, 则会得到error_code, 若请求正常则返回http_response.
		// 可指定sock5/http proxy, 如 socks5://127.0.0.1:1080, http://127.0.0.1:1080
		// Handler 函数签名为: void(boost::system::error_code, http_response)
		template<class Handler>
		auto async_perform(const std::string& ws,
			const std::string& proxy, http_request& req, Handler&& handler)
		{
			return net::async_initiate<Handler,
				void(boost::system::error_code, http_response)>(
					[this](auto handler,
						std::string ws,
						std::string proxy,
						http_request* req) mutable
					{
						initiate_do_perform(
							std::forward<decltype(handler)>(handler),
							ws,
							proxy,
							req);
					}, handler, ws, proxy, &req);
		}

		template<
			class CloseHandler = net::default_completion_token_t<executor_type>>
		auto async_close(const websocket::close_reason& cr,
			CloseHandler&& handler =
			net::default_completion_token_t<executor_type>{})
		{
			return boost::variant2::visit([&](auto& t) mutable
				{
					return t->async_close(cr, handler);
				}, m_stream);
		}

		template<
			class Handler = net::default_completion_token_t<executor_type>>
		auto async_ping(
			websocket::ping_data const& payload,
			Handler&& handler =
			net::default_completion_token_t<executor_type>{})
		{
			return boost::variant2::visit([&](auto& t) mutable
				{
					return t->async_ping(payload, handler);
				}, m_stream);
		}

		template<
			class Handler = net::default_completion_token_t<executor_type>>
		auto async_pong(
			websocket::ping_data const& payload,
			Handler&& handler =
			net::default_completion_token_t<executor_type>{})
		{
			return boost::variant2::visit([&](auto& t) mutable
				{
					return t->async_pong(payload, handler);
				}, m_stream);
		}

		template<
			class DynamicBuffer,
			class ReadHandler = net::default_completion_token_t<executor_type>>
			auto async_read(
				DynamicBuffer& buffer,
				ReadHandler&& handler =
				net::default_completion_token_t<executor_type>{})
		{
			return boost::variant2::visit([&](auto& t) mutable
				{
					return t->async_read(buffer, handler);
				}, m_stream);
		}

		template<
			class ConstBufferSequence,
			class WriteHandler = net::default_completion_token_t<executor_type>>
			auto async_write(
				ConstBufferSequence const& buffers,
				WriteHandler&& handler =
				net::default_completion_token_t<executor_type>{})
		{
			return boost::variant2::visit([&](auto& t) mutable
				{
					return t->async_write(buffers, handler);
				}, m_stream);
		}

		// tobe continue...

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
			std::string port(uv.port());

			if (beast::iequals(uv.scheme(), "ws"))
			{
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
					std::make_unique<ws_stream>(m_executor));
				m_stream.swap(newsocket);

				auto& wsstream = *(boost::variant2::get<ws_stream_ptr>(m_stream));
				auto& stream = beast::get_lowest_layer(wsstream);

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

				beast::get_lowest_layer(stream).expires_never();
			}
			else if (beast::iequals(uv.scheme(), "wss"))
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
						boost::asio::ssl::rfc2818_verification(host), ec);
					if (ec)
						co_return ec;
				}

				if (port.empty())
					port = "443";

				// These objects perform our I/O
				tcp::resolver resolver(m_executor);

				// Look up the domain name
				auto const results = co_await resolver.async_resolve(
					host, port, net_awaitable[ec]);
				if (ec)
					co_return ec;

				variant_stream newsocket(
					std::make_unique<wss_stream>(m_executor, *m_ssl_ctx));
				m_stream.swap(newsocket);

				auto& wsstream = *(boost::variant2::get<wss_stream_ptr>(m_stream));
				auto& stream = wsstream.next_layer();

				beast::get_lowest_layer(stream).expires_after(30s);
				if (!proxy_url.empty())
				{
					ec = co_await do_proxy(stream, proxy_url, host, port);
					if (ec)
						co_return ec;

					net::socket_base::keep_alive option(true);
					beast::get_lowest_layer(
						stream).socket().set_option(option, ec);
				}
				else
				{
					// Make the connection on the IP address we get from a lookup
					co_await asio_util::async_connect(
						beast::get_lowest_layer(
							stream).socket(), results, net_awaitable[ec]);
					if (ec)
						co_return ec;

					net::socket_base::keep_alive option(true);
					beast::get_lowest_layer(
						stream).socket().set_option(option, ec);
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

				beast::get_lowest_layer(stream).expires_never();
			}
			else
			{
				BOOST_ASSERT(false && "not supported scheme!");
				ec = net::error::make_error_code(
					net::error::invalid_argument);
				co_return ec;
			}

			auto hostname = host + ":" + port;
			auto target = uv.path();

			if (auto wsp = boost::variant2::get_if<ws_stream_ptr>(&m_stream))
			{
				ec = co_await async_handshake(**wsp, req, hostname, target);
			}
			else if (auto ssp = boost::variant2::get_if<wss_stream_ptr>(&m_stream))
			{
				ec = co_await async_handshake(**ssp, req, hostname, target);
			}
			else
			{
				BOOST_ASSERT(false && "variant stream is null!");
			}

			co_return ec;
		}

		template<class S>
		net::awaitable<boost::system::error_code>
		async_handshake(S& stream,
			const http_request& req,
			const std::string& hostname,
			std::string_view target)
		{
			boost::system::error_code ec;

			// Set suggested timeout settings for the websocket
			stream.set_option(
				websocket::stream_base::timeout::suggested(
					beast::role_type::client));

			// Set a decorator to change the User-Agent of the handshake
			stream.set_option(websocket::stream_base::decorator(
				[&](websocket::request_type& wsrt)
				{
					for (auto& r : req)
						wsrt.set(r.name(), r.value());
				}));


			// Perform the websocket handshake
			co_await stream.async_handshake(hostname, target, net_awaitable[ec]);
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
		bool m_check_certificate;
		std::unique_ptr<net::ssl::context> m_ssl_ctx;
		std::string m_cert_path;
		std::string m_cert_file;
		std::string m_cert_data;
		std::string m_dump_file;
		std::string m_url;
	};

	using uncia = basic_uncia<>;
}
