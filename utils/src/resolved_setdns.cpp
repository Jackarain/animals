
#if __has_include(<systemd/sd-bus.h>)

#include <arpa/inet.h>
#include <memory>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <vector>

#include <systemd/sd-bus.h>

#include <boost/asio.hpp>
#include "utils/scoped_exit.hpp"

namespace net = boost::asio;

bool SetLinkDNSv4(int if_index, std::vector<net::ip::address_v4> dns_addrs)
{
	sd_bus* bus = NULL;

	auto sd_bus_free = [](sd_bus* b) { sd_bus_unref(b); };

	int r;
	using sd_bus_ptr = std::unique_ptr<sd_bus, decltype(sd_bus_free)>;

	/* Connect to the system bus */
	r = sd_bus_default_system(&bus);
    if (r < 0)
    {
        fprintf(stderr, "Failed to connect to system bus: %s\n", strerror(-r));
        return false;
    }

	sd_bus_ptr auto_free_bus(bus, sd_bus_free);

	sd_bus_error error = SD_BUS_ERROR_NULL;

	auto sd_message_free = [](sd_bus_message* m) { sd_bus_message_unref(m); };

	using sd_bus_message_ptr = std::unique_ptr<sd_bus_message, decltype(sd_message_free)>;

	sd_bus_message* m	  = NULL;

	r = sd_bus_message_new_method_call(bus,
		&m,
		"org.freedesktop.resolve1",
		"/org/freedesktop/resolve1",
		"org.freedesktop.resolve1.Manager",
		"SetLinkDNS");

	sd_bus_message_ptr auto_m_unref{ m, sd_message_free };

	r = sd_bus_message_append(m, "i", if_index);
	r = sd_bus_message_open_container(m, 'a', "(iay)");
	for (size_t i = 0; i < dns_addrs.size(); i++)
	{
		r = sd_bus_message_open_container(m, 'r', "iay");
		r = sd_bus_message_append(m, "i", AF_INET);
		r = sd_bus_message_append_array(m, 'y', dns_addrs[i].to_bytes().data(), 4);
		r = sd_bus_message_close_container(m);
	}
	r = sd_bus_message_close_container(m);
	sd_bus_message* reply = NULL;
	r = sd_bus_call(bus, m, 0, &error, &reply);
	sd_bus_message_ptr auto_reply_unref{ reply, sd_message_free };

	scoped_exit free_bus_error([&error](){sd_bus_error_free(&error);});

	if (r < 0)
	{
		fprintf(stderr, "Failed to issue method call: %s\n", error.message);
        return false;
	}

	return true;
}

#endif
