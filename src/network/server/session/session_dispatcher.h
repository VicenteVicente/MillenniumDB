#pragma once

#include <chrono>
#include <memory>

#include <boost/asio.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/beast.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/ssl/ssl_stream.hpp>
#include <boost/asio/ssl/context.hpp>

#include "network/server/protocol.h"

namespace MDBServer {

class Server;

/**
 * Handle the initial connection and chooses the session based on the type of client that has connected
 */
class SessionDispatcher : public std::enable_shared_from_this<SessionDispatcher> {
public:
    SessionDispatcher(
        Server& server,
        boost::asio::ip::tcp::socket&& socket,
        std::chrono::seconds query_timeout
    ) :
        server(server),
        socket(std::move(socket)),
        query_timeout(query_timeout),
        ssl_ctx(boost::asio::ssl::context::tls_server)
    {
        ssl_ctx.use_certificate_chain_file("cert.pem");
        ssl_ctx.use_private_key_file("key.pem", boost::asio::ssl::context::pem);
    }

    void run();

    // templated to support both SSL and non-SSL streams
    template<typename Stream>
    void read_http_header(Stream& stream);

    void read_http_body();

    template<typename Stream>
    void dispatch_http(Stream&& stream);

    void tls_handshake();

    std::pair<std::string, std::string>
        get_user_password(const boost::beast::http::request<boost::beast::http::string_body>& http_request);

private:
    Server& server;

    boost::asio::ip::tcp::socket socket;

    std::chrono::seconds query_timeout;

    boost::asio::ssl::context ssl_ctx; // TODO: move to server
    std::unique_ptr<boost::beast::ssl_stream<boost::asio::ip::tcp::socket>> ssl_stream;

    boost::asio::streambuf read_buffer;

    boost::beast::http::request_parser<boost::beast::http::string_body> http_parser;

    // used to peek the request and check if it is encrypted or not
    uint8_t peek_byte = 0;
};
} // namespace MDBServer
