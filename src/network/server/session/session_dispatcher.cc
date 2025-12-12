#include "session_dispatcher.h"

#include "misc/logger.h"
#include "network/server/protocol.h"
#include "network/server/server.h"
#include "network/server/session/http/http_gql_session.h"
#include "network/server/session/http/http_quad_session.h"
#include "network/server/session/http/http_rdf_session.h"
#include "network/server/session/streaming/streaming_websocket_session.h"

using namespace MDBServer;
using namespace boost;
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;

void SessionDispatcher::run()
{
    // Set the timeout for getting the query
    auto self = this->shared_from_this();

    // Peek initial byte to determine if its encrypted or plain
    socket.async_receive(
        asio::buffer(&self->peek_byte, 1),
        asio::socket_base::message_peek,
        [self](const boost::system::error_code& ec, std::size_t bytes_transferred) {
            if (ec || bytes_transferred == 0) {
                self->socket.close();
                logger(Category::Error) << "Could not read the client's preamble";
                return;
            }

            const bool is_tls = self->peek_byte == 0x16;
            if (is_tls) {
                self->tls_handshake();
            } else {
                self->read_http_header(self->socket);
            }
        }
    );
}

template<typename Stream>
void SessionDispatcher::read_http_header(Stream& stream)
{
    http_parser.eager(true);
    http_parser.body_limit(16 * 1024 * 1024);

    auto self = this->shared_from_this();
    asio::async_read_until(
        stream,
        read_buffer,
        "\r\n\r\n",
        [self](const boost::system::error_code& ec, std::size_t /*bytes_transferred*/) {
            if (ec) {
                self->socket.close();
                logger(Category::Error) << "Could not read the HTTP header: " << ec.message();
                return;
            }
            auto tmp_buf = boost::asio::buffer(self->read_buffer.data(), self->read_buffer.size());
            boost::system::error_code ec2;
            self->http_parser.put(tmp_buf, ec2);
            self->read_buffer.consume(self->read_buffer.size());

            if (ec2) {
                self->socket.close();
                logger(Category::Error) << "Could not parse the HTTP header: " << ec2.message();
                return;
            }
            self->read_http_body();
        }
    );
}

void SessionDispatcher::read_http_body()
{
    if (!http_parser.is_done()) {
        auto self = this->shared_from_this();
        boost::asio::async_read(
            socket,
            read_buffer,
            boost::asio::transfer_at_least(1),
            [self](const boost::system::error_code& ec, std::size_t /*bytes_transferred*/) {
                if (ec) {
                    self->socket.close();
                    logger(Category::Error) << "Could not parse the HTTP body: " << ec.message();
                    return;
                }
                auto tmp_buf = boost::asio::buffer(self->read_buffer.data(), self->read_buffer.size());
                boost::system::error_code ec2;
                self->http_parser.put(tmp_buf, ec2);
                if (ec2) {
                    self->socket.close();
                    logger(Category::Error) << "Could not parse the HTTP: " << ec2.message();
                    return;
                }
                self->read_buffer.consume(self->read_buffer.size());
                self->read_http_body();
            }
        );
    } else {
        if (ssl_stream != nullptr) {
            dispatch_http(std::move(*(this->ssl_stream.get())));
        } else {
            beast::tcp_stream stream(std::move(socket));
            dispatch_http(std::move(stream));
        }

    }
}

template <typename Stream>
void SessionDispatcher::dispatch_http(Stream&& stream)
{
    http::request<http::string_body> http_request = http_parser.release();

    bool write_authorized = !server.has_admin_user();
    const auto&& [user, password] = get_user_password(http_request);

    if (!user.empty() && !password.empty()) {
        const auto [auth_token, valid_until] = server.create_auth_token(user, password);
        if (!auth_token.empty()) {
            write_authorized = true;
        } else {
            // TODO: tell the user that authorization failed?
        }
    }

    if (websocket::is_upgrade(http_request)) {
        auto ws_stream = std::make_unique<websocket::stream<Stream>>(std::move(stream));
        auto* ws_stream_p = ws_stream.get();

        // Try to handshake with the WebSocket client
        ws_stream_p->async_accept(
            http_request,
            [ws_stream = std::move(ws_stream),
             &server = server,
             query_timeout = query_timeout,
             write_authorized](const boost::system::error_code& ec) {
                if (ec) {
                    ws_stream->close(websocket::close_code::abnormal);
                    logger(Category::Error) << "Could not perform the WebSocket handshake with the client";
                    return;
                }
                logger(Category::Debug) << "Dispatching StreamingWebSocketSession";

                std::make_shared<StreamingWebSocketSession<Stream>>(
                    server,
                    std::move(*ws_stream),
                    query_timeout,
                    write_authorized
                )
                    ->run();
            }
        );
        return;
    }

    // TODO: SSL HTTP
    // // Handle regular HTTP requests
    // logger(Category::Debug) << "Dispatching HTTPSession";
    // if (server.model_id == Protocol::QUAD_MODEL_ID) {
    //     HttpQuadSession::run(std::make_unique<HttpQuadSession>(
    //         server,
    //         std::move(stream),
    //         std::move(http_request),
    //         query_timeout
    //     ));
    // } else if (server.model_id == Protocol::RDF_MODEL_ID) {
    //     HttpRdfSession::run(std::make_unique<HttpRdfSession>(
    //         server,
    //         std::move(stream),
    //         std::move(http_request),
    //         query_timeout
    //     ));
    // } else if (server.model_id == Protocol::GQL_MODEL_ID) {
    //     HttpGQLSession::run(std::make_unique<HttpGQLSession>(
    //         server,
    //         std::move(stream),
    //         std::move(http_request),
    //         query_timeout
    //     ));
    // } else {
    //     throw std::runtime_error("Unhandled ModelId: " + std::to_string(server.model_id));
    // }
}

void SessionDispatcher::tls_handshake()
{
    ssl_stream = std::make_unique<beast::ssl_stream<boost::asio::ip::tcp::socket>>(
        std::move(socket),
        ssl_ctx
    );

    auto self = this->shared_from_this();
    ssl_stream->async_handshake(asio::ssl::stream_base::server, [self](const boost::system::error_code& ec) {
        if (ec) {
            logger(Category::Error) << "TLS handshake failed: " << ec.message();
            return;
        }
        self->read_http_header(*(self->ssl_stream.get()));
    });
}

std::pair<std::string, std::string> SessionDispatcher::get_user_password(
    const boost::beast::http::request<boost::beast::http::string_body>& http_request
)
{
    // TODO: parse query params
    return { "admin", "1234" };
}