#ifndef __AR_OSAL_SOCKET_H__
#define __AR_OSAL_SOCKET_H__
/**
*==============================================================================
*  \file ar_sockets_api.h
*  \brief
*                    A u d i o R e a c h  S O C K E T S
*                          H E A D E R  F I L E
*
*         This file contains the socket definitions and helper macros used by
*         AR libraries.
*
*         The APIs defined in this file are based off of winsock2 for windows
*         and the linux socket apis. For additional information see Winsock2
*         and Unix socket documenation.
*
*  \copyright
*      Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*      SPDX-License-Identifier: BSD-3-Clause
*==============================================================================
*/

#include <errno.h>
#if  defined(__linux__)
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#elif defined(_WIN32) || defined(_WIN64)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <afunix.h>
#endif
#include "ar_osal_types.h"
#include "ar_osal_error.h"
#include "ar_osal_log.h"
#include "ar_osal_types.h"
#include "ar_osal_error.h"
#include "ar_osal_log.h"

#if  defined(__linux__)

#define INVALID_SOCKET -1
#define AR_SOCKET_ADDRESS_FAMILY AF_UNIX
#define TCP_PROTOCOL 0

typedef int ar_socket_t;
typedef socklen_t ar_socketlen_t;
typedef uint32_t ar_address_family_t;

#elif defined(_WIN32) || defined(_WIN64)

#define AR_SOCKET_ADDRESS_FAMILY AF_INET
#define TCP_PROTOCOL IPPROTO_TCP

typedef UINT_PTR ar_socket_t;
typedef int ar_socketlen_t;
typedef uint16_t ar_address_family_t;
#endif

#define AR_UNIX_PATH_MAX 108
typedef struct ar_sockaddr_un_t
{
    uint16_t sun_family;              /* AF_UNIX */
    char sun_path[AR_UNIX_PATH_MAX];  /* pathname */
} ar_sockaddr_un_t;

typedef struct sockaddr ar_socket_addr_t;
typedef struct sockaddr_storage ar_socket_addr_storage_t;
typedef struct sockaddr_in ar_socket_addr_in_t;
typedef struct ar_sockaddr_un_t ar_socket_addr_un_t;
typedef struct addrinfo ar_socket_addr_info_t;

#define AR_SOCKET_LAST_ERROR ar_socket_last_error()
#define AR_SOCKET_LOG_TAG  "AR SOCKET"
#define AR_SOCKET_ERR(...)  AR_LOG_ERR(AR_SOCKET_LOG_TAG, __VA_ARGS__)
#define AR_SOCKET_DBG(...)  AR_LOG_DEBUG(AR_SOCKET_LOG_TAG, __VA_ARGS__)

/* \brief
 *      Returns the error code for the last failed socket operation
 * \return A system level error code
 */
int32_t ar_socket_last_error();

/* \brief
 * Checks if a socket is invalid
 *
 * \param [in] socket: The socket to verify
 *
 * \return True if the socket is invalid, false if its valid
 */
bool_t ar_socket_is_invalid(
    ar_socket_t socket);

/* \brief
 *      Initializes the socket library
 * \return AR_EOK on success, non-zero otherwise
 */
int32_t ar_socket_init();

/* \brief
 *      De-initializes the socket library
 * \return AR_EOK on success, non-zero otherwise
 */
int32_t ar_socket_deinit();

/* \brief
 *      Closes an opened socket
 *
 * \param [in] socket: The socket to close
 *
 * \return AR_EOK on success, non-zero otherwise
 */
int32_t ar_socket_close(
    ar_socket_t socket);

/* \brief
 *      Establishes a connection to the provided socket
 *
 * \param [in] socket: The unconnected socket
 * \param [in] addr: A pointer to a ar_socket_addr_t strucutre containing the address to establish a connection with
 * \param [in] addr_len: The size of the ar_socket_addr_t structure
 *
 * \return AR_EOK on success, non-zero otherwise
 */
int32_t ar_socket_connect(
    ar_socket_t socket,
    ar_socket_addr_t *addr,
    uint32_t addr_len);

/* \brief
 *      Associates a local address with a socket
 *
 * \param [in] socket: The socket to bind to
 * \param [in] addr:  A pointer to a ar_socket_addr_t strucutre containing the address to assign to the unbound socket
 * \param [in] addr_len: The size of the ar_socket_addr_t structure
 * \return AR_EOK on success, non-zero otherwise
 */
int32_t ar_socket_bind(
    ar_socket_t socket,
    ar_socket_addr_t *addr,
    uint32_t addr_len);

/* \brief
 *      Places the provided socket into a listening state. The socket listens for inomming connections
 *
 * \param [in] socket: A bound and unconnected socket
 * \param [in] backlog: The max length of the queue of pending connections
 * \return AR_EOK on success, non-zero otherwise
 */
int32_t ar_socket_listen(
    ar_socket_t socket,
    int32_t backlog);

/* \brief
 *      Allows incomming connection requests on a socket
 *
 * \param [in] socket: The socket placed in the listening state using ar_socket_listen
 * \param [out] addr: A pointer to a buffer containg the address of the connecting client
 * \param [in] addr_len: The length of the structure pointed to by addr
 * \param [out] new_socket: The socket where the connection is made
 * \return AR_EOK on success, non-zero otherwise
 */
int32_t ar_socket_accept(
    ar_socket_t socket,
    ar_socket_addr_t *addr,
    ar_socketlen_t *addr_len,
    ar_socket_t *new_socket);

/* \brief
 *      Sends data through a connected socket
 * \param [in] socket: The connected socket
 * \param [in] buf: The buffer containing the data to transmit
 * \param [in] len: The length of the buffer to transmit
 * \param [in] flags: A set of flags that configure the call
 * \param [out] bytes_sent: The number of byes actually sent
 * \return AR_EOK on success, non-zero otherwise
 */
int32_t ar_socket_send(
    ar_socket_t socket,
    const char_t* buf,
    int32_t len,
    int32_t flags,
    int32_t *bytes_sent);

/* \brief
 *      Recieves data from a connected socket or bound connectionless socket
 *
 * \param [in] socket: The connected socket
 * \param [in] buf: The recieve buffer containing the incoming data
 * \param [in] len: The length of the recieve buffer
 * \param [in] flags: A set of flags that configure the call
 * \param [out] bytes_read: The number of bytes actually read
 * \return AR_EOK on success, non-zero otherwise
 */
int32_t ar_socket_recv(
    ar_socket_t socket,
    char_t* buf,
    int32_t len,
    int32_t flags,
    int32_t *bytes_read);

/* \brief
 *      Retrieves a socket option
 *
 * \param [in] socket: A socket to get options for
 * \param [in] level: the  option level
 * \param [in] opt_name: the name of the option
 * \param [out] opt_val: a pointer to a buffer to write the option value to
 * \param [in/out] opt_val_len: the length of the buffer containing the option value
 *
 * \return AR_EOK on success, non-zero otherwise
 */
int32_t ar_socket_get_options(
    ar_socket_t socket,
    int32_t level,
    int32_t opt_name,
    char_t* opt_val,
    ar_socketlen_t *opt_val_len);

/* \brief
 *      Sets a socket option
 *
 * \param [in] socket: A socket to set an option for
 * \param [in] level: the  option level
 * \param [in] opt_name: the name of the option
 * \param [in] opt_val: a pointer to a buffer containing the option value
 * \param [in] opt_val_len: the length of the buffer containing the option value
 * \return AR_EOK on success, non-zero otherwise
 */
int32_t ar_socket_set_options(
    ar_socket_t socket,
    int32_t level,
    int32_t opt_name,
    const char_t* opt_val,
    int32_t opt_val_len);

/* \brief
 *      Creaes an IPv4 Stream based TCP socket
 *
 * \param [out] socket: The IPv4 TCP based socket
 * \return AR_EOK on success, non-zero otherwise
 */
int32_t ar_socket_tcp(
    ar_socket_t *socket);

/* \brief
 *      Creaes an unix based socket
 *
 * \param [out] socket: The unix based socket
 * \return AR_EOK on success, non-zero otherwise
 */
int32_t ar_socket_unix(
    ar_socket_t *s);

/* \brief
 * The converts an IPv4 or IPv6 address from binary format to text. This is the equivalent of inet_ntop.
 *
 * \param [in] family: The address family
 * \param [in] addr: The address to convert to a string
 * \param [out] addr_string: The address as a string
 * \param [out] addr_string_length: The length of the address string
 * \return AR_EOK on success, non-zero otherwise
 */
int32_t ar_socket_inet_ntop(
    int32_t family,
    void* addr,
    char_t* addr_string,
    size_t addr_string_length);

/* \brief
 * The converts an IPv4 or IPv6 address string to its binary form
 *
 * \param [in] family: The address family
 * \param [in] addr_string: A null terminated string containing the inet address
 * \param [out] addr_struct: Pointer to a buffer containing the binary representation of the IP address
 * \return AR_EOK on success, non-zero otherwise
 */
int32_t ar_socket_inet_pton(
    int32_t family,
    char_t* addr_string,
    void* addr_struct);

/* \brief
 *      Converts a ushort port to TCP/IP network byte order (big-endian)
 *
 * \param [in] port: The port to convert. This port is in host-byte order
 *                    (big or little endian depending on what the host
                      supports by default)
 * \return AR_EOK on success, non-zero otherwise
 */
uint16_t ar_socket_htons(
    uint16_t port);

/* \brief
 *      Retrieves the address of a sockets connected peer
 *
 * \param [in] socket: The connected socket
 * \param [out] socket_addr: A to a ar_socket_addr_t structure where the address is written to
 * \param [out] addr_length: A poointer to the length of the ar_socket_addr_t structure
 * \return AR_EOK on success, non-zero otherwise
 */
int32_t ar_socket_get_peer_name(
    ar_socket_t socket,
    ar_socket_addr_t* socket_addr,
    ar_socketlen_t* addr_length);

/* \brief
 *      Retrieves one or more ar_socket_addr_info_t structures that contain internet address.
 *
 * \param [in] node: A null terminated string containing the host name or address string.
 *                   This is optional.
 * \param [in] service: A null terminated string containing a service name or string port
 *                      number. This is optional
 * \param [in] hints: A pointer to a ar_socket_addr_info_t structure that contains
 *                    hints about the type of sockets supported by the caller. This is optional
 * \param [out] addr_results: A pointer to a linked list of one or more ar_socket_addr_info_t
 *                            containing information about the host
 * \return AR_EOK on success, non-zero otherwise
 */
int32_t ar_socket_get_addr_info(
    const char_t *node,
    const char_t *service,
    const ar_socket_addr_info_t *hints,
    ar_socket_addr_info_t **addr_results);

/* \brief
 *      Frees the add_results aquired when calling ar_socket_get_addr_info
 *
 * \param [out] addr_info: The addr_results linked list from ar_socket_get_addr_info
 * \return AR_EOK on success, non-zero otherwise
 */
void ar_socket_free_addr_info(
    ar_socket_addr_info_t* addr_info);
#endif /*__ar_OSAL_SOCKET_H__*/
