/**
*=============================================================================
* \file tcpip_gateway_main.cpp
*
*                        T C P I P  G A T E W A Y  M A I N
*                               S O U R C E  F I L E
*
* \brief
*      The main entry point for the Gateway Server application
*
* \copyright
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*=============================================================================
*/
#include <string>
#include "tcpip_gateway_cmd_server.h"

int32_t g_pc_port = TGWS_DEFAULT_PORT;

/**
* \brief
* Only one client can be connected to this target at a time. The use of a mutex
* ensures this. This includes both types of Listening Threads (WiFi and USB).
*
* \depends
* Intended server on Target must already be started
*
* \param[in] argc: 2 input arguments. Arg1 =?? Arg2 = PC Port
* \param[in] argv: list of input arguments.
*
* \return 0 on successful completion, or negative number on failure
*	negative number refers to type of failure
*/
int main(int argc, char *argv[])
{
    int32_t status = AR_EOK;
    std::string pc_port = "";
    std::string ip_addr = TGWS_DEFAULT_IP_ADDRESS;

    GATEWAY_ERR("Inside gateway main");//DEBUG
    if (argc == 2)
    {
        pc_port = argv[1];
        GATEWAY_INFO("Specified IP: %s, Port: %s", ip_addr.c_str(), pc_port.c_str());
        size_t index = 0;
        g_pc_port = std::stoi(pc_port, &index);
    } else if (argc == 3)
    {
        ip_addr = argv[1];
        pc_port = argv[2];
        GATEWAY_INFO("Specified IP: %s, Port: %s", ip_addr.c_str(), pc_port.c_str());
    }

    /* TODO: For now only gateway over USB is supported until we can make
     * WIFI support cross-platform friendly */
    TcpipGatewayServer gs{ ip_addr, pc_port , TGWS_CONNECTION_OPTION_USB };
    status = gs.run();

    return status;
}
