/* echo-server.c - Networking echo server */

/*
 * Copyright (c) 2016 Intel Corporation.
 * Copyright (c) 2018 Nordic Semiconductor ASA.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_MODULE_NAME net_echo_server
#define NET_LOG_LEVEL LOG_LEVEL_DBG

#include <zephyr.h>
#include <linker/sections.h>
#include <errno.h>

#include <net/net_core.h>
#include <net/tls_credentials.h>

#include "common.h"
#include "certificate.h"

#define APP_BANNER "Run echo server"

static struct k_sem quit_lock;

struct configs conf = {
	.ipv4 = {
		.proto = "IPv4",
	},
	.ipv6 = {
		.proto = "IPv6",
	},
};

void quit(void)
{
	k_sem_give(&quit_lock);
}

#define PSK_TAG 2

static void init_app(void)
{
	k_sem_init(&quit_lock, 0, UINT_MAX);

	NET_INFO(APP_BANNER);

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
	int err = tls_credential_add(SERVER_CERTIFICATE_TAG,
				     TLS_CREDENTIAL_SERVER_CERTIFICATE,
				     server_certificate,
				     sizeof(server_certificate));
	if (err < 0) {
		NET_ERR("Failed to register public certificate: %d", err);
	}


	err = tls_credential_add(SERVER_CERTIFICATE_TAG,
				 TLS_CREDENTIAL_PRIVATE_KEY,
				 private_key, sizeof(private_key));
	if (err < 0) {
		NET_ERR("Failed to register private key: %d", err);
	}

	err = tls_credential_add(PSK_TAG,
				     TLS_CREDENTIAL_PSK,
				     "user",
				     4);
	if (err < 0) {
		NET_ERR("Failed to register PSK: %d", err);
	}


	err = tls_credential_add(PSK_TAG,
				 TLS_CREDENTIAL_PSK_ID,
				 "user", 5);
	if (err < 0) {
		NET_ERR("Failed to register PSK_ID: %d", err);
	}
#endif

	init_vlan();
}

static uint8_t _mbedtls_heap[65536];

void __weak exit(int code)
{
	printk("Fatal mbedTLS exit!!!\n");
	volatile int *x = 0;
	*x = 123;
}

#if defined(CONFIG_MBEDTLS)
#if !defined(CONFIG_MBEDTLS_CFG_FILE)
#include "mbedtls/config.h"
#else
#include CONFIG_MBEDTLS_CFG_FILE
#endif
#endif

#include "mbedtls/ssl.h"

void main(void)
{
	void CRYPTOCELL_IRQHandler(void*);
	IRQ_CONNECT(42, 1, CRYPTOCELL_IRQHandler, NULL, 0);
	irq_enable(42);

	mbedtls_memory_buffer_alloc_init(_mbedtls_heap, sizeof(_mbedtls_heap));

	//mbedtls_debug_set_threshold(100);

	init_app();

	int *l;
	for (l = mbedtls_ssl_list_ciphersuites(); *l; l++)
	{
		printk("%04X %s\n", *l, mbedtls_ssl_get_ciphersuite_name(*l));
	}

	if (IS_ENABLED(CONFIG_NET_TCP)) {
		start_tcp();
	}

	if (IS_ENABLED(CONFIG_NET_UDP)) {
		start_udp();
	}

	k_sem_take(&quit_lock, K_FOREVER);

	NET_INFO("Stopping...");

	if (IS_ENABLED(CONFIG_NET_TCP)) {
		stop_tcp();
	}

	if (IS_ENABLED(CONFIG_NET_UDP)) {
		stop_udp();
	}
}
