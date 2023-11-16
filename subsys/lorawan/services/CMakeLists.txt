# SPDX-License-Identifier: Apache-2.0

zephyr_library_sources_ifdef(CONFIG_LORAWAN_APP_CLOCK_SYNC clock_sync.c)
zephyr_library_sources_ifdef(CONFIG_LORAWAN_SERVICES
        bitmap.c
        frag_dec.c
        frag_flash.c
        frag_transport.c
        lorawan_services.c
        multicast.c
)
