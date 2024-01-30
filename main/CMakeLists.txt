set(requires
    hardware_driver
    player
    esp_http_client
	nvs_flash
	esp_event
	esp_netif
	esp_wifi
    )

idf_component_register(SRCS
                    INCLUDE_DIRS "."
                    EMBED_TXTFILES howsmyssl_com_root_cert.pem
                    postman_root_cert.pem
                    )