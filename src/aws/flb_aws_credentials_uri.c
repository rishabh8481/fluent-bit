/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_utils.h>

#include <stdlib.h>
#include <time.h>
#include <string.h>

struct flb_aws_provider_uri {
    struct flb_aws_credentials *creds;
    time_t next_refresh;
    struct flb_aws_client *client;
    flb_sds_t uri;
};

static int uri_credentials_request(struct flb_aws_provider_uri *implementation);

struct flb_aws_credentials *get_credentials_fn_uri(struct flb_aws_provider *provider)
{
    struct flb_aws_credentials *creds = NULL;
    int refresh = FLB_FALSE;
    struct flb_aws_provider_uri *implementation = provider->implementation;



    if (implementation->next_refresh > 0 && time(NULL) > implementation->next_refresh) {
        refresh = FLB_TRUE;
    }
    if (!implementation->creds || refresh == FLB_TRUE) {
        if (try_lock_provider(provider)) {
            uri_credentials_request(implementation);
            unlock_provider(provider);
        } else {
            flb_error("try_lock_provider failed");
        }
    }

    if (!implementation->creds) {
        flb_warn("[aws_credentials] No cached credentials are available and "
                 "a credential refresh is already in progress. The current "
                 "co-routine will retry.");
        return NULL;
    }

    creds = flb_calloc(1, sizeof(struct flb_aws_credentials));
    if (!creds) {
        flb_errno();
        goto error;
    }

    creds->access_key_id = flb_sds_create(implementation->creds->access_key_id);
    if (!creds->access_key_id) {
        flb_errno();
        goto error;
    }

    creds->secret_access_key = flb_sds_create(implementation->creds->secret_access_key);
    if (!creds->secret_access_key) {
        flb_errno();
        goto error;
    }

    if (implementation->creds->session_token) {
        creds->session_token = flb_sds_create(implementation->creds->session_token);
        if (!creds->session_token) {
            flb_errno();
            goto error;
        }
    } else {
        creds->session_token = NULL;
    }

    return creds;

error:
    flb_aws_credentials_destroy(creds);
    return NULL;
}

int refresh_fn_uri(struct flb_aws_provider *provider) {
    struct flb_aws_provider_uri *implementation = provider->implementation;
    int ret = -1;


    if (try_lock_provider(provider)) {
        ret = uri_credentials_request(implementation);
        unlock_provider(provider);
    }
    return ret;
}

int init_fn_uri(struct flb_aws_provider *provider) {
    struct flb_aws_provider_uri *implementation = provider->implementation;
    int ret = -1;


    implementation->client->debug_only = FLB_TRUE;

    if (try_lock_provider(provider)) {
        ret = uri_credentials_request(implementation);
        unlock_provider(provider);
    }

    implementation->client->debug_only = FLB_FALSE;
    return ret;
}

void sync_fn_uri(struct flb_aws_provider *provider) {
    struct flb_aws_provider_uri *implementation = provider->implementation;

    flb_stream_disable_async_mode(&implementation->client->upstream->base);
}

void async_fn_uri(struct flb_aws_provider *provider) {
    struct flb_aws_provider_uri *implementation = provider->implementation;

    flb_stream_enable_async_mode(&implementation->client->upstream->base);
}

void upstream_set_fn_uri(struct flb_aws_provider *provider,
                         struct flb_output_instance *ins) {
    struct flb_aws_provider_uri *implementation = provider->implementation;

    ins->use_tls = FLB_FALSE;
    flb_output_upstream_set(implementation->client->upstream, ins);
    ins->use_tls = FLB_TRUE;
}

void destroy_fn_uri(struct flb_aws_provider *provider) {
    struct flb_aws_provider_uri *implementation = provider->implementation;

    if (implementation) {
        if (implementation->creds) {
            flb_aws_credentials_destroy(implementation->creds);
        }
        if (implementation->client) {
            flb_aws_client_destroy(implementation->client);
        }
        if (implementation->uri) {
            flb_sds_destroy(implementation->uri);
        }
        flb_free(implementation);
        provider->implementation = NULL;
    }
}

static struct flb_aws_provider_vtable uri_provider_vtable = {
    .get_credentials = get_credentials_fn_uri,
    .init = init_fn_uri,
    .refresh = refresh_fn_uri,
    .destroy = destroy_fn_uri,
    .sync = sync_fn_uri,
    .async = async_fn_uri,
    .upstream_set = upstream_set_fn_uri,
};

struct flb_aws_provider *flb_uri_provider_create(struct flb_config *config,
                                                 char *uri,
                                                 struct flb_aws_client_generator *generator)
{
    struct flb_aws_provider_uri *implementation = NULL;
    struct flb_aws_provider *provider = NULL;
    struct flb_upstream *upstream = NULL;
    flb_sds_t protocol = NULL;
    flb_sds_t host = NULL;
    flb_sds_t port_sds = NULL;
    flb_sds_t path = NULL;
    int port = 80;
    int insecure = FLB_TRUE;
    int ret;

    if (!uri || strlen(uri) == 0) {
    
        return NULL;
    }

    ret = flb_utils_url_split_sds(uri, &protocol, &host, &port_sds, &path);
    if (ret < 0) {
        flb_error("[aws_credentials] URI provider: failed to parse URI: %s", uri);
        return NULL;
    }

    if (port_sds != NULL) {
        port = atoi(port_sds);
        if (port == 0) {
            flb_error("[aws_credentials] URI provider: invalid port in URI: %s", uri);
            goto error;
        }
    }

    insecure = strncmp(protocol, "http", 4) == 0 ? FLB_TRUE : FLB_FALSE;



    provider = flb_calloc(1, sizeof(struct flb_aws_provider));
    if (!provider) {
        flb_errno();
        goto error;
    }

    pthread_mutex_init(&provider->lock, NULL);

    implementation = flb_calloc(1, sizeof(struct flb_aws_provider_uri));
    if (!implementation) {
        flb_free(provider);
        flb_errno();
        goto error;
    }

    provider->provider_vtable = &uri_provider_vtable;
    provider->implementation = implementation;

    implementation->uri = flb_sds_create(uri);
    if (!implementation->uri) {
        flb_errno();
        goto error;
    }

    upstream = flb_upstream_create(config, host, port,
                                   insecure == FLB_TRUE ? FLB_IO_TCP : FLB_IO_TLS, NULL);
    if (!upstream) {
        flb_aws_provider_destroy(provider);
        flb_error("[aws_credentials] URI Provider: connection initialization error");
        goto error;
    }

    upstream->base.net.connect_timeout = FLB_AWS_CREDENTIAL_NET_TIMEOUT;

    implementation->client = generator->create();
    if (!implementation->client) {
        flb_aws_provider_destroy(provider);
        flb_upstream_destroy(upstream);
        flb_error("[aws_credentials] URI Provider: client creation error");
        goto error;
    }

    implementation->client->name = "uri_provider_client";
    implementation->client->has_auth = FLB_FALSE;
    implementation->client->provider = NULL;
    implementation->client->region = NULL;
    implementation->client->service = NULL;
    implementation->client->port = port;
    implementation->client->flags = 0;
    implementation->client->proxy = NULL;
    implementation->client->upstream = upstream;

    flb_sds_destroy(protocol);
    flb_sds_destroy(host);
    flb_sds_destroy(port_sds);
    flb_sds_destroy(path);

    return provider;

error:
    if (protocol) flb_sds_destroy(protocol);
    if (host) flb_sds_destroy(host);
    if (port_sds) flb_sds_destroy(port_sds);
    if (path) flb_sds_destroy(path);
    return NULL;
}

static int uri_credentials_request(struct flb_aws_provider_uri *implementation)
{
    char *response = NULL;
    size_t response_len;
    time_t expiration;
    struct flb_aws_credentials *creds = NULL;
    struct flb_aws_client *client = implementation->client;
    struct flb_http_client *c = NULL;
    flb_sds_t protocol = NULL;
    flb_sds_t host = NULL;
    flb_sds_t port_sds = NULL;
    flb_sds_t path = NULL;
    int ret;


    
    ret = flb_utils_url_split_sds(implementation->uri, &protocol, &host, &port_sds, &path);
    if (ret < 0) {
        flb_error("[aws_credentials] URI provider: failed to parse URI");
        return -1;
    }


    
    c = client->client_vtable->request(client, FLB_HTTP_GET, path, NULL, 0, NULL, 0);
    


    flb_sds_destroy(protocol);
    flb_sds_destroy(host);
    flb_sds_destroy(port_sds);
    flb_sds_destroy(path);

    if (!c || c->resp.status != 200) {
        flb_error("[aws_credentials] URI credentials request failed. Status: %d", c ? c->resp.status : -1);
        if (c) {
            if (c->resp.payload_size > 0) {
                flb_aws_print_error_code(c->resp.payload, c->resp.payload_size,
                                         "URICredentialsProvider");
            }
            flb_http_client_destroy(c);
        }
        return -1;
    }

    response = c->resp.payload;
    response_len = c->resp.payload_size;

    /* Force read response if payload is empty but status is 200 */
    if (response_len == 0 && c->resp.status == 200) {
        flb_error("[aws_credentials] URI provider: HTTP 200 but empty payload - possible client issue");
    }

    if (response_len == 0) {
        flb_error("[aws_credentials] URI provider HTTP response payload is empty - credential server returned no data");
    }

    creds = flb_parse_http_credentials(response, response_len, &expiration);
    if (!creds) {
        flb_http_client_destroy(c);
        return -1;
    }

    flb_aws_credentials_destroy(implementation->creds);
    implementation->creds = NULL;

    implementation->creds = creds;
    implementation->next_refresh = expiration - FLB_AWS_REFRESH_WINDOW;
    flb_http_client_destroy(c);

    return 0;
}