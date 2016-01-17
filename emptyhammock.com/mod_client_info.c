/* Copyright 2014 Jeff Trawick, http://emptyhammock.com/
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This module can be used to set REMOTE_HOST and REMOTE_ADDR in an
 * origin server based on the Host header received by a proxy.
 *
 * In the proxy, load the module and configure it with
 *
 *   LoadModule client_info_module modules/mod_client_info.so
 *   ClientInfoMode proxy
 *
 * This causes the original Host header to be passed to the origin
 * server in a custom request header.  (See CI_REMOTE_HOST_HEADER below.)
 *
 * In the origin server, load the module and configure it with
 *
 *   LoadModule client_info_module modules/mod_client_info.so
 *   ClientInfoMode origin
 *
 * This will set REMOTE_HOST to the value passed from the proxy, and
 * set REMOTE_ADDR to the first IP address returned for the REMOTE_HOST
 * value.
 *
 * The ClientInfoMode setting can be global or per-VirtualHost.
 *
 * Warning: In origin server mode, the custom HTTP header will be
 *          trusted regardless of which host made the setting.  There
 *          is no provision for only trusting it for certain client
 *          IP addresses.
 */

#include "apr_strings.h"

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"

APLOG_USE_MODULE(client_info);

typedef enum {CI_MODE_UNSET, CI_MODE_PROXY, CI_MODE_ORIGIN} ci_mode_t;

typedef struct {
    ci_mode_t mode;
} ci_server_config;

#define CI_REMOTE_HOST_HEADER "X-CI-Inbound-Host"

module AP_MODULE_DECLARE_DATA client_info_module;

static void proxy_manipulation(request_rec *r)
{
    apr_table_t *in = r->headers_in;
    const char *host = apr_table_get(in, "Host");

    if (host) {
        apr_table_set(in, CI_REMOTE_HOST_HEADER, host);
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "no Host header received");
    }
}

static apr_status_t end_req(void *data)
{
    request_rec *r = data;

    r->connection->remote_host = NULL;
    return APR_SUCCESS;
}

static void origin_manipulation(request_rec *r)
{
    apr_table_t *in = r->headers_in;
    const char *host_val = apr_table_get(in, CI_REMOTE_HOST_HEADER);
    apr_status_t rv;
    apr_sockaddr_t *sa;

    if (host_val) {
        if (r->connection->remote_host) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                          "Ignoring remote host setting (%s)",
                          r->connection->remote_host);
        }
        /* remote_host is not const */
        r->connection->remote_host = apr_pstrdup(r->pool, host_val);
        /* restore conn_rec setting at end of request */
        apr_pool_cleanup_register(r->pool, r, end_req, apr_pool_cleanup_null);

        rv = apr_sockaddr_info_get(&sa, host_val, APR_UNSPEC, 0,
                                   APR_IPV4_ADDR_OK, r->pool);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "Can't resolve address \"%s\"",
                          host_val);
        }
        else {
            r->useragent_addr = sa;
            apr_sockaddr_ip_get(&r->useragent_ip, r->useragent_addr);
        }
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "Header " CI_REMOTE_HOST_HEADER " is not set");
    }
}

static int ci_post_read_request(request_rec *r)
{
    ci_server_config *sconf = ap_get_module_config(r->server->module_config,
                                                   &client_info_module);

    switch(sconf->mode) {
    case CI_MODE_UNSET:
        break;
    case CI_MODE_PROXY:
        proxy_manipulation(r);
        break;
    case CI_MODE_ORIGIN:
        origin_manipulation(r);
        break;
    }

    return OK;
}

static void ci_register_hooks(apr_pool_t *p)
{
    ap_hook_post_read_request(ci_post_read_request, NULL, NULL, APR_HOOK_MIDDLE);
}

static void *ci_create_server_config(apr_pool_t *p, server_rec *s)
{
    ci_server_config *conf =
        (ci_server_config *)apr_pcalloc(p, sizeof(ci_server_config));
    
    conf->mode = CI_MODE_UNSET;

    return conf;
}

static void *ci_merge_server_config(apr_pool_t *p, void *basev, void *virtv)
{
    ci_server_config *base = (ci_server_config *)basev;
    ci_server_config *virt = (ci_server_config *)virtv;
    ci_server_config *conf;

    conf = (ci_server_config *)apr_pmemdup(p, base, sizeof(*base));

    if (virt->mode != CI_MODE_UNSET) {
        conf->mode = virt->mode;
    }

    return conf;
}

static const char *ci_set_mode(cmd_parms *cmd, void *dummy, const char *arg)
{
    ci_server_config *sconf = ap_get_module_config(cmd->server->module_config,
                                                   &client_info_module);

    if (!strcasecmp(arg, "proxy")) {
        sconf->mode = CI_MODE_PROXY;
    }
    else if (!strcasecmp(arg, "origin")) {
        sconf->mode = CI_MODE_ORIGIN;
    }
    else {
        return "ClientInfoMode argument must be \"proxy\" or \"origin\".";
    }
    return NULL;
}

static const command_rec ci_cmds[] = {
    AP_INIT_TAKE1("ClientInfoMode", ci_set_mode, NULL, RSRC_CONF,
                  "Set processing mode to \"proxy\" or \"origin\""),
    {NULL}
};

module AP_MODULE_DECLARE_DATA client_info_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    ci_create_server_config,
    ci_merge_server_config,
    ci_cmds,
    ci_register_hooks,
};
