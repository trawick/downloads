/* Copyright 2013 Jeff Trawick, http://emptyhammock.com/
 * (See "Special note" below.)
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
 * Special note: Feel free to use this as an example; the original
 *               copyright notice should be removed if changed
 *               substantially.
 */

/*
 * Current status: Barely tested
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(remove_server_header);
#endif

static apr_status_t remove_server_header_filter(ap_filter_t *f,
                                       apr_bucket_brigade *bb)
{
    apr_bucket *b;
    
    if (APR_BRIGADE_EMPTY(bb)
        || APR_BUCKET_IS_METADATA((b = APR_BRIGADE_FIRST(bb)))) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c,
                      "unexpected input to remove_server_header_filter()");
    }
    else {
        apr_status_t rv;
        const char *data;
        apr_size_t bytes_read;

        rv = apr_bucket_read(b, &data, &bytes_read, APR_BLOCK_READ);
        if (rv != APR_SUCCESS) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c,
                          "unexpected rv %d from bucket read", rv);
        }
        else if (bytes_read < 5 || memcmp(data, "HTTP/", 5)) {
            ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, f->c,
                          "doesn't look like HTTP response");
        }
        else {
            const char *ch = data;
            apr_bucket *next = NULL;

            while (ch < (data + bytes_read)) {
                const char *cr = memchr(ch, '\r', bytes_read - (ch - data));
                if (!cr) {
                    break;
                }
                if (cr - ch > 7 && !strncasecmp("Server:", ch, 7)) {
                    cr++;
                    if (*cr != '\n') {
                        ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, f->c,
                                      "didn't find LF after Server...CR");
                        break;
                    }
                    apr_bucket_split(b, ch - data);
                    next = APR_BUCKET_NEXT(b);
                    apr_bucket_split(next, cr - ch + 1);
                    APR_BUCKET_REMOVE(next);
                    break;
                }
                else {
                    ch += 1;
                }
            }
            if (!next) {
                ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, f->c,
                              "didn't find Server header");
            }
        }
    }

    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
}

static void my_insert_filter(request_rec *r)
{
    ap_add_output_filter("REMOVE_SERVER_HEADER", NULL, r, r->connection);
}

static void remove_server_header_register_hooks(apr_pool_t *p)
{
    ap_register_output_filter("REMOVE_SERVER_HEADER", remove_server_header_filter, NULL,
                              AP_FTYPE_PROTOCOL);

    ap_hook_insert_filter(my_insert_filter, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_insert_error_filter(my_insert_filter, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA remove_server_header_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    remove_server_header_register_hooks
};
