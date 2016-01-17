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
 * Building the module:
 *   /path/to/apxs -ci mod_request_cpu.c
 *
 * Configuration:
 *   LoadModule request_cpu_module modules/mod_request_cpu.so
 *   Add "%Z" to your access log configuration
 *
 * This module has been very lightly tested with httpd 2.4.11-dev.
 * I do not suggest using it in a production environment until checking
 * it in a similar test environment.
 */

#include <sys/time.h>
#include <sys/resource.h>

#include "apr_strings.h"

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "mod_log_config.h"

typedef struct {
    int valid;
    struct rusage start_usage;
} rcpu_req_info_t;

module AP_MODULE_DECLARE_DATA request_cpu_module;

static const char *rcpu_log_request_cpu(request_rec *r, char *a)
{
    struct rusage stop_usage;
    rcpu_req_info_t *reqinfo;

    reqinfo = ap_get_module_config(r->request_config, &request_cpu_module);

    if (reqinfo && reqinfo->valid &&
        0 == getrusage(RUSAGE_THREAD, &stop_usage)) {
        /* this seems like a horrible kludge; just do the arithmetic
         * with carry and all that
         * (or, is the sample code in the glibc manual viral?)
         */
        apr_int64_t start_user =
            reqinfo->start_usage.ru_utime.tv_sec * 1000000
            + reqinfo->start_usage.ru_utime.tv_usec;
        apr_int64_t start_system =
            reqinfo->start_usage.ru_stime.tv_sec * 1000000
            + reqinfo->start_usage.ru_stime.tv_usec;
        apr_int64_t stop_user =
            stop_usage.ru_utime.tv_sec * 1000000
            + stop_usage.ru_utime.tv_usec;
        apr_int64_t stop_system =
            stop_usage.ru_stime.tv_sec * 1000000
            + stop_usage.ru_stime.tv_usec;

        return apr_psprintf(r->pool,
                            "%" APR_INT64_T_FMT "u,%" APR_INT64_T_FMT "s",
                            stop_user - start_user,
                            stop_system - start_system);
    }
    else {
        return "?";
    }
}

static int rcpu_post_read_request(request_rec *r)
{
    rcpu_req_info_t *reqinfo;

    reqinfo = apr_pcalloc(r->pool, sizeof(*reqinfo));
    if (0 == getrusage(RUSAGE_THREAD, &reqinfo->start_usage)) {
        reqinfo->valid = 1;
    }
    ap_set_module_config(r->request_config, &request_cpu_module, reqinfo);
    
    return OK;
}

static int rcpu_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
{
    static APR_OPTIONAL_FN_TYPE(ap_register_log_handler) *log_pfn_register;

    log_pfn_register = APR_RETRIEVE_OPTIONAL_FN(ap_register_log_handler);

    if (log_pfn_register) {
        log_pfn_register(p, "Z", rcpu_log_request_cpu, 0);
    }

    return OK;
}

static void rcpu_register_hooks(apr_pool_t *p)
{
    ap_hook_pre_config(rcpu_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(rcpu_post_read_request, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA request_cpu_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    rcpu_register_hooks,
};

