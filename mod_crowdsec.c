/*
 * MIT License
 *
 * Copyright (c) 2024 Graham Leggett
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


/*
 * The Apache mod_crowdsec module allows the request to be
 * verified against the blocklist supplied by Crowdsec at
 * https://www.crowdsec.net.
 *
 * When blocked, this module returns 429 Too Many Requests
 * as described in
 * https://datatracker.ietf.org/doc/html/rfc6585#section-4
 *
 * Alternatively, the CrowdsecLocation directive can specify
 * an URL to redirect to on block.
 *
 *  Author: Graham Leggett
 *
 * Basic configuration:
 *
 * <IfModule !crowdsec_module>
 *   LoadModule crowdsec_module modules/mod_crowdsec.so
 * </IfModule>
 * <IfModule !proxy_module>
 *   LoadModule proxy_module modules/mod_proxy.so
 * </IfModule>
 * <IfModule !proxy_http_module>
 *   LoadModule proxy_http_module modules/mod_proxy_http.so
 * </IfModule>
 * <IfModule !socache_shmcb_module>
 *   LoadModule socache_shmcb_module modules/mod_socache_shmcb.so
 * </IfModule>
 *
 * <Proxy "http://localhost:8080">
 *   ProxySet connectiontimeout=1 timeout=5
 * </Proxy>
 *
 * CrowdsecURL http://localhost:8080
 * CrowdsecAPIKey [...]
 *
 * CrowdsecCache shmcb
 * CrowdsecCacheTimeout 60
 *
 * <Location />
 *   Crowdsec on
 * </Location>
 *
 * <Location /one/>
 *   Crowdsec on
 *   ErrorDocument 429 "IP Address Blocked"
 * </Location>
 *
 * <Location /two/>
 *   Crowdsec on
 *   ErrorDocument 429 https://somewhere.example.com/blocked.html
 * </Location>
 *
 * <Location /three/>
 *   Crowdsec on
 *   ErrorDocument 429 /you-are-blocked.html
 * </Location>
 *
 * <Location /four/>
 *   Crowdsec on
 *   CrowdsecLocation https://somewhere.example.com/blocked.html?ip=%{REMOTE_ADDR}
 * </Location>
 */

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_expr.h"
#include "ap_socache.h"
#include "util_mutex.h"

#include <apr_strings.h>

module AP_MODULE_DECLARE_DATA crowdsec_module;

typedef struct
{
    /* the url of the crowdsec service */
    const char *url;
    /* the API key of the crowdsec service */
    const char *key;
    /* shared obect cache mutex */
    apr_global_mutex_t *cache_mutex;
    /* The configured shared object cache provider */
    const ap_socache_provider_t *cache_provider;
    /* shared object cache provider data structure */
    ap_socache_instance_t *cache_instance;
    /* shared object cache timeout */
    apr_interval_time_t cache_timeout;
    /* the url was explicitly set */
    unsigned int url_set:1;
    /* the key was explicitly set */
    unsigned int key_set:1;
    /* the provider was explicitly set */
    unsigned int cache_provider_set:1;
    /* the timeout was explicitly set */
    unsigned int cache_timeout_set:1;
} crowdsec_server_rec;

typedef enum {
    CROWDSEC_FAIL,
    CROWDSEC_BLOCK,
    CROWDSEC_ALLOW
} crowdsec_fallback;

typedef enum {
    TOO_MANY_REQS = HTTP_TOO_MANY_REQUESTS,
    FORBIDDEN = HTTP_FORBIDDEN,
    INT_ERROR = HTTP_INTERNAL_SERVER_ERROR,
} http_code;

typedef struct
{
    /* the response from the crowdsec service is stored here */
    const char *response;
    /* the location to redirect to on block */
    ap_expr_info_t *location;
    /* enable was explicitly set */
    unsigned int enable:1;
    /* crowdsec fallback behaviour */
    crowdsec_fallback fallback:2;
    /* crowdsec blocked http code */
    http_code blockedhttpcode;
    /* crowdsec has been enabled */
    unsigned int enable_set:1;
    /* enable was explicitly set */
    unsigned int fallback_set:1;
    /* location was explicitly set */
    unsigned int location_set:1;
    /* blocked http code was explicitely set */
    unsigned int blockedhttpcode_set:1;
} crowdsec_config_rec;

#define CROWDSEC_CACHE_TIMEOUT_DEFAULT 60

#define MAX_VAL_LEN 256

static const char *const crowdsec_id = "crowdsec";

static apr_status_t cleanup_lock(void *data)
{
    server_rec *s = data;

    crowdsec_server_rec *sconf = (crowdsec_server_rec *)
        ap_get_module_config(s->module_config,
                             &crowdsec_module);
    if (sconf->cache_mutex) {
        apr_global_mutex_destroy(sconf->cache_mutex);
        sconf->cache_mutex = NULL;
    }

    return APR_SUCCESS;
}

static apr_status_t cleanup_cache(void *data)
{
    server_rec *s = data;

    crowdsec_server_rec *sconf = (crowdsec_server_rec *)
        ap_get_module_config(s->module_config,
                             &crowdsec_module);

    if (sconf->cache_instance) {
        sconf->cache_provider->destroy(sconf->cache_instance, s);
        sconf->cache_instance = NULL;
    }

    return APR_SUCCESS;
}

/*
 * The socache_shmcb module has an arbitrary restriction
 * that keys cannot be less than 4 bytes. Localhost can
 * be 3 bytes (::1), pad if necessary.
 */
static const char *crowdsec_cache_key(request_rec * r, apr_size_t * len)
{

    const char *key = r->useragent_ip;

    apr_size_t slen = strlen(key);

    if (slen < 4) {

        char *padded;

        padded = apr_pcalloc(r->pool, 5);
        memset(padded, ' ', 4);
        memcpy(padded, r->useragent_ip, slen);

        *len = 4;
        return padded;
    }
    else {
        *len = slen;
        return key;
    }
}

static const char *crowdsec_from_cache(request_rec * r)
{

    const char *key;
    apr_size_t keylen;

    unsigned char val[MAX_VAL_LEN];
    unsigned int vallen = MAX_VAL_LEN - 1;

    crowdsec_server_rec *sconf = (crowdsec_server_rec *)
        ap_get_module_config(r->server->module_config,
                             &crowdsec_module);

    const char *response = NULL;

    apr_status_t status;

    if (!sconf->cache_provider) {
        return NULL;
    }

    key = crowdsec_cache_key(r, &keylen);

    status = sconf->cache_provider->retrieve(sconf->cache_instance, r->server,
                                             (unsigned char *) key, keylen,
                                             val, &vallen, r->pool);

    if (APR_STATUS_IS_NOTFOUND(status)) {
        /* not found - just return */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "crowdsec: no response found in cache for %s",
                      r->useragent_ip);
        return NULL;
    }
    else if (status == APR_SUCCESS) {
        /* OK, we got a value */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "crowdsec: response found in cache for %s",
                      r->useragent_ip);
    }
    else {
        /* error: give up and pass the buck */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                      "crowdsec: error while retrieving cache response for %s",
                      r->useragent_ip);
        return NULL;
    }

    response = apr_pstrmemdup(r->pool, (char *) val, vallen);

    return response;
}

static void crowdsec_to_cache(request_rec * r, const char *response)
{

    crowdsec_server_rec *sconf = (crowdsec_server_rec *)
        ap_get_module_config(r->server->module_config,
                             &crowdsec_module);

    apr_time_t expiry;

    const char *key;
    apr_size_t keylen;

    apr_status_t status;

    if (!sconf->cache_mutex) {
        return;
    }

    status = apr_global_mutex_trylock(sconf->cache_mutex);

    if (APR_STATUS_IS_EBUSY(status)) {
        /* don't wait around; just abandon it */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, status, r,
                      "crowdsec: result for %s not written to cache (mutex busy)",
                      r->useragent_ip);
        return;
    }
    else if (status != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                      "crowdsec: result for %s not written to cache (failed to lock cache mutex)",
                      r->useragent_ip);
        return;
    }


    key = crowdsec_cache_key(r, &keylen);

    expiry = apr_time_now() + sconf->cache_timeout;

    /* store it */
    status = sconf->cache_provider->store(sconf->cache_instance, r->server,
                                          (unsigned char *) key, keylen,
                                          expiry, (unsigned char *) response,
                                          strlen(response), r->pool);

    if (status == APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "crowdsec: result for %s written to cache", r->useragent_ip);
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                      "crowdsec: result for %s not written to cache",
                      r->useragent_ip);
    }

    /* We're done with the mutex */
    status = apr_global_mutex_unlock(sconf->cache_mutex);

    if (status != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                      "crowdsec: failed to release mutex");
    }

}

static int crowdsec_proxy(request_rec * r, const char **response)
{

    request_rec *rr;
    int status;

    crowdsec_server_rec *sconf = (crowdsec_server_rec *)
        ap_get_module_config(r->server->module_config,
                             &crowdsec_module);

    crowdsec_config_rec *rrconf;

    /*
     * Using mod_proxy, we connect to the crowdsec API.
     *
     * To do this, we create a subrequest, and then disassociate
     * the subrequest from the main request so that no part of
     * the crowdsec response ends up in the main response.
     *
     * We then replace the input filter stack with a null filter
     * so that no attempt is made to read from the main request,
     * and finally we replace the output filter stack with a
     * filter that reads and parses the response from the API.
     */

    const char *target = apr_pstrcat(r->pool, sconf->url,
                                     "/v1/decisions?ip=",
                                     ap_escape_urlencoded(r->pool,
                                                          r->useragent_ip),
                                     NULL);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
                  "crowdsec: looking up IP '%s' at url: %s",
                  r->useragent_ip, target);

    /* create a proxy request */
    rr = ap_sub_req_method_uri("GET", r->uri, r, NULL);

    if (rr->status != HTTP_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r,
                      "crowdsec: service '%s' returned %d, request rejected: %s",
                      target, rr->status, r->uri);
        return rr->status;
    }

    /* disassociate the subrequest from the main request */
    rr->main = NULL;
    rr->output_filters = NULL;
    ap_add_output_filter("CROWDSEC", NULL, rr, r->connection);

    /* Make sure that proxy cannot touch our main request body */
    rr->input_filters = NULL;
    ap_add_input_filter("CROWDSEC_NULL", NULL, rr, r->connection);

    /* headers and trailers */
    rr->headers_in = apr_table_make(r->pool, 2);
    rr->trailers_in = apr_table_make(r->pool, 2);
    rr->headers_out = apr_table_make(r->pool, 2);
    rr->trailers_out = apr_table_make(r->pool, 2);

    /* emulate the function of proxy_detect so that a remote proxy request
     * will be attempted */
    rr->proxyreq = PROXYREQ_REVERSE;
    rr->uri = rr->unparsed_uri;
    rr->filename = apr_pstrcat(rr->pool, "proxy:", target, NULL);
    rr->handler = "proxy-server";

    /* make sure we don't recurse */
    rrconf = (crowdsec_config_rec *)
        ap_get_module_config(rr->per_dir_config, &crowdsec_module);

    if (sconf->key) {
        apr_table_setn(rr->headers_in, "X-Api-Key", sconf->key);
    }

    apr_table_setn(rr->headers_in, "User-Agent", ap_get_server_description());

    status = ap_run_sub_req(rr);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
                  "crowdsec: function call status is '%d' (response status is "
                  "'%d') from url: %s",
                  status, rr->status, rr->filename);

    if (HTTP_NOT_FOUND == status ||
        (status == OK && HTTP_NOT_FOUND == rr->status)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r,
                      "crowdsec: we received a 404 Not Found when speaking "
                      "to the crowdsec service '%s', you might be pointing at "
                      "something that isn't a crowdsec service, or the "
                      "mod_proxy_http module has not been installed, request "
                      "rejected: %s", target, r->uri);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    else if (status != OK) {

        crowdsec_config_rec *conf = (crowdsec_config_rec *)
            ap_get_module_config(r->per_dir_config,
                                 &crowdsec_module);

        switch (conf->fallback) {
        case CROWDSEC_FAIL: {

            ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r,
                          "crowdsec: crowdsec service '%s' returned status %d, "
                          "request failed: %s", target, status, r->uri);

            apr_table_setn(r->notes, "error-notes",
                           "Could not verify the request against the threat intelligence "
                           "service, the request has been rejected.");

            /* Allow "error-notes" string to be printed by ap_send_error_response() */
            apr_table_setn(r->notes, "verbose-error-to", "*");

            return HTTP_INTERNAL_SERVER_ERROR;
        }
        case CROWDSEC_BLOCK: {

            ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r,
                          "crowdsec: crowdsec service '%s' returned status %d, "
                          "request blocked: %s", target, status, r->uri);

            *response = apr_psprintf(r->pool,
                                     "[{\"error\":\"'%s' returned %d\"}]",
                                     target, status);

            return OK;
        }
        case CROWDSEC_ALLOW: {

            ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r,
                          "crowdsec: crowdsec service '%s' returned status %d, "
                          "request accepted anyway: %s", target, status, r->uri);

            *response = "null";

            return OK;
        }
        }

    }

    if (!rrconf->response) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r,
                      "crowdsec: response from crowdsec service '%s' was not recorded, "
                      "request rejected: %s", target, r->uri);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    *response = rrconf->response;

    return OK;
}

static int crowdsec_query(request_rec * r)
{

    const char *response;
    int status;

    crowdsec_server_rec *sconf = (crowdsec_server_rec *)
        ap_get_module_config(r->server->module_config,
                             &crowdsec_module);

    crowdsec_config_rec *conf = (crowdsec_config_rec *)
        ap_get_module_config(r->per_dir_config,
                             &crowdsec_module);

    if (r->main || !sconf || !sconf->url) {
        return DECLINED;
    }

    response = crowdsec_from_cache(r);

    if (!response) {

        status = crowdsec_proxy(r, &response);

        if ((status) != OK) {
            return status;
        }

        crowdsec_to_cache(r, response);

    }

    /* parse response of crowdsec request here */

    if (!strcmp("null", response)) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
                      "crowdsec: ip address '%s' not blocked, "
                      "request accepted: %s", r->useragent_ip, r->uri);
        return OK;
    }

    else if (conf->location) {

        const char *location;
        const char *err;

        err = NULL;
        location = ap_expr_str_exec(r, conf->location, &err);
        if (err) {
            ap_log_rerror(
                    APLOG_MARK, APLOG_ERR, 0, r,
                                       "crowdsec: CrowdsecLocation: can't "
                    "evaluate location expression: %s", err);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
                      "crowdsec: ip address '%s' lookup returned %s, "
                      "request redirected to '%s': %s",
                      r->useragent_ip, response, location, r->uri);

        ap_custom_response(r, conf->blockedhttpcode, location);
        return conf->blockedhttpcode;
    }

    else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
                      "crowdsec: ip address '%s' lookup returned %s, "
                      "request rejected: %s",
                      r->useragent_ip, response, r->uri);
        return conf->blockedhttpcode;
    }

}

static int crowdsec_check_access(request_rec * r)
{
    /* make sure we don't recurse */
    crowdsec_config_rec *conf = (crowdsec_config_rec *)
        ap_get_module_config(r->per_dir_config,
                             &crowdsec_module);

    int status;

    if (r->main || !conf->enable) {
        return DECLINED;
    }

    if ((status = crowdsec_query(r)) == OK) {
        return DECLINED;
    }

    return status;
}

/**
 * CROWDSEC filter: Soak up the response from the API.
 *
 * Set the response aside to be accessible to the
 * crowdsec_query above.
 */
static apr_status_t crowdsec_out_filter(ap_filter_t * f,
                                        apr_bucket_brigade * bb)
{

    crowdsec_config_rec *conf = (crowdsec_config_rec *)
        ap_get_module_config(f->r->per_dir_config,
                             &crowdsec_module);
    char *response;

    apr_off_t len;
    apr_size_t size;

    apr_brigade_length(bb, 1, &len);
    size = (apr_size_t) len;
    response = apr_palloc(f->r->pool, size + 1);
    apr_brigade_flatten(bb, response, &size);
    response[len] = 0;

    conf->response = response;

    apr_brigade_cleanup(bb);

    return OK;
}

/**
 * Cap the input filter stack, returning nothing.
 */
static apr_status_t null_in_filter(ap_filter_t * f, apr_bucket_brigade * bb,
                                   ap_input_mode_t mode,
                                   apr_read_type_e block, apr_off_t readbytes)
{
    apr_bucket *e;

    /* all the null filter does is insert an EOS, and then return success. */
    e = apr_bucket_eos_create(f->c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, e);

    return APR_SUCCESS;
}

static void *create_crowdsec_dir_config(apr_pool_t * p, char *d)
{
    crowdsec_config_rec *conf = apr_pcalloc(p, sizeof(crowdsec_config_rec));

    return conf;
}

static void *merge_crowdsec_dir_config(apr_pool_t * p, void *basev,
                                       void *addv)
{
    crowdsec_config_rec *new = (crowdsec_config_rec *) apr_pcalloc(p,
                                                                   sizeof
                                                                   (crowdsec_config_rec));
    crowdsec_config_rec *add = (crowdsec_config_rec *) addv;
    crowdsec_config_rec *base = (crowdsec_config_rec *) basev;

    new->enable = (add->enable_set == 0) ? base->enable : add->enable;
    new->enable_set = add->enable_set || base->enable_set;

    new->fallback = (add->fallback_set == 0) ? base->fallback : add->fallback;
    new->fallback_set = add->fallback_set || base->fallback_set;

    new->location = (add->location_set == 0) ? base->location : add->location;
    new->location_set = add->location_set || base->location_set;

    new->blockedhttpcode = (add->blockedhttpcode_set == 0) ? base->blockedhttpcode : add->blockedhttpcode;
    new->blockedhttpcode_set = add->blockedhttpcode_set || base->blockedhttpcode_set;

    return new;
}

static void *create_crowdsec_server_config(apr_pool_t * p, server_rec * s)
{
    crowdsec_server_rec *conf = apr_pcalloc(p, sizeof(crowdsec_server_rec));

    conf->cache_timeout = apr_time_from_sec(CROWDSEC_CACHE_TIMEOUT_DEFAULT);

    return conf;
}

/* cache-related settings are not merged here, but in the post_config hook,
 * since the cache has not yet sprung to life
 */
static void *merge_crowdsec_server_config(apr_pool_t * p, void *basev,
                                          void *addv)
{
    crowdsec_server_rec *new = (crowdsec_server_rec *) apr_pcalloc(p,
                                                                   sizeof
                                                                   (crowdsec_server_rec));
    crowdsec_server_rec *add = (crowdsec_server_rec *) addv;
    crowdsec_server_rec *base = (crowdsec_server_rec *) basev;

    new->url = (add->url_set == 0) ? base->url : add->url;
    new->url_set = add->url_set || base->url_set;

    new->key = (add->key_set == 0) ? base->key : add->key;
    new->key_set = add->key_set || base->key_set;

    new->cache_provider =
        (add->cache_provider_set ==
         0) ? base->cache_provider : add->cache_provider;
    new->cache_instance =
        (add->cache_provider_set ==
         0) ? base->cache_instance : add->cache_instance;
    new->cache_provider_set = add->cache_provider_set
        || base->cache_provider_set;

    new->cache_timeout =
        (add->cache_timeout_set ==
         0) ? base->cache_timeout : add->cache_timeout;
    new->cache_timeout_set = add->cache_timeout_set
        || base->cache_timeout_set;

    return new;
}

static int crowdsec_pre_config(apr_pool_t * pconf, apr_pool_t * plog,
                               apr_pool_t * ptmp)
{
    apr_status_t rv = ap_mutex_register(pconf, crowdsec_id,
                                        NULL, APR_LOCK_DEFAULT, 0);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, plog,
                      "failed to register %s mutex", crowdsec_id);
        return 500;             /* An HTTP status would be a misnomer! */
    }

    return OK;
}

static int crowdsec_post_config(apr_pool_t * pconf, apr_pool_t * plog,
                                apr_pool_t * ptmp, server_rec * s)
{
    apr_status_t status;

    server_rec *s_vhost;

    static struct ap_socache_hints cache_hints = { 48, 256, 60000000 };

    s_vhost = s;
    while (s_vhost) {

        crowdsec_server_rec *sconf;

        sconf = (crowdsec_server_rec *)
            ap_get_module_config(s_vhost->module_config, &crowdsec_module);

        if (sconf->cache_provider_set) {

            status = ap_global_mutex_create(&sconf->cache_mutex, NULL,
                                            crowdsec_id, NULL, s_vhost, pconf,
                                            0);
            if (status != APR_SUCCESS) {
                ap_log_perror(APLOG_MARK, APLOG_CRIT, status, plog,
                              "failed to create %s mutex", crowdsec_id);
                return 500;     /* An HTTP status would be a misnomer! */
            }
            apr_pool_cleanup_register(pconf, (void *) s_vhost, cleanup_lock,
                                      apr_pool_cleanup_null);


            status =
                sconf->cache_provider->init(sconf->cache_instance,
                                            crowdsec_id, &cache_hints,
                                            s_vhost, pconf);

            if (status != APR_SUCCESS) {
                ap_log_perror(APLOG_MARK, APLOG_CRIT, status, plog,
                              "failed to initialise %s cache", crowdsec_id);
                return 500;     /* An HTTP status would be a misnomer! */
            }
            apr_pool_cleanup_register(pconf, (void *) s_vhost, cleanup_cache,
                                      apr_pool_cleanup_null);

        }

        s_vhost = s_vhost->next;
    }


    return OK;
}

static const char *set_crowdsec(cmd_parms * cmd, void *dconf, int flag)
{
    crowdsec_config_rec *conf = dconf;

    conf->enable = flag;
    conf->enable_set = 1;

    return NULL;
}



static const char *set_crowdsec_fallback(cmd_parms * cmd, void *dconf, const char *fallback)
{
    crowdsec_config_rec *conf = dconf;

    if (!strcmp(fallback, "fail")) {
        conf->fallback = CROWDSEC_FAIL;
    }
    else if (!strcmp(fallback, "block")) {
        conf->fallback = CROWDSEC_BLOCK;
    }
    else if (!strcmp(fallback, "allow")) {
        conf->fallback = CROWDSEC_ALLOW;
    }
    else {
        return apr_psprintf(cmd->pool,
                            "Unknown CrowdsecFallback '%s'. Valid values "
                            "are 'fail', 'block' and 'allow'.", fallback);
    }

    conf->fallback_set = 1;

    return NULL;
}


static const char *set_crowdsec_blockedhttpcode(cmd_parms * cmd, void *dconf, const char *blockedhttpcode)
{
    crowdsec_config_rec *conf = dconf;
    int http_code = atoi(blockedhttpcode);

    //let's restrict to a few values to avoid weird stuff:
    // 200, 403, 500, 429
    switch (http_code) {
        case HTTP_FORBIDDEN:
        case HTTP_INTERNAL_SERVER_ERROR:
        case HTTP_TOO_MANY_REQUESTS:
        //case 418: /*Apache won't let me do that :<*/
            conf->blockedhttpcode = http_code;
            break;
        default:
            return apr_psprintf(cmd->pool,
                                "Unknown CrowdsecBlockedHTTPCode '%s'. Valid values "
                                "are 403, 500 and 429.", blockedhttpcode);
    }

    conf->blockedhttpcode_set = 1;

    return NULL;
}

static const char *set_crowdsec_location(cmd_parms *cmd, void *dconf,
                                const char *location)
{
    crowdsec_config_rec *conf = dconf;

    const char *expr_err = NULL;

    conf->location = ap_expr_parse_cmd(cmd, location, AP_EXPR_FLAG_STRING_RESULT,
            &expr_err, NULL);
    if (expr_err) {
        return apr_pstrcat(cmd->temp_pool,
                "crowdsec: cannot parse expression '", location, "' in CrowdsecLocation: ",
                      expr_err, NULL);
    }

    conf->location_set = 1;

    return NULL;
}

static const char *set_crowdsec_url(cmd_parms * cmd, void *dconf,
                                    const char *url)
{
    crowdsec_server_rec *sconf = (crowdsec_server_rec *)
        ap_get_module_config(cmd->server->module_config,
                             &crowdsec_module);

    sconf->url = url;
    sconf->url_set = 1;

    return NULL;
}

static const char *set_crowdsec_api_key(cmd_parms * cmd, void *dconf,
                                        const char *key)
{
    crowdsec_server_rec *sconf = (crowdsec_server_rec *)
        ap_get_module_config(cmd->server->module_config,
                             &crowdsec_module);

    sconf->key = key;
    sconf->key_set = 1;

    return NULL;
}

static const char *set_crowdsec_cache(cmd_parms * cmd, void *dconf,
                                      const char *cache)
{
    crowdsec_server_rec *sconf = (crowdsec_server_rec *)
        ap_get_module_config(cmd->server->module_config,
                             &crowdsec_module);

    const char *err;
    const char *param, *name;

    /* Argument is of form 'name:args' or just 'name'. */
    param = ap_strchr_c(cache, ':');
    if (param) {
        name = apr_pstrmemdup(cmd->pool, cache, param - cache);
        param++;
    }
    else {
        name = cache;
    }

    sconf->cache_provider =
        ap_lookup_provider(AP_SOCACHE_PROVIDER_GROUP, name,
                           AP_SOCACHE_PROVIDER_VERSION);
    if (sconf->cache_provider == NULL) {
        err = apr_psprintf(cmd->pool,
                           "Unknown socache provider '%s'. Maybe you need "
                           "to load the appropriate socache module "
                           "(mod_socache_%s?)", name, name);
    }
    else {
        err = sconf->cache_provider->create(&sconf->cache_instance, param,
                                            cmd->temp_pool, cmd->pool);
    }

    if (err) {
        err = apr_psprintf(cmd->pool, "CrowdsecCache: %s", err);

        return err;
    }

    sconf->cache_provider_set = 1;

    return err;
}

static const char *set_crowdsec_cache_timeout(cmd_parms * cmd, void *dconf,
                                              const char *timeout)
{
    crowdsec_server_rec *sconf = (crowdsec_server_rec *)
        ap_get_module_config(cmd->server->module_config,
                             &crowdsec_module);

    int secs = atoi(timeout);

    sconf->cache_timeout = apr_time_from_sec(secs);
    sconf->cache_timeout_set = 1;

    return NULL;
}

static const command_rec crowdsec_cmds[] = {
    AP_INIT_FLAG("Crowdsec",
                 set_crowdsec, NULL, RSRC_CONF | ACCESS_CONF,
                 "Enable crowdsec in the given location. Defaults to 'off'."),
    AP_INIT_TAKE1("CrowdsecFallback",
                  set_crowdsec_fallback, NULL, RSRC_CONF | ACCESS_CONF,
                  "How to respond if the Crowdsec API is not available. 'fail' returns a 500 Internal Server Error. 'block' returns a 302 Redirect (or 429 Too Many Requests if CrowdsecLocation is unset). 'allow' will allow the request through. Default to 'fail'."),
 
    AP_INIT_TAKE1("CrowdsecBlockedHTTPCode",
                  set_crowdsec_blockedhttpcode, NULL, RSRC_CONF | ACCESS_CONF,
                  "Set the HTTP code to return when the IP address is blocked. Defaults to 429 Too Many Requests."),
    AP_INIT_TAKE1("CrowdsecLocation",
                  set_crowdsec_location, NULL, RSRC_CONF | ACCESS_CONF,
                  "Set to the URL to redirect to when the IP address is banned. As per RFC 7231 may be a path, or a full URL. For example: /sorry.html"),
    AP_INIT_TAKE1("CrowdsecURL",
                  set_crowdsec_url, NULL, RSRC_CONF,
                  "Set to the URL of the Crowdsec API. For example: http://localhost:8080."),
    AP_INIT_TAKE1("CrowdsecAPIKey",
                  set_crowdsec_api_key, NULL, RSRC_CONF,
                  "Set to the API key of the Crowdsec API. Add an API key using 'cscli bouncers add'."),
    AP_INIT_TAKE1("CrowdsecCache",
                  set_crowdsec_cache, NULL, RSRC_CONF,
                  "Enable the crowdsec cache. Defaults to 'none'. Options detailed here: https://httpd.apache.org/docs/2.4/socache.html."),
    AP_INIT_TAKE1("CrowdsecCacheTimeout",
                  set_crowdsec_cache_timeout, NULL, RSRC_CONF,
                  "Set the crowdsec cache timeout. Defaults to 60 seconds."),
    {NULL}
};


static void register_hooks(apr_pool_t * p)
{
    ap_hook_pre_config(crowdsec_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(crowdsec_post_config, NULL, NULL, APR_HOOK_MIDDLE);

    ap_register_output_filter("CROWDSEC", crowdsec_out_filter, NULL,
                              AP_FTYPE_CONTENT_SET);
    ap_register_input_filter("CROWDSEC_NULL", null_in_filter, NULL,
                             AP_FTYPE_CONTENT_SET);

    ap_hook_access_checker(crowdsec_check_access, NULL, NULL, APR_HOOK_FIRST);

}

AP_DECLARE_MODULE(crowdsec) = {
    STANDARD20_MODULE_STUFF,
    create_crowdsec_dir_config, /* dir config creater */
    merge_crowdsec_dir_config,  /* dir merger --- default is to override */
    create_crowdsec_server_config,      /* server config */
    merge_crowdsec_server_config,       /* merge server config */
    crowdsec_cmds,              /* command apr_table_t */
    register_hooks              /* register hooks */
};
