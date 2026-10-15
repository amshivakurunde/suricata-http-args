#include "suricata-common.h"
#include "threads.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-engine-inspect-buffer.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"

#include "flow.h"

#include "util-debug.h"
#include "util-memcmp.h"
#include "util-streaming-buffer.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"

#include "detect-http-args.h"
#include "stream-tcp.h"

static uint8_t DetectEngineInspectBufferHttpArgs(
        DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx,
        const DetectEngineAppInspectionEngine *engine,
        const Signature *s,
        Flow *f,
        uint8_t flags,
        void *alstate,
        void *txv,
        uint64_t tx_id);


static int g_http_args_buffer_id = 0;


static int DetectHttpArgsSetup(
        DetectEngineCtx *de_ctx, Signature *s, const char *str);

static void DetectHttpArgsSetupCallback(
        const DetectEngineCtx *de_ctx, Signature *s);

static InspectionBuffer *GetData(
        DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *f,
        const uint8_t flow_flags,
        void *txv,
        const int list_id);


/**
 * \brief Check whether request body is
 * application/x-www-form-urlencoded.
 */
static bool IsFormUrlEncoded(htp_tx_t *tx)
{
    static const uint8_t form_type[] =
            "application/x-www-form-urlencoded";

    const size_t form_type_len =
            sizeof(form_type) - 1;

    const htp_header_t *header =
            htp_tx_request_header(tx, "Content-Type");

    if (header == NULL) {
        return false;
    }

    const uint8_t *value =
            htp_header_value_ptr(header);

    size_t value_len =
            (size_t)htp_header_value_len(header);

    if (value == NULL || value_len == 0) {
        return false;
    }

    /*
     * Skip optional leading whitespace.
     */
    while (value_len > 0 &&
            (*value == ' ' || *value == '\t')) {
        value++;
        value_len--;
    }

    if (value_len < form_type_len) {
        return false;
    }

    /*
     * Case-insensitive comparison.
     *
     * SCMemcmpLowercase expects the first argument
     * to already be lowercase.
     */
    if (SCMemcmpLowercase(
                form_type,
                value,
                form_type_len) != 0) {
        return false;
    }

    /*
     * Exact:
     *
     * application/x-www-form-urlencoded
     *
     * or:
     *
     * application/x-www-form-urlencoded; charset=UTF-8
     */
    if (value_len == form_type_len) {
        return true;
    }

    const uint8_t next = value[form_type_len];

    return next == ';' ||
           next == ' ' ||
           next == '\t';
}


/**
 * \brief Register the http.args sticky buffer.
 */
void DetectHttpArgsRegister(void)
{
    sigmatch_table[DETECT_HTTP_ARGS].name =
            "http.args";

    sigmatch_table[DETECT_HTTP_ARGS].desc =
            "sticky buffer containing HTTP request arguments";

    sigmatch_table[DETECT_HTTP_ARGS].Setup =
            DetectHttpArgsSetup;

    sigmatch_table[DETECT_HTTP_ARGS].flags |=
            SIGMATCH_NOOPT |
            SIGMATCH_INFO_STICKY_BUFFER;


    /*
     * BODY instead of LINE because http.args can now
     * contain request-body parameters.
     */
    DetectAppLayerInspectEngineRegister(
        "http_args",
        ALPROTO_HTTP1,
        SIG_FLAG_TOSERVER,
        HTP_REQUEST_PROGRESS_BODY,
        DetectEngineInspectBufferHttpArgs,
        NULL);


   /* DetectAppLayerMpmRegister(
            "http_args",
            SIG_FLAG_TOSERVER,
            2,
            PrefilterGenericMpmRegister,
            GetData,
            ALPROTO_HTTP1,
            HTP_REQUEST_PROGRESS_BODY); */


    DetectBufferTypeSetDescriptionByName(
            "http_args",
            "HTTP request arguments");


    /*
     * When a rule uses http.args, enable request-body
     * collection in HTP.
     */
    DetectBufferTypeRegisterSetupCallback(
            "http_args",
            DetectHttpArgsSetupCallback);


    g_http_args_buffer_id =
            DetectBufferTypeGetByName("http_args");
}


/**
 * \brief Called when a signature uses http.args.
 */
static void DetectHttpArgsSetupCallback(
        const DetectEngineCtx *de_ctx,
        Signature *s)
{
    (void)de_ctx;

    AppLayerHtpEnableRequestBodyCallback();

    /*
     * Ensure buffered request data is flushed into
     * detection when necessary.
     */
    s->init_data->init_flags |=
            SIG_FLAG_INIT_NEED_FLUSH;
}


/**
 * \brief Activate the http.args sticky buffer.
 */
static int DetectHttpArgsSetup(
        DetectEngineCtx *de_ctx,
        Signature *s,
        const char *str)
{
    (void)str;

    if (SCDetectBufferSetActiveList(
                de_ctx,
                s,
                g_http_args_buffer_id) < 0) {
        return -1;
    }

    if (SCDetectSignatureSetAppProto(
                s,
                ALPROTO_HTTP) < 0) {
        return -1;
    }

    /*
     * http.args may inspect a streaming request body.
     */
    s->init_data->init_flags |=
            SIG_FLAG_INIT_TXDIR_STREAMING_TOSERVER;

    return 0;
}


/**
 * \brief Populate http.args.
 *
 * URI:
 *
 *   /login?source=web
 *
 * Body:
 *
 *   username=john&role=admin
 *
 * Result:
 *
 *   source=web&username=john&role=admin
 */
static InspectionBuffer *GetData(
        DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *f,
        const uint8_t flow_flags,
        void *txv,
        const int list_id)
{
    (void)f;
    (void)flow_flags;

    InspectionBuffer *buffer =
            InspectionBufferGet(det_ctx, list_id);

    

    htp_tx_t *tx = (htp_tx_t *)txv;

    if (tx == NULL) {
        return NULL;
    }


    /*
     * --------------------------------------------------
     * 1. URI query arguments
     * --------------------------------------------------
     */

    const uint8_t *query_data = NULL;
    uint32_t query_len = 0;

    const htp_uri_t *uri =
            htp_tx_parsed_uri(tx);

    if (uri != NULL) {
        const bstr *query =
                htp_uri_query(uri);

        if (query != NULL) {
            const size_t query_size =
        bstr_len(query);

if (query_size > UINT32_MAX) {
    return NULL;
}

if (query_size > 0) {
    query_data =
            bstr_ptr(query);

    query_len =
            (uint32_t)query_size;
}
        }
    }


    /*
     * --------------------------------------------------
     * 2. URL-encoded request body arguments
     * --------------------------------------------------
     */

    const uint8_t *body_data = NULL;
    uint32_t body_len = 0;

    if (IsFormUrlEncoded(tx)) {

        HtpTxUserData *htud =
                (HtpTxUserData *)
                htp_tx_get_user_data(tx);

        if (htud != NULL &&
                htud->request_body.sb != NULL) {

            uint64_t body_offset = 0;

            if (StreamingBufferGetData(
            htud->request_body.sb,
            &body_data,
            &body_len,
            &body_offset) != 1) {

    body_data = NULL;
    body_len = 0;

    
} else {
   
}

            /*
             * If offset is not zero, the start of the
             * body is no longer present in the active
             * streaming-buffer window.
             *
             * Do not expose an incomplete parameter set.
             */
            if (body_offset != 0) {
                body_data = NULL;
                body_len = 0;
            }
        }
    }


    /*
     * Nothing to inspect.
     */
    if (query_len == 0 &&
            body_len == 0) {
        return NULL;
    }


    /*
     * --------------------------------------------------
     * 3. Calculate combined buffer size
     * --------------------------------------------------
     */

    const bool add_separator =
            query_len > 0 &&
            body_len > 0;

    uint64_t total_len =
            (uint64_t)query_len +
            (uint64_t)body_len;

    if (add_separator) {
        total_len++;
    }

    if (total_len == 0 ||
            total_len > UINT32_MAX) {
        return NULL;
    }


    /*
     * --------------------------------------------------
     * 4. Allocate InspectionBuffer-owned memory
     * --------------------------------------------------
     */

    uint8_t *dst =
            SCInspectionBufferCheckAndExpand(
                    buffer,
                    (uint32_t)total_len);

    if (dst == NULL) {
        return NULL;
    }


    /*
     * --------------------------------------------------
     * 5. Construct:
     *
     * query&body
     * --------------------------------------------------
     */

    uint32_t pos = 0;

    if (query_len > 0) {
        memcpy(
                dst + pos,
                query_data,
                query_len);

        pos += query_len;
    }

    if (add_separator) {
        dst[pos++] = '&';
    }

    if (body_len > 0) {
        memcpy(
                dst + pos,
                body_data,
                body_len);

        pos += body_len;
    }


    /*
     * The combined http.args buffer always begins
     * at offset zero.
     */
    buffer->inspect_offset = 0;


    /*
     * Register our InspectionBuffer-owned memory as
     * the actual inspection data and apply transforms.
     */
    InspectionBufferSetupAndApplyTransforms(
            det_ctx,
            list_id,
            buffer,
            dst,
            pos,
            transforms);


    return buffer;
}

static uint8_t DetectEngineInspectBufferHttpArgs(
        DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx,
        const DetectEngineAppInspectionEngine *engine,
        const Signature *s,
        Flow *f,
        uint8_t flags,
        void *alstate,
        void *txv,
        uint64_t tx_id)
{
    (void)alstate;
    (void)tx_id;

    /*
     * HTTP body data may arrive over multiple TCP segments
     * or HTTP chunks.
     *
     * Do not consider the signature permanently finished
     * until HTP has progressed beyond the BODY stage.
     */
 
 const int progress =
        AppLayerParserGetStateProgress(
                f->proto,
                f->alproto,
                txv,
                flags);



const bool eof =
        progress > HTP_REQUEST_PROGRESS_BODY;

    /*
     * If MPM is not being used, transformations must be
     * applied here through GetData().
     */
    const DetectEngineTransforms *transforms = NULL;

    if (!engine->mpm) {
        transforms = engine->v2.transforms;
    }

    /*
     * Call our http.args GetData() directly.
     *
     * Do NOT use engine->v2.GetData here because Suricata
     * only stores that pointer automatically for the
     * generic inspection callback.
     */
    const InspectionBuffer *buffer =
            GetData(
                    det_ctx,
                    transforms,
                    f,
                    flags,
                    txv,
                    engine->sm_list);

    if (buffer == NULL || buffer->inspect == NULL) {

        if (eof && engine->match_on_null) {
            return DETECT_ENGINE_INSPECT_SIG_MATCH;
        }

        return eof
                ? DETECT_ENGINE_INSPECT_SIG_CANT_MATCH
                : DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    }

    const uint32_t data_len =
            buffer->inspect_len;

    const uint8_t *data =
            buffer->inspect;

    const uint64_t offset =
            buffer->inspect_offset;

    uint8_t ci_flags =
            eof ? DETECT_CI_FLAGS_END : 0;

    ci_flags |=
            (offset == 0 ? DETECT_CI_FLAGS_START : 0);

    ci_flags |= buffer->flags;

    const bool match =
            DetectEngineContentInspection(
                    de_ctx,
                    det_ctx,
                    s,
                    engine->smd,
                    NULL,
                    f,
                    data,
                    data_len,
                    offset,
                    ci_flags,
                    DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);

    if (match) {
        return DETECT_ENGINE_INSPECT_SIG_MATCH;
    }

    /*
     * Critical streaming behavior:
     *
     * BODY still active:
     *     NO_MATCH
     *     -> try this signature again when more body arrives.
     *
     * BODY finished:
     *     CANT_MATCH
     *     -> no more request-body data can help.
     */
    if (AppLayerParserGetStateProgress(
                IPPROTO_TCP,
                ALPROTO_HTTP1,
                txv,
                flags) > HTP_REQUEST_PROGRESS_BODY) {

        return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
    }

    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}
