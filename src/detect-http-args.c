#include "suricata-common.h"
#include "threads.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"

#include "flow.h"

#include "util-debug.h"

#include "app-layer.h"
#include "app-layer-htp.h"

#include "detect-http-args.h"
#include "stream-tcp.h"

static int g_http_args_buffer_id = 0;

static int DetectHttpArgsSetup(
        DetectEngineCtx *de_ctx, Signature *s, const char *str);

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f,
        const uint8_t flow_flags, void *txv, const int list_id);


/**
 * \brief Register the http.args sticky buffer.
 */
void DetectHttpArgsRegister(void)
{
    sigmatch_table[DETECT_HTTP_ARGS].name = "http.args";

    sigmatch_table[DETECT_HTTP_ARGS].desc =
            "sticky buffer containing HTTP request arguments";

    sigmatch_table[DETECT_HTTP_ARGS].Setup = DetectHttpArgsSetup;

    sigmatch_table[DETECT_HTTP_ARGS].flags |=
            SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister(
            "http_args",
            ALPROTO_HTTP1,
            SIG_FLAG_TOSERVER,
            HTP_REQUEST_PROGRESS_LINE,
            DetectEngineInspectBufferGeneric,
            GetData);

    DetectAppLayerMpmRegister(
            "http_args",
            SIG_FLAG_TOSERVER,
            2,
            PrefilterGenericMpmRegister,
            GetData,
            ALPROTO_HTTP1,
            HTP_REQUEST_PROGRESS_LINE);

    DetectBufferTypeSetDescriptionByName(
            "http_args",
            "HTTP request arguments");

    g_http_args_buffer_id =
            DetectBufferTypeGetByName("http_args");
}


/**
 * \brief Activate the http.args sticky buffer.
 */
static int DetectHttpArgsSetup(
        DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (SCDetectBufferSetActiveList(
                de_ctx, s, g_http_args_buffer_id) < 0) {
        return -1;
    }

    if (SCDetectSignatureSetAppProto(s, ALPROTO_HTTP) < 0) {
        return -1;
    }

    return 0;
}


/**
 * \brief Populate http.args from the URI query string.
 *
 * Example:
 *
 *     GET /login?username=john&role=admin HTTP/1.1
 *
 * produces:
 *
 *     username=john&role=admin
 */
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f,
        const uint8_t flow_flags, void *txv, const int list_id)
{
    InspectionBuffer *buffer =
            InspectionBufferGet(det_ctx, list_id);

    if (!buffer->initialized) {
        htp_tx_t *tx = (htp_tx_t *)txv;

        const htp_uri_t *uri =
                htp_tx_parsed_uri(tx);

        if (uri == NULL) {
            return NULL;
        }

        const bstr *query =
                htp_uri_query(uri);

        if (query == NULL) {
            return NULL;
        }

        const size_t query_len = bstr_len(query);

        if (query_len == 0 ||
                query_len > UINT32_MAX) {
            return NULL;
        }

        const uint8_t *query_data =
                bstr_ptr(query);

        if (query_data == NULL) {
            return NULL;
        }

        InspectionBufferSetupAndApplyTransforms(
                det_ctx,
                list_id,
                buffer,
                query_data,
                (uint32_t)query_len,
                transforms);
    }

    return buffer;
}
