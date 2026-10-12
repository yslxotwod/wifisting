/* ==================================================================== */
/*  LIVE TRAFFIC INSPECTOR - 28_live_traffic                            */
/*  Included by main.c, not compiled standalone.                        */
/* ==================================================================== */

typedef enum {
    LT_BEACON = 0,
    LT_PROBE_REQ,
    LT_PROBE_RESP,
    LT_AUTH_ASSOC,
    LT_DEAUTH_DISASSOC,
    LT_DATA,
    LT_EAPOL,
    LT_OTHER,
    LT_N
} LiveKind;

typedef struct {
    guint     num;
    gint64    ts_usec;
    guint8    kind;
    guint16   subtype;
    char      sa[20];
    char      da[20];
    char      bssid[20];
    char      ssid[40];
    int       channel;
    int       signal_dbm;
    char      eapol_type[6];
    gboolean  pmkid;
} LiveFrame;

typedef struct {
    AppState *state;

    GtkWidget *lbl_iface;
    GtkWidget *lbl_channel;
    GtkWidget *lbl_count;
    GtkWidget *lbl_status;

    GtkWidget *btn_start;
    GtkWidget *btn_stop;
    GtkWidget *btn_pause;
    GtkWidget *btn_clear;
    GtkWidget *entry_lock;
    GtkWidget *btn_lock;
    GtkWidget *chk_pcap;
    GtkWidget *entry_pcap;

    GtkWidget *tog[LT_N];
    GtkWidget *entry_mac;
    GtkWidget *entry_ssid;
    GtkWidget *spin_dbm;
    GtkWidget *btn_apply;
    GtkWidget *btn_reset;

    GtkWidget *list;
    GtkWidget *scroll;

    GPtrArray *pending;
    guint      flush_id;
    guint      poll_id;
    gboolean   running;
    gboolean   paused;
    gboolean   destroyed;

    gboolean   kind_enabled[LT_N];
    gchar     *filter_mac;
    gchar     *filter_ssid;
    int        min_dbm;

    GSubprocess      *stream_proc;
    GSubprocess      *pcap_proc;
    GDataInputStream *stream;
    GCancellable     *cancel;

    guint64    total_seen;
    guint64    total_rendered;

    gchar     *iface;
    gchar     *iface_type;
    gchar     *pcap_path;

    int        warnings_seen;
    gboolean   saw_any_data;
    GtkWidget   *iface_dd;      /* GtkDropDown, not an entry */
    GtkStringList *iface_names; /* index -> interface name */
} LiveTrafficPage;

/* Defined with the other picker helpers; the stream start path above them
   reads the selected interface, so it needs the declaration here. */
static const gchar *live_iface_picked(LiveTrafficPage *p);

#define LIVE_PENDING_CAP  1500
#define LIVE_VISIBLE_CAP  800
#define LIVE_FLUSH_BATCH  150
#define LIVE_FLUSH_MS     100


static GPtrArray *
live_list_monitor_ifaces(void)
{
    g_autoptr(GError) error = NULL;
    g_autofree gchar *out = NULL;
    g_autofree gchar *err = NULL;
    GPtrArray *result = g_ptr_array_new_with_free_func(g_free);
    const gchar *argv[] = { "iw", "dev", NULL };
    GSubprocess *proc;

    proc = g_subprocess_newv(argv,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_SILENCE,
        &error);
    if (proc == NULL) return result;

    if (!g_subprocess_communicate_utf8(
            proc, NULL, NULL, &out, &err, &error)) {
        g_object_unref(proc);
        return result;
    }
    g_object_unref(proc);
    if (out == NULL) return result;

    {
        g_auto(GStrv) lines = g_strsplit(out, "\n", -1);
        g_autofree gchar *cur_iface = NULL;
        for (guint i = 0; lines[i] != NULL; i++) {
            const gchar *l = lines[i];
            while (*l == ' ' || *l == '\t') l++;
            if (g_str_has_prefix(l, "Interface ")) {
                g_free(cur_iface);
                cur_iface = g_strdup(l + strlen("Interface "));
                g_strstrip(cur_iface);
            } else if (g_str_has_prefix(l, "type monitor") &&
                       cur_iface != NULL && *cur_iface != '\0') {
                g_ptr_array_add(result, g_strdup(cur_iface));
            }
        }
    }
    return result;
}

static void live_traffic_install_css(void);

static void
live_frame_free(gpointer data)
{
    g_free(data);
}

static const char *
live_kind_name(LiveKind k)
{
    switch (k) {
        case LT_BEACON:          return "BEACON";
        case LT_PROBE_REQ:       return "PROBE-REQ";
        case LT_PROBE_RESP:      return "PROBE-RESP";
        case LT_AUTH_ASSOC:      return "AUTH/ASSOC";
        case LT_DEAUTH_DISASSOC: return "DEAUTH";
        case LT_DATA:            return "DATA";
        case LT_EAPOL:           return "EAPOL";
        default:                 return "OTHER";
    }
}

static const char *
live_kind_css(LiveKind k)
{
    switch (k) {
        case LT_BEACON:          return "lt-row-beacon";
        case LT_PROBE_REQ:       return "lt-row-probe";
        case LT_PROBE_RESP:      return "lt-row-probe";
        case LT_AUTH_ASSOC:      return "lt-row-auth";
        case LT_DEAUTH_DISASSOC: return "lt-row-deauth";
        case LT_DATA:            return "lt-row-data";
        case LT_EAPOL:           return "lt-row-eapol";
        default:                 return "lt-row-other";
    }
}

static LiveKind
live_classify(guint16 subtype, const char *eapol_type, gboolean pmkid)
{
    guint8 t = (subtype >> 4) & 0x03;
    guint8 s = subtype & 0x0F;

    if (eapol_type != NULL && *eapol_type != '\0') return LT_EAPOL;
    if (pmkid) return LT_EAPOL;

    if (t == 0) {
        switch (s) {
            case 0x04: return LT_PROBE_REQ;
            case 0x05: return LT_PROBE_RESP;
            case 0x08: return LT_BEACON;
            case 0x00: case 0x01: case 0x02: case 0x03: case 0x0b:
                return LT_AUTH_ASSOC;
            case 0x0a: case 0x0c:
                return LT_DEAUTH_DISASSOC;
            default: return LT_OTHER;
        }
    }
    if (t == 2) return LT_DATA;
    return LT_OTHER;
}


/* tshark hex-encodes wlan.ssid when it contains non-printable bytes
   (padding zeros, etc.). Decode back to a printable string if the
   input looks like pure hex and the decoded bytes are all printable.
   Otherwise return a copy of the input unchanged. */
static gchar *
live_maybe_hex_decode(const gchar *in)
{
    gsize n, i;
    gchar *out;
    gboolean all_hex;

    if (in == NULL || *in == '\0') return g_strdup("");

    n = strlen(in);
    if (n < 2 || (n & 1) != 0) return g_strdup(in);

    all_hex = TRUE;
    for (i = 0; i < n; i++) {
        if (!g_ascii_isxdigit(in[i])) { all_hex = FALSE; break; }
    }
    if (!all_hex) return g_strdup(in);

    /* NOTE: plain g_malloc0, NOT g_autofree. We return this pointer
       directly to the caller on the happy path. The g_autofree
       cleanup at function-exit would free the same pointer right
       before returning, which is a double-free the moment the
       caller tries to use it (and glibc detects a second later). */
    out = g_malloc0(n / 2 + 1);
    for (i = 0; i < n; i += 2) {
        gchar hi = in[i], lo = in[i + 1];
        guint8 v = ((hi >= '0' && hi <= '9') ? hi - '0'
                   : (hi | 0x20) - 'a' + 10) << 4;
        v |= (lo >= '0' && lo <= '9') ? lo - '0'
             : (lo | 0x20) - 'a' + 10;
        out[i / 2] = (gchar) v;
    }

    /* If decoded bytes aren't all printable ASCII, fall back to the
       original hex string. Free `out` explicitly — no autoptr. */
    for (i = 0; i < n / 2; i++) {
        if ((guint8) out[i] < 0x20 || (guint8) out[i] > 0x7e) {
            g_free(out);
            return g_strdup(in);
        }
    }
    return out;
}


/* Replace anything that isn't valid UTF-8 with '?'. GTK/Pango will
   abort on invalid UTF-8 passed to gtk_label_new, and tshark
   occasionally emits SSID bytes that don't form valid UTF-8. */
static gchar *
live_utf8_sanitize(const gchar *in)
{
    const gchar *end;
    GString *out;

    if (in == NULL) return g_strdup("");
    if (g_utf8_validate(in, -1, &end)) return g_strdup(in);

    out = g_string_new(NULL);
    {
        const gchar *p = in;
        while (*p) {
            if (g_utf8_validate(p, -1, &end)) {
                /* Rest is valid; append and stop */
                g_string_append(out, p);
                break;
            }
            if (end > p) {
                /* Valid prefix before the invalid byte */
                g_string_append_len(out, p, end - p);
            }
            g_string_append_c(out, '?');
            p = end + 1;  /* skip the invalid byte */
        }
    }
    return g_string_free(out, FALSE);
}

static LiveFrame *
live_parse_line(const char *line)
{
    g_auto(GStrv) f = NULL;
    guint n;
    LiveFrame *fr;
    const char *num_s = "", *ts_s = "", *sub_s = "";
    const char *sa_s = "", *da_s = "", *bs_s = "", *ss_s = "";
    const char *ch_s = "", *sig_s = "", *eap_s = "", *pmk_s = "";
    guint16 subtype = 0;
    gboolean pmkid = FALSE;

    if (line == NULL || *line == '\0') return NULL;

    f = g_strsplit(line, "\t", -1);
    n = g_strv_length(f);
    if (n < 3) return NULL;

    if (n > 0)  num_s = f[0];
    if (n > 1)  ts_s  = f[1];
    if (n > 2)  sub_s = f[2];
    if (n > 3)  sa_s  = f[3];
    if (n > 4)  da_s  = f[4];
    if (n > 5)  bs_s  = f[5];
    if (n > 6)  ss_s  = f[6];
    if (n > 7)  ch_s  = f[7];
    if (n > 8)  sig_s = f[8];
    if (n > 9)  eap_s = f[9];
    if (n > 10) pmk_s = f[10];

    if (*sub_s) {
        if (sub_s[0] == '0' && (sub_s[1] == 'x' || sub_s[1] == 'X'))
            subtype = (guint16) g_ascii_strtoull(sub_s + 2, NULL, 16);
        else
            subtype = (guint16) g_ascii_strtoull(sub_s, NULL, 10);
    }
    if (*pmk_s) pmkid = TRUE;

    fr = g_new0(LiveFrame, 1);
    fr->num      = (guint) g_ascii_strtoull(num_s, NULL, 10);
    fr->ts_usec  = (*ts_s)
        ? (gint64)(g_ascii_strtod(ts_s, NULL) * 1000000.0) : 0;
    fr->subtype  = subtype;
    fr->kind     = (guint8) live_classify(subtype, eap_s, pmkid);
    g_strlcpy(fr->sa,    *sa_s  ? sa_s  : "", sizeof fr->sa);
    g_strlcpy(fr->da,    *da_s  ? da_s  : "", sizeof fr->da);
    g_strlcpy(fr->bssid, *bs_s  ? bs_s  : "", sizeof fr->bssid);
    {
        g_autofree gchar *ssid_decoded =
            live_maybe_hex_decode(*ss_s ? ss_s : "");
        g_autofree gchar *ssid_clean =
            live_utf8_sanitize(ssid_decoded);
        g_strlcpy(fr->ssid, ssid_clean, sizeof fr->ssid);
    }
    fr->channel    = (*ch_s)  ? atoi(ch_s)  : 0;
    fr->signal_dbm = (*sig_s) ? atoi(sig_s) : 0;
    g_strlcpy(fr->eapol_type, *eap_s ? eap_s : "", sizeof fr->eapol_type);
    fr->pmkid      = pmkid;
    return fr;
}

static gboolean
live_frame_passes(const LiveTrafficPage *p, const LiveFrame *fr)
{
    if (fr->kind < LT_N && !p->kind_enabled[fr->kind]) return FALSE;

    if (p->filter_mac != NULL && *p->filter_mac != '\0') {
        g_autofree gchar *needle = g_utf8_strdown(p->filter_mac, -1);
        g_autofree gchar *sa = g_utf8_strdown(fr->sa, -1);
        g_autofree gchar *da = g_utf8_strdown(fr->da, -1);
        g_autofree gchar *bs = g_utf8_strdown(fr->bssid, -1);
        if (!strstr(sa, needle) && !strstr(da, needle) &&
            !strstr(bs, needle))
            return FALSE;
    }

    if (p->filter_ssid != NULL && *p->filter_ssid != '\0') {
        g_autofree gchar *needle = g_utf8_strdown(p->filter_ssid, -1);
        g_autofree gchar *hay = g_utf8_strdown(fr->ssid, -1);
        if (!strstr(hay, needle)) return FALSE;
    }

    if (p->min_dbm != 0 && fr->signal_dbm != 0 &&
        fr->signal_dbm < p->min_dbm)
        return FALSE;

    return TRUE;
}

static GtkWidget *
live_build_row(LiveTrafficPage *p, LiveFrame *fr)
{
    GtkWidget *row = gtk_list_box_row_new();
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *l_num, *l_ts, *l_kind, *l_sa, *l_da, *l_bs, *l_ss;
    GtkWidget *l_ch, *l_sig, *l_extra;
    g_autofree gchar *num_s = g_strdup_printf("%u", fr->num);
    g_autofree gchar *ts_s = NULL;
    g_autofree gchar *ch_s = g_strdup_printf("%d", fr->channel);
    g_autofree gchar *sig_s = (fr->signal_dbm != 0)
        ? g_strdup_printf("%d", fr->signal_dbm) : g_strdup("--");
    g_autofree gchar *extra = NULL;

    {
        g_autoptr(GDateTime) dt = fr->ts_usec
            ? g_date_time_new_from_unix_local(fr->ts_usec / 1000000)
            : NULL;
        ts_s = dt ? g_date_time_format(dt, "%H:%M:%S")
                  : g_strdup("--:--:--");
    }

    if (fr->pmkid) {
        extra = g_strdup("PMKID");
    } else if (fr->eapol_type[0]) {
        extra = g_strdup_printf("EAPOL t=%s", fr->eapol_type);
    } else {
        extra = g_strdup("");
    }

    l_num   = gtk_label_new(num_s);
    l_ts    = gtk_label_new(ts_s);
    l_kind  = gtk_label_new(live_kind_name((LiveKind) fr->kind));
    l_sa    = gtk_label_new(fr->sa);
    l_da    = gtk_label_new(fr->da);
    l_bs    = gtk_label_new(fr->bssid);
    l_ss    = gtk_label_new(fr->ssid);
    l_ch    = gtk_label_new(ch_s);
    l_sig   = gtk_label_new(sig_s);
    l_extra = gtk_label_new(extra);

    gtk_widget_set_size_request(l_num,   60, -1);
    gtk_widget_set_size_request(l_ts,    70, -1);
    gtk_widget_set_size_request(l_kind,  90, -1);
    gtk_widget_set_size_request(l_sa,   130, -1);
    gtk_widget_set_size_request(l_da,   130, -1);
    gtk_widget_set_size_request(l_bs,   130, -1);
    gtk_widget_set_size_request(l_ss,   140, -1);
    gtk_widget_set_size_request(l_ch,    30, -1);
    gtk_widget_set_size_request(l_sig,   40, -1);

    gtk_label_set_xalign(GTK_LABEL(l_num),   0.0f);
    gtk_label_set_xalign(GTK_LABEL(l_ts),    0.0f);
    gtk_label_set_xalign(GTK_LABEL(l_kind),  0.0f);
    gtk_label_set_xalign(GTK_LABEL(l_sa),    0.0f);
    gtk_label_set_xalign(GTK_LABEL(l_da),    0.0f);
    gtk_label_set_xalign(GTK_LABEL(l_bs),    0.0f);
    gtk_label_set_xalign(GTK_LABEL(l_ss),    0.0f);
    gtk_label_set_xalign(GTK_LABEL(l_ch),    0.0f);
    gtk_label_set_xalign(GTK_LABEL(l_sig),   0.0f);
    gtk_label_set_xalign(GTK_LABEL(l_extra), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(l_ss), PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(l_ss, TRUE);

    gtk_widget_add_css_class(row,     "lt-row");
    gtk_widget_add_css_class(row,     live_kind_css((LiveKind) fr->kind));
    gtk_widget_add_css_class(box,     "lt-row-inner");
    gtk_widget_add_css_class(l_num,   "lt-mono");
    gtk_widget_add_css_class(l_ts,    "lt-mono");
    gtk_widget_add_css_class(l_kind,  "lt-kind");
    {
        static const char *kcls[LT_N] = {
            "lt-kind-beacon", "lt-kind-probe", "lt-kind-probe",
            "lt-kind-auth", "lt-kind-deauth", "lt-kind-data",
            "lt-kind-eapol", "lt-kind-other"
        };
        if (fr->kind < LT_N)
            gtk_widget_add_css_class(l_kind, kcls[fr->kind]);
    }
    gtk_widget_add_css_class(l_sa,    "lt-mono");
    gtk_widget_add_css_class(l_da,    "lt-mono");
    gtk_widget_add_css_class(l_bs,    "lt-mono");
    gtk_widget_add_css_class(l_ss,    "lt-ssid");
    gtk_widget_add_css_class(l_ch,    "lt-mono");
    gtk_widget_add_css_class(l_sig,   "lt-mono");
    gtk_widget_add_css_class(l_extra, "lt-extra");

    gtk_box_append(GTK_BOX(box), l_num);
    gtk_box_append(GTK_BOX(box), l_ts);
    gtk_box_append(GTK_BOX(box), l_kind);
    gtk_box_append(GTK_BOX(box), l_sa);
    gtk_box_append(GTK_BOX(box), l_da);
    gtk_box_append(GTK_BOX(box), l_bs);
    gtk_box_append(GTK_BOX(box), l_ss);
    gtk_box_append(GTK_BOX(box), l_ch);
    gtk_box_append(GTK_BOX(box), l_sig);
    gtk_box_append(GTK_BOX(box), l_extra);

    gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), box);

    g_object_set_data_full(G_OBJECT(row), "lt-sa",
                           g_strdup(fr->sa), g_free);
    g_object_set_data_full(G_OBJECT(row), "lt-da",
                           g_strdup(fr->da), g_free);
    g_object_set_data_full(G_OBJECT(row), "lt-bssid",
                           g_strdup(fr->bssid), g_free);
    g_object_set_data_full(G_OBJECT(row), "lt-channel",
                           g_strdup(ch_s), g_free);
    g_object_set_data(G_OBJECT(row), "lt-manager", p);

    return row;
}

static guint
live_visible_count(GtkWidget *list)
{
    guint n = 0;
    GtkWidget *c;
    if (list == NULL) return 0;
    c = gtk_widget_get_first_child(list);
    while (c != NULL) { n++; c = gtk_widget_get_next_sibling(c); }
    return n;
}

static gboolean
live_flush_cb(gpointer user_data)
{
    LiveTrafficPage *p = user_data;
    guint i, n_flush;

    if (p->destroyed) { p->flush_id = 0; return G_SOURCE_REMOVE; }

    if (p->paused || p->list == NULL || p->pending == NULL)
        return G_SOURCE_CONTINUE;

    n_flush = MIN(p->pending->len, LIVE_FLUSH_BATCH);
    for (i = 0; i < n_flush; i++) {
        /* Peek — don't remove yet. If we remove first, the array's
           free_func destroys the frame, and the next line
           dereferences a freed pointer. */
        LiveFrame *fr = g_ptr_array_index(p->pending, 0);

        if (live_frame_passes(p, fr)) {
            GtkWidget *row = live_build_row(p, fr);
            gtk_list_box_append(GTK_LIST_BOX(p->list), row);
            p->total_rendered++;
        }
        /* Now remove: free_func fires once, here, and only here. */
        g_ptr_array_remove_index(p->pending, 0);
    }

    while (live_visible_count(p->list) > LIVE_VISIBLE_CAP) {
        GtkWidget *first = gtk_widget_get_first_child(p->list);
        if (first == NULL) break;
        gtk_list_box_remove(GTK_LIST_BOX(p->list), first);
    }

    if (p->lbl_count != NULL) {
        g_autofree gchar *s = g_strdup_printf(
            "%" G_GUINT64_FORMAT " seen  -  %u shown",
            p->total_seen, live_visible_count(p->list));
        gtk_label_set_text(GTK_LABEL(p->lbl_count), s);
    }

    return G_SOURCE_CONTINUE;
}

static void live_read_next(LiveTrafficPage *p);

static void
live_read_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    LiveTrafficPage *p = user_data;
    g_autoptr(GError) error = NULL;
    gsize len = 0;
    gchar *line;

    if (p->destroyed) return;

    line = g_data_input_stream_read_line_finish(
        G_DATA_INPUT_STREAM(source), result, &len, &error);

    if (line == NULL) {
        gboolean was_cancelled =
            (error != NULL &&
             g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED));

        if (p->stream == G_DATA_INPUT_STREAM(source)) {
            g_object_unref(p->stream);
            p->stream = NULL;
        }

        if (!was_cancelled) {
            if (p->saw_any_data) {
                append_event(p->state, "Live: stream ended");
            } else if (error != NULL) {
                g_autofree gchar *m = g_strdup_printf(
                    "Live: stream ended immediately: %s",
                    error->message);
                append_event(p->state, m);
            } else {
                append_event(p->state,
                    "Live: stream ended immediately "
                    "(no frames received)");
            }
        }

        p->running = FALSE;
        if (p->btn_start != NULL)
            gtk_widget_set_sensitive(p->btn_start, TRUE);
        if (p->btn_stop != NULL)
            gtk_widget_set_sensitive(p->btn_stop, FALSE);
        if (p->lbl_status != NULL) {
            gtk_label_set_text(GTK_LABEL(p->lbl_status),
                p->saw_any_data ? "stopped" : "no frames");
        }
        return;
    }

    if (*line != '\0') {
        LiveFrame *fr = live_parse_line(line);
        if (fr != NULL) {
            p->total_seen++;
            p->saw_any_data = TRUE;
            if (p->lbl_status != NULL)
                gtk_label_set_text(GTK_LABEL(p->lbl_status), "running");
            /* pending is the sole owner. remove_index fires its
               free_func if we exceed the cap, freeing the oldest
               frame. ring was redundant — dropped. */
            if (p->pending->len >= LIVE_PENDING_CAP)
                g_ptr_array_remove_index(p->pending, 0);
            g_ptr_array_add(p->pending, fr);
        } else if (p->warnings_seen < 12) {
            g_autofree gchar *m = g_strdup_printf("live: %s", line);
            append_event(p->state, m);
            p->warnings_seen++;
            if (p->warnings_seen == 12) {
                append_event(p->state,
                    "live: further stderr suppressed");
            }
        }
    }
    g_free(line);
    live_read_next(p);
}

static void
live_read_next(LiveTrafficPage *p)
{
    if (p->destroyed || p->stream == NULL) return;
    g_data_input_stream_read_line_async(
        p->stream, G_PRIORITY_DEFAULT, p->cancel, live_read_cb, p);
}

static void
live_start_pcap(LiveTrafficPage *p, const gchar *path)
{
    g_autoptr(GError) error = NULL;
    const gchar *argv[16];
    guint i = 0;

    if (p->pcap_proc != NULL) return;
    if (path == NULL || *path == '\0') return;
    if (p->iface == NULL || *p->iface == '\0') return;

    argv[i++] = "pkexec";
    argv[i++] = "env";
    argv[i++] = "WIFISTING_ROOT=" PROJECT_DIR;
    argv[i++] = "WIFISTING_STATE=" PROJECT_DIR "/state";
    argv[i++] = "WIFISTING_HOME=" PROJECT_DIR;
    argv[i++] = "TMP_DIR=/tmp/wifisting";
    argv[i++] = "HOME=" PROJECT_DIR;
    argv[i++] = LIVE_TRAFFIC_SCRIPT;
    argv[i++] = "--save-pcap";
    argv[i++] = p->iface;
    argv[i++] = path;
    argv[i]   = NULL;

    p->pcap_proc = g_subprocess_newv(
        argv, G_SUBPROCESS_FLAGS_NONE, &error);
    if (p->pcap_proc == NULL) {
        g_autofree gchar *m = g_strdup_printf(
            "Live pcap start failed: %s",
            error ? error->message : "unknown");
        append_event(p->state, m);
    }
}

static void
live_stop_pcap(LiveTrafficPage *p)
{
    if (p->pcap_proc != NULL) {
        g_subprocess_force_exit(p->pcap_proc);
        g_clear_object(&p->pcap_proc);
    }
}

static void
live_start_stream(LiveTrafficPage *p)
{
    g_autoptr(GError) error = NULL;
    GInputStream *raw;
    const gchar *argv[16];
    guint i = 0;

    {
        const gchar *picked = live_iface_picked(p);
        if (picked != NULL && *picked != '\0') {
            g_free(p->iface);
            p->iface = g_strdup(picked);
        }
    }

    if (p->iface == NULL || *p->iface == '\0') {
        append_event(p->state, "Live: no interface");
        return;
    }
    if (p->running) return;

    if (p->cancel != NULL) {
        g_object_unref(p->cancel);
        p->cancel = NULL;
    }
    p->cancel = g_cancellable_new();
    p->saw_any_data = FALSE;

    argv[i++] = "pkexec";
    argv[i++] = "env";
    argv[i++] = "WIFISTING_ROOT=" PROJECT_DIR;
    argv[i++] = "WIFISTING_STATE=" PROJECT_DIR "/state";
    argv[i++] = "WIFISTING_HOME=" PROJECT_DIR;
    argv[i++] = "TMP_DIR=/tmp/wifisting";
    argv[i++] = "HOME=" PROJECT_DIR;
    argv[i++] = LIVE_TRAFFIC_SCRIPT;
    argv[i++] = "--stream";
    argv[i++] = p->iface;
    argv[i]   = NULL;

    p->stream_proc = g_subprocess_newv(
        argv,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE |
        G_SUBPROCESS_FLAGS_STDERR_MERGE,
        &error);

    if (p->stream_proc == NULL) {
        g_autofree gchar *m = g_strdup_printf(
            "Live: could not start tshark: %s",
            error ? error->message : "unknown");
        append_event(p->state, m);
        if (p->lbl_status != NULL)
            gtk_label_set_text(GTK_LABEL(p->lbl_status), "start failed");
        return;
    }

    raw = g_subprocess_get_stdout_pipe(p->stream_proc);
    p->stream = g_data_input_stream_new(raw);
    g_data_input_stream_set_newline_type(
        p->stream, G_DATA_STREAM_NEWLINE_TYPE_LF);
    g_object_unref(raw);

    p->running = TRUE;
    if (p->btn_start != NULL)
        gtk_widget_set_sensitive(p->btn_start, FALSE);
    if (p->btn_stop != NULL)
        gtk_widget_set_sensitive(p->btn_stop, TRUE);
    if (p->lbl_status != NULL)
        gtk_label_set_text(GTK_LABEL(p->lbl_status), "starting");

    live_read_next(p);
}

static void
live_stop_stream(LiveTrafficPage *p)
{
    if (!p->running && p->stream_proc == NULL && p->stream == NULL)
        return;

    if (p->cancel != NULL) {
        g_cancellable_cancel(p->cancel);
    }
    if (p->stream_proc != NULL) {
        g_subprocess_force_exit(p->stream_proc);
        g_clear_object(&p->stream_proc);
    }

    {
        g_autoptr(GError) error = NULL;
        const gchar *argv[] = {
            "pkexec", LIVE_TRAFFIC_SCRIPT, "--stop", NULL
        };
        GSubprocess *k = g_subprocess_newv(
            argv, G_SUBPROCESS_FLAGS_NONE, &error);
        if (k != NULL) g_object_unref(k);
    }

    p->running = FALSE;
    if (p->btn_start != NULL)
        gtk_widget_set_sensitive(p->btn_start, TRUE);
    if (p->btn_stop != NULL)
        gtk_widget_set_sensitive(p->btn_stop, FALSE);
    if (p->lbl_status != NULL)
        gtk_label_set_text(GTK_LABEL(p->lbl_status), "stopped");
}

static void
live_parse_status_into_page(LiveTrafficPage *p, const char *out)
{
    g_autofree gchar *iface = NULL;
    g_autofree gchar *itype = NULL;
    g_autofree gchar *chan  = NULL;
    g_auto(GStrv) lines = NULL;

    if (out == NULL) return;
    lines = g_strsplit(out, "\n", -1);
    for (guint i = 0; lines[i] != NULL; i++) {
        g_auto(GStrv) kv = g_strsplit(lines[i], "\t", 2);
        if (g_strv_length(kv) != 2) continue;
        if (g_strcmp0(kv[0], "iface") == 0) {
            g_free(iface); iface = g_strdup(kv[1]);
        } else if (g_strcmp0(kv[0], "iface_type") == 0) {
            g_free(itype); itype = g_strdup(kv[1]);
        } else if (g_strcmp0(kv[0], "channel") == 0) {
            g_free(chan); chan = g_strdup(kv[1]);
        }
    }

    if (live_iface_picked(p) == NULL) {
        g_free(p->iface);  p->iface = g_strdup(iface);
    }
    g_free(p->iface_type); p->iface_type = g_strdup(itype);

    if (p->lbl_iface != NULL) {
        g_autofree gchar *s = g_strdup_printf(
            "iface: %s (%s)",
            (iface && *iface) ? iface : "-",
            (itype && *itype) ? itype : "unknown");
        gtk_label_set_text(GTK_LABEL(p->lbl_iface), s);
    }
    if (p->lbl_channel != NULL) {
        g_autofree gchar *s = g_strdup_printf(
            "channel: %s", (chan && *chan) ? chan : "-");
        gtk_label_set_text(GTK_LABEL(p->lbl_channel), s);
    }

    if (p->lbl_status != NULL && itype != NULL &&
        g_strcmp0(itype, "monitor") != 0) {
        gtk_label_set_text(GTK_LABEL(p->lbl_status),
                           "iface not in monitor mode");
        gtk_widget_add_css_class(p->lbl_status, "lt-status-warn");
    } else if (p->lbl_status != NULL) {
        gtk_widget_remove_css_class(p->lbl_status, "lt-status-warn");
    }
}

static void
live_poll_finished(GObject *source, GAsyncResult *result, gpointer user_data)
{
    LiveTrafficPage *p = user_data;
    g_autoptr(GError) error = NULL;
    g_autofree gchar *out = NULL;
    g_autofree gchar *err = NULL;

    if (p->destroyed) return;
    if (!g_subprocess_communicate_utf8_finish(
            G_SUBPROCESS(source), result, &out, &err, &error)) {
        return;
    }
    live_parse_status_into_page(p, out);
}

static gboolean
live_poll_cb(gpointer user_data)
{
    LiveTrafficPage *p = user_data;
    g_autoptr(GError) error = NULL;
    GSubprocess *proc;
    const gchar *argv[] = { LIVE_TRAFFIC_SCRIPT, "--status-tsv", NULL };

    if (p->destroyed) { p->poll_id = 0; return G_SOURCE_REMOVE; }

    proc = g_subprocess_newv(
        argv,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE |
        G_SUBPROCESS_FLAGS_STDERR_SILENCE,
        &error);
    if (proc == NULL) return G_SOURCE_CONTINUE;

    g_subprocess_communicate_utf8_async(
        proc, NULL, NULL, live_poll_finished, p);
    g_object_unref(proc);
    return G_SOURCE_CONTINUE;
}

static void
live_start_clicked(GtkButton *b, gpointer user_data)
{
    LiveTrafficPage *p = user_data;
    (void) b;

    if (p->chk_pcap != NULL &&
        gtk_check_button_get_active(GTK_CHECK_BUTTON(p->chk_pcap)) &&
        p->entry_pcap != NULL) {
        const gchar *path = gtk_editable_get_text(
            GTK_EDITABLE(p->entry_pcap));
        if (path != NULL && *path != '\0') {
            g_free(p->pcap_path);
            p->pcap_path = g_strdup(path);
            live_start_pcap(p, path);
        }
    }

    live_start_stream(p);
}

static void
live_stop_clicked(GtkButton *b, gpointer user_data)
{
    LiveTrafficPage *p = user_data;
    (void) b;
    live_stop_stream(p);
    live_stop_pcap(p);
}

static void
live_pause_clicked(GtkButton *b, gpointer user_data)
{
    LiveTrafficPage *p = user_data;
    (void) b;
    p->paused = !p->paused;
    if (p->btn_pause != NULL)
        gtk_button_set_label(GTK_BUTTON(p->btn_pause),
                             p->paused ? "Resume" : "Pause");
}

static void
live_clear_clicked(GtkButton *b, gpointer user_data)
{
    LiveTrafficPage *p = user_data;
    GtkWidget *child, *next;
    (void) b;

    if (p->list == NULL) return;
    child = gtk_widget_get_first_child(p->list);
    while (child != NULL) {
        next = gtk_widget_get_next_sibling(child);
        gtk_list_box_remove(GTK_LIST_BOX(p->list), child);
        child = next;
    }
    if (p->pending != NULL) g_ptr_array_set_size(p->pending, 0);
    p->total_seen = 0;
    p->total_rendered = 0;
    if (p->lbl_count != NULL)
        gtk_label_set_text(GTK_LABEL(p->lbl_count), "0 seen");
}

static void
live_lock_clicked(GtkButton *b, gpointer user_data)
{
    LiveTrafficPage *p = user_data;
    g_autoptr(GError) error = NULL;
    const gchar *ch;
    GSubprocess *proc;
    (void) b;

    if (p->iface == NULL || *p->iface == '\0') return;
    if (p->entry_lock == NULL) return;

    ch = gtk_editable_get_text(GTK_EDITABLE(p->entry_lock));
    if (ch == NULL || *ch == '\0') return;

    {
        const gchar *argv[] = {
            "pkexec", LIVE_TRAFFIC_SCRIPT, "--lock-channel",
            p->iface, ch, NULL
        };
        proc = g_subprocess_newv(
            argv,
            G_SUBPROCESS_FLAGS_STDOUT_PIPE |
            G_SUBPROCESS_FLAGS_STDERR_SILENCE,
            &error);
    }
    if (proc == NULL) return;

    {
        g_autofree gchar *m = g_strdup_printf(
            "Live: lock %s -> ch %s", p->iface, ch);
        append_event(p->state, m);
    }
    g_object_unref(proc);
}


/* The interface picker is a dropdown, so callers ask it for the selected
   name rather than reading typed text. Returns NULL when nothing is
   selected, which the callers treat as "fall back to what the stream
   reports". */
static const gchar *
live_iface_picked(LiveTrafficPage *p)
{
    guint idx;

    if (p == NULL || p->iface_dd == NULL || p->iface_names == NULL)
        return NULL;
    idx = gtk_drop_down_get_selected(GTK_DROP_DOWN(p->iface_dd));
    if (idx == GTK_INVALID_LIST_POSITION)
        return NULL;
    return gtk_string_list_get_string(p->iface_names, idx);
}

/* Fill the picker from the module, which knows each interface's type. An
   interface in managed mode cannot capture, so showing the type next to the
   name explains a failure before it happens. */
static void
live_iface_dropdown_reload(LiveTrafficPage *p)
{
    g_autoptr(GError) error = NULL;
    g_autofree gchar *out = NULL;
    g_autofree gchar *err = NULL;
    const gchar *argv[] = { PROJECT_DIR "/modules/28_live_traffic.sh",
                            "--list-ifaces-tsv", NULL };
    GSubprocess *proc;
    gboolean ok;

    if (p == NULL || p->iface_names == NULL) return;

    proc = g_subprocess_newv(argv,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE,
        &error);
    if (proc == NULL) return;
    ok = g_subprocess_communicate_utf8(proc, NULL, NULL, &out, &err, &error);
    g_object_unref(proc);

    gtk_string_list_splice(p->iface_names, 0,
        g_list_model_get_n_items(G_LIST_MODEL(p->iface_names)), NULL);
    if (!ok || out == NULL) return;

    {
        g_auto(GStrv) lines = g_strsplit(out, "\n", -1);
        guint added = 0;
        for (guint i = 0; lines[i] != NULL; i++) {
            g_auto(GStrv) kv = g_strsplit(lines[i], "\t", 2);
            if (kv[0] == NULL || *kv[0] == '\0') continue;
            g_autofree gchar *label = (kv[1] != NULL && *kv[1] != '\0')
                ? g_strdup_printf("%s  (%s)", kv[0], kv[1])
                : g_strdup(kv[0]);
            gtk_string_list_append(p->iface_names, label);
            added++;
        }
        if (added > 0) gtk_drop_down_set_selected(GTK_DROP_DOWN(p->iface_dd), 0);
    }
}

static void
live_iface_rescan(GtkButton *b, gpointer ud)
{
    (void) b;
    live_iface_dropdown_reload((LiveTrafficPage *) ud);
}

static void
live_apply_filters_clicked(GtkButton *b, gpointer user_data)
{
    LiveTrafficPage *p = user_data;
    (void) b;

    for (int i = 0; i < LT_N; i++) {
        if (p->tog[i] != NULL)
            p->kind_enabled[i] = gtk_toggle_button_get_active(
                GTK_TOGGLE_BUTTON(p->tog[i]));
    }

    g_free(p->filter_mac);
    g_free(p->filter_ssid);
    p->filter_mac  = p->entry_mac
        ? g_strdup(gtk_editable_get_text(GTK_EDITABLE(p->entry_mac)))
        : NULL;
    p->filter_ssid = p->entry_ssid
        ? g_strdup(gtk_editable_get_text(GTK_EDITABLE(p->entry_ssid)))
        : NULL;
    p->min_dbm     = p->spin_dbm
        ? gtk_spin_button_get_value_as_int(
              GTK_SPIN_BUTTON(p->spin_dbm))
        : 0;

    live_clear_clicked(NULL, p);
    append_event(p->state, "Live: filters applied");
}

static void
live_reset_filters_clicked(GtkButton *b, gpointer user_data)
{
    LiveTrafficPage *p = user_data;
    (void) b;
    for (int i = 0; i < LT_N; i++) {
        if (p->tog[i] != NULL)
            gtk_toggle_button_set_active(
                GTK_TOGGLE_BUTTON(p->tog[i]), TRUE);
    }
    if (p->entry_mac != NULL)
        gtk_editable_set_text(GTK_EDITABLE(p->entry_mac), "");
    if (p->entry_ssid != NULL)
        gtk_editable_set_text(GTK_EDITABLE(p->entry_ssid), "");
    if (p->spin_dbm != NULL)
        gtk_spin_button_set_value(GTK_SPIN_BUTTON(p->spin_dbm), 0);
    live_apply_filters_clicked(NULL, p);
}

static void live_popover_closed(GtkPopover *pop, gpointer ud)
{
    (void) ud;
    gtk_widget_unparent(GTK_WIDGET(pop));
}

static void
live_copy_clicked(GtkButton *b, gpointer user_data)
{
    AppState *state = user_data;
    const gchar *t = g_object_get_data(G_OBJECT(b), "copy-text");
    GdkClipboard *cb;
    GtkWidget *pop;
    if (t == NULL) return;
    cb = gdk_display_get_clipboard(gdk_display_get_default());
    gdk_clipboard_set_text(cb, t);
    pop = gtk_widget_get_ancestor(GTK_WIDGET(b), GTK_TYPE_POPOVER);
    if (pop != NULL) gtk_popover_popdown(GTK_POPOVER(pop));
    show_toast(state, "Copied");
}

static void
live_set_target_clicked(GtkButton *b, gpointer user_data)
{
    LiveTrafficPage *p = user_data;
    const gchar *bssid = g_object_get_data(G_OBJECT(b), "bssid");
    const gchar *ssid  = g_object_get_data(G_OBJECT(b), "ssid");
    const gchar *chan  = g_object_get_data(G_OBJECT(b), "chan");
    g_autoptr(GError) error = NULL;
    GSubprocess *proc = NULL;
    GtkWidget *pop;

    if (bssid == NULL || *bssid == '\0') return;

    {
        const gchar *argv[] = {
            "bash", "-c",
            "\"$0\" --set-target \"$1\" \"$2\" \"$3\" \"$4\"",
            RECON_SCRIPT,
            bssid,
            chan ? chan : "",
            ssid ? ssid : "",
            "WPA2",
            NULL
        };
        proc = g_subprocess_newv(argv, G_SUBPROCESS_FLAGS_NONE, &error);
        if (proc != NULL) g_object_unref(proc);
    }

    target_panel_update(p->state, bssid,
                        (ssid && *ssid) ? ssid : "<hidden>",
                        chan, "WPA2");
    show_toast(p->state, "Target set");
    pop = gtk_widget_get_ancestor(GTK_WIDGET(b), GTK_TYPE_POPOVER);
    if (pop != NULL) gtk_popover_popdown(GTK_POPOVER(pop));
}

static void
live_filter_mac_clicked(GtkButton *b, gpointer user_data)
{
    LiveTrafficPage *p = user_data;
    const gchar *mac = g_object_get_data(G_OBJECT(b), "mac");
    GtkWidget *pop;
    if (mac == NULL || p->entry_mac == NULL) return;
    gtk_editable_set_text(GTK_EDITABLE(p->entry_mac), mac);
    live_apply_filters_clicked(NULL, p);
    pop = gtk_widget_get_ancestor(GTK_WIDGET(b), GTK_TYPE_POPOVER);
    if (pop != NULL) gtk_popover_popdown(GTK_POPOVER(pop));
}

static void
live_deauth_clicked(GtkButton *b, gpointer user_data)
{
    LiveTrafficPage *p = user_data;
    const gchar *mac = g_object_get_data(G_OBJECT(b), "mac");
    g_autoptr(GError) error = NULL;
    GSubprocess *proc = NULL;
    GtkWidget *pop;

    if (mac == NULL || *mac == '\0') return;

    {
        const gchar *argv[] = {
            "pkexec", ATTACK_SCRIPT, "--deauth-client", mac, "10", NULL
        };
        proc = g_subprocess_newv(argv, G_SUBPROCESS_FLAGS_NONE, &error);
        if (proc != NULL) g_object_unref(proc);
    }

    {
        g_autofree gchar *m = g_strdup_printf(
            "Live: deauth sent to %s", mac);
        append_event(p->state, m);
    }
    show_toast(p->state, "Deauth launched");
    pop = gtk_widget_get_ancestor(GTK_WIDGET(b), GTK_TYPE_POPOVER);
    if (pop != NULL) gtk_popover_popdown(GTK_POPOVER(pop));
}

static void
live_row_right_click(GtkGestureClick *g, int np,
                     double x, double y, gpointer user_data)
{
    GtkWidget *row = gtk_event_controller_get_widget(
        GTK_EVENT_CONTROLLER(g));
    LiveTrafficPage *p = g_object_get_data(G_OBJECT(row), "lt-manager");
    const gchar *sa = g_object_get_data(G_OBJECT(row), "lt-sa");
    const gchar *da = g_object_get_data(G_OBJECT(row), "lt-da");
    const gchar *bs = g_object_get_data(G_OBJECT(row), "lt-bssid");
    const gchar *ch = g_object_get_data(G_OBJECT(row), "lt-channel");
    GtkWidget *pop, *box, *b_sa, *b_da, *b_bs, *b_tg, *b_fm, *b_de;
    GdkRectangle rect;

    (void) np;
    (void) user_data;
    if (p == NULL) return;

    pop = gtk_popover_new();
    box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_set_margin_top(box, 6);
    gtk_widget_set_margin_bottom(box, 6);
    gtk_widget_set_margin_start(box, 6);
    gtk_widget_set_margin_end(box, 6);

    b_sa = gtk_button_new_with_label("Copy SA");
    b_da = gtk_button_new_with_label("Copy DA");
    b_bs = gtk_button_new_with_label("Copy BSSID");
    b_tg = gtk_button_new_with_label("Set as target (BSSID)");
    b_fm = gtk_button_new_with_label("Filter to SA");
    b_de = gtk_button_new_with_label("Deauth this client (SA)");

    g_object_set_data_full(G_OBJECT(b_sa), "copy-text",
                           g_strdup(sa ? sa : ""), g_free);
    g_object_set_data_full(G_OBJECT(b_da), "copy-text",
                           g_strdup(da ? da : ""), g_free);
    g_object_set_data_full(G_OBJECT(b_bs), "copy-text",
                           g_strdup(bs ? bs : ""), g_free);

    g_object_set_data_full(G_OBJECT(b_tg), "bssid",
                           g_strdup(bs ? bs : ""), g_free);
    g_object_set_data_full(G_OBJECT(b_tg), "ssid",
                           g_strdup(""), g_free);
    g_object_set_data_full(G_OBJECT(b_tg), "chan",
                           g_strdup(ch ? ch : ""), g_free);

    g_object_set_data_full(G_OBJECT(b_fm), "mac",
                           g_strdup(sa ? sa : ""), g_free);
    g_object_set_data_full(G_OBJECT(b_de), "mac",
                           g_strdup(sa ? sa : ""), g_free);

    g_signal_connect(b_sa, "clicked",
                     G_CALLBACK(live_copy_clicked), p->state);
    g_signal_connect(b_da, "clicked",
                     G_CALLBACK(live_copy_clicked), p->state);
    g_signal_connect(b_bs, "clicked",
                     G_CALLBACK(live_copy_clicked), p->state);
    g_signal_connect(b_tg, "clicked",
                     G_CALLBACK(live_set_target_clicked), p);
    g_signal_connect(b_fm, "clicked",
                     G_CALLBACK(live_filter_mac_clicked), p);
    g_signal_connect(b_de, "clicked",
                     G_CALLBACK(live_deauth_clicked), p);

    gtk_box_append(GTK_BOX(box), b_sa);
    gtk_box_append(GTK_BOX(box), b_da);
    gtk_box_append(GTK_BOX(box), b_bs);
    gtk_box_append(GTK_BOX(box), b_tg);
    gtk_box_append(GTK_BOX(box), b_fm);
    gtk_box_append(GTK_BOX(box), b_de);

    gtk_popover_set_child(GTK_POPOVER(pop), box);
    gtk_popover_set_has_arrow(GTK_POPOVER(pop), FALSE);

    rect.x = (int) x;
    rect.y = (int) y;
    rect.width = 1;
    rect.height = 1;
    gtk_popover_set_pointing_to(GTK_POPOVER(pop), &rect);
    gtk_popover_set_position(GTK_POPOVER(pop), GTK_POS_RIGHT);

    g_signal_connect(pop, "closed",
                     G_CALLBACK(live_popover_closed), NULL);

    gtk_widget_set_parent(pop, row);
    gtk_popover_popup(GTK_POPOVER(pop));
}

static void
live_traffic_page_free(gpointer data)
{
    LiveTrafficPage *p = data;

    p->destroyed = TRUE;

    p->iface_dd = NULL;
    p->iface_names = NULL;
    p->lbl_iface = NULL;
    p->lbl_channel = NULL;
    p->lbl_count = NULL;
    p->lbl_status = NULL;
    p->btn_start = NULL;
    p->btn_stop = NULL;
    p->btn_pause = NULL;
    p->btn_clear = NULL;
    p->entry_lock = NULL;
    p->btn_lock = NULL;
    p->chk_pcap = NULL;
    p->entry_pcap = NULL;
    p->list = NULL;
    p->scroll = NULL;

    if (p->flush_id != 0) {
        g_source_remove(p->flush_id);
        p->flush_id = 0;
    }
    if (p->poll_id != 0) {
        g_source_remove(p->poll_id);
        p->poll_id = 0;
    }

    if (p->cancel != NULL) {
        g_cancellable_cancel(p->cancel);
        g_object_unref(p->cancel);
        p->cancel = NULL;
    }
    if (p->stream_proc != NULL) {
        g_subprocess_force_exit(p->stream_proc);
        g_clear_object(&p->stream_proc);
    }
    if (p->pcap_proc != NULL) {
        g_subprocess_force_exit(p->pcap_proc);
        g_clear_object(&p->pcap_proc);
    }

    if (p->stream != NULL) {
        g_object_unref(p->stream);
        p->stream = NULL;
    }
    if (p->pending != NULL) {
        g_ptr_array_set_free_func(p->pending, live_frame_free);
        g_ptr_array_unref(p->pending);
        p->pending = NULL;
    }

    g_free(p->filter_mac);   p->filter_mac = NULL;
    g_free(p->filter_ssid);  p->filter_ssid = NULL;
    g_free(p->iface);        p->iface = NULL;
    g_free(p->iface_type);   p->iface_type = NULL;
    g_free(p->pcap_path);    p->pcap_path = NULL;

    /* Deliberately NOT freed — async read/poll callbacks queued in the
       main context still hold this pointer. Bounded leak (one struct
       per tab close), safe. */
}

static void
live_traffic_install_css(void)
{
    static gboolean installed = FALSE;
    static const char *css =
        "list.lt-list { background-color: #000000; }\n"
        "list.lt-list > row { background-color: #000000; }\n"
        "list.lt-list > row.lt-row-beacon { background-color: #09090b; }\n"
        "list.lt-list > row.lt-row-probe  { background-color: #0a1520; }\n"
        "list.lt-list > row.lt-row-auth   { background-color: #0d0d0d; }\n"
        "list.lt-list > row.lt-row-deauth { background-color: #300a0a; }\n"
        "list.lt-list > row.lt-row-eapol  { background-color: #2a1e00; }\n"
        "list.lt-list > row.lt-row-data   { background-color: #050505; }\n"
        "list.lt-list > row.lt-row-other  { background-color: #050505; }\n"
        "scrolledwindow.lt-scroll { background-color: #000000; }\n"
        "scrolledwindow.lt-scroll > viewport { background-color: #000000; }\n"
        ".lt-row-inner { padding: 2px 6px; }\n"
        ".lt-mono  { font-family: monospace; font-size: 11px; color: #b9bdc5; }\n"
        ".lt-kind  { font-family: monospace; font-size: 11px; font-weight: bold; }\n"
        ".lt-kind-beacon { color: #ffffff; }\n"
        ".lt-kind-probe  { color: #6fb3ff; }\n"
        ".lt-kind-auth   { color: #cccccc; }\n"
        ".lt-kind-deauth { color: #ff3232; }\n"
        ".lt-kind-data   { color: #62e690; }\n"
        ".lt-kind-eapol  { color: #ffbe32; }\n"
        ".lt-kind-other  { color: #7f838e; }\n"
        ".lt-ssid  { font-size: 11px; color: #ffd60a; font-weight: bold; }\n"
        ".lt-extra { font-family: monospace; font-size: 11px; color: #ffd66b; }\n"
        ".lt-status-warn { color: #ff526f; font-weight: bold; }\n"
        ".lt-header { font-size: 11px; color: #b9bdc5; }\n"
        ".lt-header-value { font-family: monospace; font-size: 11px; }"
        ;
    if (installed) return;
    installed = TRUE;

    {
        GtkCssProvider *prov = gtk_css_provider_new();
        gtk_css_provider_load_from_string(prov, css);
        gtk_style_context_add_provider_for_display(
            gdk_display_get_default(),
            GTK_STYLE_PROVIDER(prov),
            GTK_STYLE_PROVIDER_PRIORITY_APPLICATION + 1);
        g_object_unref(prov);
    }
}

static void
live_pcap_toggled(GtkToggleButton *b, gpointer user_data)
{
    LiveTrafficPage *p = user_data;
    gtk_widget_set_sensitive(p->entry_pcap,
        gtk_toggle_button_get_active(b));
}

static GtkWidget *
live_build_header(LiveTrafficPage *p)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    GtkWidget *col;

    gtk_widget_add_css_class(box, "lt-header-box");
    gtk_widget_set_margin_top(box, 8);
    gtk_widget_set_margin_bottom(box, 4);
    gtk_widget_set_margin_start(box, 12);
    gtk_widget_set_margin_end(box, 12);

    col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    {
        GtkWidget *cap = gtk_label_new("IFACE");
        GtkWidget *val = gtk_label_new("detecting...");
        gtk_widget_add_css_class(cap, "lt-header");
        gtk_widget_add_css_class(val, "lt-header-value");
        gtk_label_set_xalign(GTK_LABEL(cap), 0.0f);
        gtk_label_set_xalign(GTK_LABEL(val), 0.0f);
        p->lbl_iface = val;
        gtk_box_append(GTK_BOX(col), cap);
        gtk_box_append(GTK_BOX(col), val);
    }
    gtk_box_append(GTK_BOX(box), col);

    col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    {
        GtkWidget *cap = gtk_label_new("CHANNEL");
        GtkWidget *val = gtk_label_new("-");
        gtk_widget_add_css_class(cap, "lt-header");
        gtk_widget_add_css_class(val, "lt-header-value");
        gtk_label_set_xalign(GTK_LABEL(cap), 0.0f);
        gtk_label_set_xalign(GTK_LABEL(val), 0.0f);
        p->lbl_channel = val;
        gtk_box_append(GTK_BOX(col), cap);
        gtk_box_append(GTK_BOX(col), val);
    }
    gtk_box_append(GTK_BOX(box), col);

    col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    {
        GtkWidget *cap = gtk_label_new("FRAMES");
        GtkWidget *val = gtk_label_new("0 seen");
        gtk_widget_add_css_class(cap, "lt-header");
        gtk_widget_add_css_class(val, "lt-header-value");
        gtk_label_set_xalign(GTK_LABEL(cap), 0.0f);
        gtk_label_set_xalign(GTK_LABEL(val), 0.0f);
        p->lbl_count = val;
        gtk_box_append(GTK_BOX(col), cap);
        gtk_box_append(GTK_BOX(col), val);
    }
    gtk_box_append(GTK_BOX(box), col);

    {
        GtkWidget *sp = gtk_label_new("");
        gtk_widget_set_hexpand(sp, TRUE);
        gtk_box_append(GTK_BOX(box), sp);
    }

    {
        GtkWidget *s = gtk_label_new("idle");
        gtk_widget_add_css_class(s, "lt-header-value");
        gtk_label_set_xalign(GTK_LABEL(s), 1.0f);
        p->lbl_status = s;
        gtk_box_append(GTK_BOX(box), s);
    }

    return box;
}

static GtkWidget *
live_build_controls(LiveTrafficPage *p)
{
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    GtkWidget *row_a = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *row_b = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *lbl;

    gtk_widget_set_margin_start(outer, 12);
    gtk_widget_set_margin_end(outer, 12);
    gtk_widget_set_margin_bottom(outer, 4);

    /* Row A: iface + transport */
    {
        GtkWidget *iface_lbl = gtk_label_new("Iface:");
        GtkWidget *iface_rescan = gtk_button_new_with_label("Rescan");

        /* A list, not a text box: the interface name has to be exact, and
           with two adapters attached (one managed, one monitor) guessing it
           from memory is the easiest way to start a capture that silently
           sees nothing. The type is shown beside each name for the same
           reason. */
        p->iface_names = gtk_string_list_new(NULL);
        p->iface_dd = gtk_drop_down_new(G_LIST_MODEL(p->iface_names), NULL);
        gtk_widget_set_size_request(p->iface_dd, 220, -1);
        gtk_widget_set_valign(iface_rescan, GTK_ALIGN_CENTER);
        gtk_box_append(GTK_BOX(row_a), iface_lbl);
        gtk_box_append(GTK_BOX(row_a), p->iface_dd);
        gtk_box_append(GTK_BOX(row_a), iface_rescan);
        g_signal_connect(iface_rescan, "clicked",
                         G_CALLBACK(live_iface_rescan), p);
        live_iface_dropdown_reload(p);
    }

    p->btn_start = gtk_button_new_with_label("Start");
    p->btn_stop  = gtk_button_new_with_label("Stop");
    p->btn_pause = gtk_button_new_with_label("Pause");
    p->btn_clear = gtk_button_new_with_label("Clear");
    gtk_widget_add_css_class(p->btn_start, "accent");
    gtk_widget_set_sensitive(p->btn_stop, FALSE);

    gtk_box_append(GTK_BOX(row_a), p->btn_start);
    gtk_box_append(GTK_BOX(row_a), p->btn_stop);
    gtk_box_append(GTK_BOX(row_a), p->btn_pause);
    gtk_box_append(GTK_BOX(row_a), p->btn_clear);

    /* Row B: channel lock + pcap */
    p->entry_lock = gtk_entry_new();
    p->btn_lock   = gtk_button_new_with_label("Lock ch");
    gtk_widget_set_size_request(p->entry_lock, 50, -1);
    gtk_entry_set_placeholder_text(GTK_ENTRY(p->entry_lock), "6");
    gtk_box_append(GTK_BOX(row_b), p->entry_lock);
    gtk_box_append(GTK_BOX(row_b), p->btn_lock);

    lbl = gtk_label_new("Save pcap:");
    gtk_widget_set_margin_start(lbl, 12);
    p->chk_pcap = gtk_check_button_new();
    p->entry_pcap = gtk_entry_new();
    /* A real path, not a shell expression: placeholder text is shown
       verbatim, so "${WIFISTING_ROOT:-...}" appeared literal and looked
       broken. The stream sets WIFISTING_ROOT to PROJECT_DIR anyway. */
    gtk_entry_set_placeholder_text(GTK_ENTRY(p->entry_pcap),
        PROJECT_DIR "/captures/live.pcap");
    gtk_widget_set_size_request(p->entry_pcap, 320, -1);
    gtk_widget_set_sensitive(p->entry_pcap, FALSE);
    gtk_widget_set_hexpand(p->entry_pcap, TRUE);

    g_signal_connect(p->chk_pcap, "toggled",
                     G_CALLBACK(live_pcap_toggled), p);

    gtk_box_append(GTK_BOX(row_b), lbl);
    gtk_box_append(GTK_BOX(row_b), p->chk_pcap);
    gtk_box_append(GTK_BOX(row_b), p->entry_pcap);

    gtk_box_append(GTK_BOX(outer), row_a);
    gtk_box_append(GTK_BOX(outer), row_b);

    g_signal_connect(p->btn_start, "clicked",
                     G_CALLBACK(live_start_clicked), p);
    g_signal_connect(p->btn_stop, "clicked",
                     G_CALLBACK(live_stop_clicked), p);
    g_signal_connect(p->btn_pause, "clicked",
                     G_CALLBACK(live_pause_clicked), p);
    g_signal_connect(p->btn_clear, "clicked",
                     G_CALLBACK(live_clear_clicked), p);
    g_signal_connect(p->btn_lock, "clicked",
                     G_CALLBACK(live_lock_clicked), p);

    return outer;
}


static GtkWidget *
live_build_filters(LiveTrafficPage *p)
{
    static const struct {
        LiveKind k;
        const char *lbl;
    } kinds[] = {
        { LT_BEACON,          "Beacon" },
        { LT_PROBE_REQ,       "Probe Req" },
        { LT_PROBE_RESP,      "Probe Resp" },
        { LT_AUTH_ASSOC,      "Auth/Assoc" },
        { LT_DEAUTH_DISASSOC, "Deauth" },
        { LT_DATA,            "Data" },
        { LT_EAPOL,           "EAPOL" },
    };

    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    GtkWidget *row_a = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *row_b = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *lbl;

    gtk_widget_set_margin_start(outer, 12);
    gtk_widget_set_margin_end(outer, 12);
    gtk_widget_set_margin_bottom(outer, 6);

    for (guint i = 0; i < G_N_ELEMENTS(kinds); i++) {
        LiveKind k = kinds[i].k;
        p->tog[k] = gtk_toggle_button_new_with_label(kinds[i].lbl);
        gtk_toggle_button_set_active(
            GTK_TOGGLE_BUTTON(p->tog[k]), TRUE);
        p->kind_enabled[k] = TRUE;
        gtk_box_append(GTK_BOX(row_a), p->tog[k]);
    }

    lbl = gtk_label_new("MAC:");
    p->entry_mac = gtk_entry_new();
    gtk_widget_set_size_request(p->entry_mac, 140, -1);
    gtk_entry_set_placeholder_text(GTK_ENTRY(p->entry_mac),
        "aa:bb:cc or substring");
    gtk_box_append(GTK_BOX(row_b), lbl);
    gtk_box_append(GTK_BOX(row_b), p->entry_mac);

    lbl = gtk_label_new("SSID:");
    p->entry_ssid = gtk_entry_new();
    gtk_widget_set_size_request(p->entry_ssid, 120, -1);
    gtk_entry_set_placeholder_text(GTK_ENTRY(p->entry_ssid), "substring");
    gtk_box_append(GTK_BOX(row_b), lbl);
    gtk_box_append(GTK_BOX(row_b), p->entry_ssid);

    lbl = gtk_label_new("min dBm:");
    p->spin_dbm = gtk_spin_button_new_with_range(-100, 0, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(p->spin_dbm), 0);
    gtk_box_append(GTK_BOX(row_b), lbl);
    gtk_box_append(GTK_BOX(row_b), p->spin_dbm);

    p->btn_apply = gtk_button_new_with_label("Apply");
    p->btn_reset = gtk_button_new_with_label("Reset");
    gtk_box_append(GTK_BOX(row_b), p->btn_apply);
    gtk_box_append(GTK_BOX(row_b), p->btn_reset);

    g_signal_connect(p->btn_apply, "clicked",
                     G_CALLBACK(live_apply_filters_clicked), p);
    g_signal_connect(p->btn_reset, "clicked",
                     G_CALLBACK(live_reset_filters_clicked), p);

    gtk_box_append(GTK_BOX(outer), row_a);
    gtk_box_append(GTK_BOX(outer), row_b);

    return outer;
}


static GtkWidget *
live_build_column_header(void)
{
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *labels[10];
    const char *cap[] = {
        "#", "time", "type", "SA", "DA", "BSSID", "SSID",
        "ch", "dBm", "extra"
    };
    int widths[] = { 60, 70, 90, 130, 130, 130, 140, 30, 40, 80 };

    gtk_widget_set_margin_start(row, 12);
    gtk_widget_set_margin_end(row, 12);
    gtk_widget_set_margin_bottom(row, 2);

    for (int i = 0; i < 10; i++) {
        labels[i] = gtk_label_new(cap[i]);
        gtk_widget_set_size_request(labels[i], widths[i], -1);
        gtk_label_set_xalign(GTK_LABEL(labels[i]), 0.0f);
        gtk_widget_add_css_class(labels[i], "lt-header");
        gtk_box_append(GTK_BOX(row), labels[i]);
    }
    gtk_widget_set_hexpand(labels[6], TRUE);
    return row;
}

static GtkWidget *
create_live_traffic_page_inner(AppState *state)
{
    LiveTrafficPage *p = g_new0(LiveTrafficPage, 1);
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *header, *controls, *filters, *colhdr;
    GtkWidget *scroll, *list;

    p->state = state;
    p->pending = g_ptr_array_new_with_free_func(live_frame_free);
    p->kind_enabled[LT_BEACON]          = TRUE;
    p->kind_enabled[LT_PROBE_REQ]       = TRUE;
    p->kind_enabled[LT_PROBE_RESP]      = TRUE;
    p->kind_enabled[LT_AUTH_ASSOC]      = TRUE;
    p->kind_enabled[LT_DEAUTH_DISASSOC] = TRUE;
    p->kind_enabled[LT_DATA]            = TRUE;
    p->kind_enabled[LT_EAPOL]           = TRUE;
    p->kind_enabled[LT_OTHER]           = TRUE;

    live_traffic_install_css();

    header   = live_build_header(p);
    controls = live_build_controls(p);
    filters  = live_build_filters(p);
    colhdr   = live_build_column_header();

    scroll = gtk_scrolled_window_new();
    list   = gtk_list_box_new();
    gtk_widget_add_css_class(scroll, "lt-scroll");
    gtk_widget_add_css_class(list,   "lt-list");
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(list),
                                    GTK_SELECTION_NONE);
    gtk_list_box_set_show_separators(GTK_LIST_BOX(list), FALSE);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), list);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_widget_set_hexpand(scroll, TRUE);

    p->list   = list;
    p->scroll = scroll;

    {
        GtkGesture *g = gtk_gesture_click_new();
        gtk_gesture_single_set_button(
            GTK_GESTURE_SINGLE(g), GDK_BUTTON_SECONDARY);
        g_signal_connect(g, "pressed",
            G_CALLBACK(live_row_right_click), NULL);
        gtk_widget_add_controller(
            list, GTK_EVENT_CONTROLLER(g));
    }

    gtk_box_append(GTK_BOX(outer), header);
    gtk_box_append(GTK_BOX(outer), controls);
    gtk_box_append(GTK_BOX(outer), filters);
    gtk_box_append(GTK_BOX(outer), colhdr);
    gtk_box_append(GTK_BOX(outer), scroll);

    g_object_set_data_full(G_OBJECT(outer), "live-traffic",
                           p, live_traffic_page_free);
    g_object_set_data_full(G_OBJECT(outer), "module-id",
                           g_strdup("28_live_traffic"), g_free);

    p->flush_id = g_timeout_add(LIVE_FLUSH_MS, live_flush_cb, p);
    p->poll_id  = g_timeout_add_seconds(5, live_poll_cb, p);
    live_poll_cb(p);

    return outer;
}

/* ==================================================================== */
/*  Live Traffic tier-2 config bar                                      */
/*                                                                      */
/*  Wraps the original page in an outer vertical box and prepends a     */
/*  filter / PSK / rotation bar. The original constructor remains       */
/*  untouched below.                                                    */
/* ==================================================================== */

static void
lt_cfg_filter_apply(GtkButton *b, gpointer ud)
{
    GtkWidget *entry = ud;
    g_autoptr(GError) error = NULL;
    const char *argv[5];
    GSubprocess *proc;
    const char *filter;

    (void) b;

    if (entry == NULL) return;
    filter = gtk_editable_get_text(GTK_EDITABLE(entry));
    if (filter == NULL || *filter == '\0') return;

    argv[0] = "pkexec";
    argv[1] = PROJECT_DIR "/modules/28_live_traffic.sh";
    argv[2] = "--set-filter";
    argv[3] = filter;
    argv[4] = NULL;

    proc = g_subprocess_newv(argv,
        G_SUBPROCESS_FLAGS_STDOUT_SILENCE | G_SUBPROCESS_FLAGS_STDERR_SILENCE,
        &error);
    if (proc != NULL) g_object_unref(proc);
}

static void
lt_cfg_filter_clear(GtkButton *b, gpointer ud)
{
    GtkWidget *entry = ud;
    g_autoptr(GError) error = NULL;
    const char *argv[] = { PROJECT_DIR "/modules/28_live_traffic.sh",
                            "--clear-filter", NULL };
    GSubprocess *proc;

    (void) b;

    if (entry != NULL)
        gtk_editable_set_text(GTK_EDITABLE(entry), "");

    proc = g_subprocess_newv(argv,
        G_SUBPROCESS_FLAGS_STDOUT_SILENCE | G_SUBPROCESS_FLAGS_STDERR_SILENCE,
        &error);
    if (proc != NULL) g_object_unref(proc);
}

static void
lt_cfg_psk_confirm(GtkButton *b, gpointer ud)
{
    gpointer *arr = ud;
    GtkWidget *psk_entry = arr[0];
    GtkWidget *ssid_entry = arr[1];
    GtkWidget *dlg = arr[2];
    g_autoptr(GError) error = NULL;
    GSubprocess *proc;
    const char *psk;
    const char *ssid;
    const char *argv[6];

    (void) b;

    psk = gtk_editable_get_text(GTK_EDITABLE(psk_entry));
    ssid = gtk_editable_get_text(GTK_EDITABLE(ssid_entry));
    if (psk == NULL || *psk == '\0' || ssid == NULL || *ssid == '\0') return;

    argv[0] = "pkexec";
    argv[1] = PROJECT_DIR "/modules/28_live_traffic.sh";
    argv[2] = "--set-psk";
    argv[3] = psk;
    argv[4] = ssid;
    argv[5] = NULL;

    proc = g_subprocess_newv(argv,
        G_SUBPROCESS_FLAGS_STDOUT_SILENCE | G_SUBPROCESS_FLAGS_STDERR_SILENCE,
        &error);
    if (proc != NULL) g_object_unref(proc);

    gtk_window_destroy(GTK_WINDOW(dlg));
    g_free(arr);
}

static void
lt_cfg_psk_open(GtkButton *b, gpointer ud)
{
    GtkWidget *parent = ud;
    GtkWidget *dlg, *box, *r1, *r2, *btnrow, *ok, *cancel;
    GtkWidget *psk_entry, *ssid_entry;
    gpointer *arr;

    (void) b;

    dlg = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(dlg), "Set WPA2 PSK");
    gtk_window_set_modal(GTK_WINDOW(dlg), TRUE);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 400, -1);
    if (parent != NULL) {
        GtkRoot *root = gtk_widget_get_root(parent);
        if (root != NULL && GTK_IS_WINDOW(root))
            gtk_window_set_transient_for(GTK_WINDOW(dlg),
                                         GTK_WINDOW(root));
    }

    box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_top(box, 14);
    gtk_widget_set_margin_bottom(box, 14);
    gtk_widget_set_margin_start(box, 14);
    gtk_widget_set_margin_end(box, 14);

    r1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    r2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    psk_entry = gtk_entry_new();
    ssid_entry = gtk_entry_new();
    GtkWidget *l1 = gtk_label_new("PSK:");
    GtkWidget *l2 = gtk_label_new("SSID:");
    gtk_entry_set_visibility(GTK_ENTRY(psk_entry), FALSE);
    gtk_widget_set_hexpand(psk_entry, TRUE);
    gtk_widget_set_hexpand(ssid_entry, TRUE);
    gtk_widget_set_valign(l1, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(l2, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(r1), l1);
    gtk_box_append(GTK_BOX(r1), psk_entry);
    gtk_box_append(GTK_BOX(r2), l2);
    gtk_box_append(GTK_BOX(r2), ssid_entry);

    btnrow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    ok = gtk_button_new_with_label("Save");
    cancel = gtk_button_new_with_label("Cancel");
    gtk_widget_add_css_class(ok, "accent");
    gtk_widget_set_halign(btnrow, GTK_ALIGN_END);
    gtk_widget_set_hexpand(btnrow, TRUE);
    gtk_box_append(GTK_BOX(btnrow), cancel);
    gtk_box_append(GTK_BOX(btnrow), ok);

    gtk_box_append(GTK_BOX(box), r1);
    gtk_box_append(GTK_BOX(box), r2);
    gtk_box_append(GTK_BOX(box), btnrow);
    gtk_window_set_child(GTK_WINDOW(dlg), box);

    arr = g_new0(gpointer, 3);
    arr[0] = psk_entry;
    arr[1] = ssid_entry;
    arr[2] = dlg;

    g_signal_connect(ok, "clicked", G_CALLBACK(lt_cfg_psk_confirm), arr);
    g_signal_connect_swapped(cancel, "clicked",
        G_CALLBACK(gtk_window_destroy), dlg);

    gtk_window_present(GTK_WINDOW(dlg));
}

static void
lt_cfg_psk_clear(GtkButton *b, gpointer ud)
{
    g_autoptr(GError) error = NULL;
    const char *argv[] = { PROJECT_DIR "/modules/28_live_traffic.sh",
                            "--clear-psk", NULL };
    GSubprocess *proc;
    (void) b; (void) ud;

    proc = g_subprocess_newv(argv,
        G_SUBPROCESS_FLAGS_STDOUT_SILENCE | G_SUBPROCESS_FLAGS_STDERR_SILENCE,
        &error);
    if (proc != NULL) g_object_unref(proc);
}

static void
lt_cfg_rotate(GtkButton *b, gpointer ud)
{
    gpointer *arr = ud;
    GtkWidget *spin = arr[0];
    GtkWidget *status = arr[1];
    GtkWidget *btn = arr[2];
    g_autoptr(GError) error = NULL;
    GSubprocess *proc;
    gboolean rotating;

    (void) b;

    rotating = g_object_get_data(G_OBJECT(btn), "rotating") != NULL;

    if (rotating) {
        const char *argv[] = {
            PROJECT_DIR "/modules/28_live_traffic.sh", "--rotate-stop", NULL
        };
        g_object_set_data(G_OBJECT(btn), "rotating", NULL);
        gtk_button_set_label(GTK_BUTTON(btn), "Start rotation");
        if (status) gtk_label_set_text(GTK_LABEL(status), "stopped");
        proc = g_subprocess_newv(argv,
            G_SUBPROCESS_FLAGS_STDOUT_SILENCE |
            G_SUBPROCESS_FLAGS_STDERR_SILENCE, &error);
    } else {
        g_autofree char *interval = g_strdup_printf("%d",
            gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(spin)));
        const char *argv[] = {
            "pkexec",
            PROJECT_DIR "/modules/28_live_traffic.sh", "--rotate-start",
            "wlan0", /* TODO: pick from the iface list */
            interval,
            NULL
        };
        g_object_set_data(G_OBJECT(btn), "rotating", GINT_TO_POINTER(1));
        gtk_button_set_label(GTK_BUTTON(btn), "Stop rotation");
        if (status) gtk_label_set_text(GTK_LABEL(status), "rotating");
        proc = g_subprocess_newv(argv,
            G_SUBPROCESS_FLAGS_STDOUT_SILENCE |
            G_SUBPROCESS_FLAGS_STDERR_SILENCE, &error);
    }

    if (proc != NULL) g_object_unref(proc);
}

static gpointer lt_cfg_rotate_arr[3];


/* Common capture filters as a list. The entry stays for anything not
   covered ("Custom…" just focuses it), but the handful of filters people
   actually reach for should not have to be recalled exactly: tshark rejects
   a malformed filter silently, so a typo looks like an empty network. */
static const struct { const char *label; const char *filter; } lt_filter_presets[] = {
    { "Custom…",              NULL },
    { "All traffic",          "" },
    { "Handshakes (EAPOL)",   "eapol" },
    { "Deauth / disassoc",    "wlan.fc.type_subtype == 12 || wlan.fc.type_subtype == 10" },
    { "Beacons and probes",   "wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 4" },
    { "Data frames only",     "wlan.fc.type == 2" },
    { "ARP",                  "arp" },
    { "DHCP",                 "bootp" },
    { "DNS",                  "dns" },
    { "mDNS",                 "udp.port == 5353" },
    { "HTTP",                 "http" },
    { "TLS",                  "tls" },
};

static void
lt_cfg_preset_changed(GtkDropDown *dd, GParamSpec *pspec, gpointer ud)
{
    GtkWidget *entry = ud;
    guint idx = gtk_drop_down_get_selected(dd);
    const char *filter;

    (void) pspec;

    if (entry == NULL || idx == GTK_INVALID_LIST_POSITION) return;
    if (idx >= G_N_ELEMENTS(lt_filter_presets)) return;

    filter = lt_filter_presets[idx].filter;
    if (filter == NULL) {
        /* Custom: leave whatever is typed alone and put the cursor there. */
        gtk_widget_grab_focus(entry);
        return;
    }
    gtk_editable_set_text(GTK_EDITABLE(entry), filter);
    lt_cfg_filter_apply(NULL, entry);
}

GtkWidget *
create_live_traffic_page(AppState *state)
{
    GtkWidget *inner = create_live_traffic_page_inner(state);
    GtkWidget *wrap = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *lbl = gtk_label_new("Filter:");
    GtkWidget *preset = NULL;
    GtkWidget *entry = gtk_entry_new();
    GtkWidget *apply = gtk_button_new_with_label("Apply");
    GtkWidget *clear = gtk_button_new_with_label("Clear");
    GtkWidget *psk_btn = gtk_button_new_with_label("Set PSK…");
    GtkWidget *psk_clr = gtk_button_new_with_label("Clear PSK");
    GtkWidget *rot_btn = gtk_button_new_with_label("Start rotation");
    GtkWidget *rot_spin = gtk_spin_button_new_with_range(60, 3600, 30);
    GtkWidget *status = gtk_label_new("idle");

    gtk_widget_add_css_class(bar, "lt-config-bar");
    gtk_widget_add_css_class(status, "dependency-summary");
    gtk_widget_set_margin_top(bar, 6);
    gtk_widget_set_margin_bottom(bar, 6);
    gtk_widget_set_margin_start(bar, 6);
    gtk_widget_set_margin_end(bar, 6);

    gtk_entry_set_placeholder_text(GTK_ENTRY(entry),
        "tshark filter (e.g. wlan.bssid == aa:bb:cc:dd:ee:ff)");
    gtk_widget_set_hexpand(entry, TRUE);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(rot_spin), 300);

    gtk_widget_set_valign(lbl, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(apply, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(clear, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(psk_btn, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(psk_clr, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(rot_btn, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(rot_spin, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(status, GTK_ALIGN_CENTER);
    gtk_widget_add_css_class(rot_btn, "accent");

    {
        const char *labels[G_N_ELEMENTS(lt_filter_presets) + 1];
        for (guint i = 0; i < G_N_ELEMENTS(lt_filter_presets); i++)
            labels[i] = lt_filter_presets[i].label;
        labels[G_N_ELEMENTS(lt_filter_presets)] = NULL;
        preset = gtk_drop_down_new_from_strings(labels);
        gtk_widget_set_valign(preset, GTK_ALIGN_CENTER);
        gtk_widget_set_tooltip_text(preset,
            "Pick a common capture filter, or Custom… to type one");
    }

    gtk_box_append(GTK_BOX(bar), lbl);
    gtk_box_append(GTK_BOX(bar), preset);
    gtk_box_append(GTK_BOX(bar), entry);
    gtk_box_append(GTK_BOX(bar), apply);
    gtk_box_append(GTK_BOX(bar), clear);
    gtk_box_append(GTK_BOX(bar), psk_btn);
    gtk_box_append(GTK_BOX(bar), psk_clr);
    gtk_box_append(GTK_BOX(bar), rot_btn);
    gtk_box_append(GTK_BOX(bar), rot_spin);
    gtk_box_append(GTK_BOX(bar), status);

    gtk_box_append(GTK_BOX(wrap), bar);
    gtk_box_append(GTK_BOX(wrap), inner);

    g_signal_connect(apply, "clicked",
                     G_CALLBACK(lt_cfg_filter_apply), entry);
    g_signal_connect(clear, "clicked",
                     G_CALLBACK(lt_cfg_filter_clear), entry);
    g_signal_connect(preset, "notify::selected",
                     G_CALLBACK(lt_cfg_preset_changed), entry);
    g_signal_connect(psk_btn, "clicked",
                     G_CALLBACK(lt_cfg_psk_open), wrap);
    g_signal_connect(psk_clr, "clicked",
                     G_CALLBACK(lt_cfg_psk_clear), NULL);

    lt_cfg_rotate_arr[0] = rot_spin;
    lt_cfg_rotate_arr[1] = status;
    lt_cfg_rotate_arr[2] = rot_btn;
    g_signal_connect(rot_btn, "clicked",
                     G_CALLBACK(lt_cfg_rotate), lt_cfg_rotate_arr);

    (void) state;
    return wrap;
}
