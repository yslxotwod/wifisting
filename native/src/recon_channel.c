
/* ==================================================================== */
/*  WI-FI RECON — CHANNEL OCCUPANCY                                     */
/*                                                                      */
/*  Which channels are crowded, and which one to use. The answer matters */
/*  immediately before standing up a rogue AP: pick a channel that the   */
/*  target's neighbours are not already saturating.                      */
/*                                                                      */
/*  Everything here is cairo on a small surface that repaints on load,   */
/*  never on a timer - unlike the ambient backdrops, which is what took  */
/*  the app to 80% of a core before they were reined in.                 */
/* ==================================================================== */

#define RECON_CHANNELS 13

/* Defined below; the series are owned by the page so a refresh only
   rewrites values and queues a redraw. */
typedef struct { double v[64]; int n; double r, g, b; } SparkSeries;

typedef struct {
    AppState    *state;
    GtkWidget   *map;          /* occupancy chart */
    SparkSeries *sum_s, *busy_s, *pick_s;
    GtkWidget   *sum_area, *busy_area, *pick_area;
    GtkWidget   *l_total, *l_busy, *l_pick, *l_status;
    int          count[RECON_CHANNELS + 1];   /* APs per channel */
    double       power[48];                   /* signal, for the sparkline */
    int          n_power;
    int          total;
    int          busiest;
    int          suggested;
    GSubprocess *proc;
} ChannelPage;

/* ---- the sparkline from the reference card ---------------------------
   A line, a soft fill down to the baseline, and an end-cap dot. Small and
   static, so it costs nothing to draw. */
static void
sparkline_draw(cairo_t *cr, int w, int h,
               const double *v, int n,
               double r, double g, double b)
{
    double lo, hi, span, x, y, step;
    int i;

    if (n < 2 || w < 8 || h < 8) return;

    lo = hi = v[0];
    for (i = 1; i < n; i++) {
        if (v[i] < lo) lo = v[i];
        if (v[i] > hi) hi = v[i];
    }
    span = (hi > lo) ? (hi - lo) : 1.0;

    step = (double) (w - 4) / (double) (n - 1);

    cairo_new_path(cr);
    for (i = 0; i < n; i++) {
        x = 2.0 + step * i;
        y = (double) h - 3.0 - ((v[i] - lo) / span) * (double) (h - 8);
        if (i == 0) cairo_move_to(cr, x, y);
        else        cairo_line_to(cr, x, y);
    }

    /* Keep the stroke path, then extend a copy down for the fill. */
    cairo_path_t *path = cairo_copy_path(cr);
    cairo_line_to(cr, 2.0 + step * (n - 1), h);
    cairo_line_to(cr, 2.0, h);
    cairo_close_path(cr);
    {
        cairo_pattern_t *gr = cairo_pattern_create_linear(0, 0, 0, h);
        cairo_pattern_add_color_stop_rgba(gr, 0.0, r, g, b, 0.38);
        cairo_pattern_add_color_stop_rgba(gr, 1.0, r, g, b, 0.02);
        cairo_set_source(cr, gr);
        cairo_fill(cr);
        cairo_pattern_destroy(gr);
    }

    cairo_new_path(cr);
    cairo_append_path(cr, path);
    cairo_path_destroy(path);
    cairo_set_source_rgba(cr, r, g, b, 1.0);
    cairo_set_line_width(cr, 1.8);
    cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);
    cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
    cairo_stroke(cr);

    /* end-cap dot */
    x = 2.0 + step * (n - 1);
    y = (double) h - 3.0 - ((v[n - 1] - lo) / span) * (double) (h - 8);
    cairo_arc(cr, x, y, 2.6, 0, 2 * G_PI);
    cairo_set_source_rgba(cr, 0.06, 0.09, 0.12, 1.0);
    cairo_fill(cr);
    cairo_arc(cr, x, y, 1.8, 0, 2 * G_PI);
    cairo_set_source_rgba(cr, r, g, b, 1.0);
    cairo_fill(cr);
}

/* Draw callback shared by the three cards; each carries its own series. */
static void
spark_draw(GtkDrawingArea *area, cairo_t *cr, int w, int h, gpointer ud)
{
    SparkSeries *s = ud;
    (void) area;
    cairo_set_source_rgba(cr, 0, 0, 0, 0);
    cairo_paint(cr);
    sparkline_draw(cr, w, h, s->v, s->n, s->r, s->g, s->b);
}

static void
spark_free(gpointer d) { g_free(d); }

static GtkWidget *
spark_new(SparkSeries *s)
{
    GtkWidget *a = gtk_drawing_area_new();
    gtk_widget_set_size_request(a, 120, 44);
    gtk_drawing_area_set_draw_func(GTK_DRAWING_AREA(a), spark_draw, s, spark_free);
    return a;
}

/* ---- the occupancy chart --------------------------------------------- */
static void
map_draw(GtkDrawingArea *area, cairo_t *cr, int w, int h, gpointer ud)
{
    ChannelPage *p = ud;
    int ch, maxc = 1;
    double pad_l = 34.0, pad_b = 22.0, pad_t = 10.0, pad_r = 8.0;
    double plot_w, plot_h, bw, gap;

    (void) area;

    cairo_set_source_rgba(cr, 0, 0, 0, 0);
    cairo_paint(cr);

    for (ch = 1; ch <= RECON_CHANNELS; ch++)
        if (p->count[ch] > maxc) maxc = p->count[ch];

    plot_w = (double) w - pad_l - pad_r;
    plot_h = (double) h - pad_t - pad_b;
    if (plot_w < 40 || plot_h < 20) return;

    gap = plot_w / (double) RECON_CHANNELS;
    bw = gap * 0.62;

    /* gridlines + y labels */
    cairo_set_line_width(cr, 1.0);
    cairo_set_font_size(cr, 10.0);
    for (int k = 0; k <= maxc; k++) {
        double y = pad_t + plot_h - (plot_h * (double) k / (double) maxc);
        cairo_set_source_rgba(cr, 0.55, 0.62, 0.70, 0.18);
        cairo_move_to(cr, pad_l, y + 0.5);
        cairo_line_to(cr, pad_l + plot_w, y + 0.5);
        cairo_stroke(cr);
        cairo_set_source_rgba(cr, 0.62, 0.68, 0.75, 0.85);
        {
            char lbl[8];
            g_snprintf(lbl, sizeof lbl, "%d", k);
            cairo_move_to(cr, pad_l - 8 - 6 * (k > 9 ? 1 : 0), y + 3.5);
            cairo_show_text(cr, lbl);
        }
    }

    for (ch = 1; ch <= RECON_CHANNELS; ch++) {
        double x = pad_l + gap * (ch - 1) + (gap - bw) / 2.0;
        double bh = plot_h * (double) p->count[ch] / (double) maxc;
        double y = pad_t + plot_h - bh;
        gboolean pick = (ch == p->suggested);
        gboolean busy = (ch == p->busiest && p->count[ch] > 0);

        /* Non-overlapping channels get a faint backing so 1/6/11 read as a
           set without needing a legend. */
        if (ch == 1 || ch == 6 || ch == 11) {
            cairo_set_source_rgba(cr, 0.35, 0.55, 0.85, 0.10);
            cairo_rectangle(cr, pad_l + gap * (ch - 1), pad_t, gap, plot_h);
            cairo_fill(cr);
        }

        if (p->count[ch] > 0) {
            if (pick)       cairo_set_source_rgba(cr, 0.20, 0.85, 0.45, 0.95);
            else if (busy)  cairo_set_source_rgba(cr, 0.95, 0.45, 0.30, 0.90);
            else            cairo_set_source_rgba(cr, 0.30, 0.62, 0.95, 0.75);
            cairo_rectangle(cr, x, y, bw, bh);
            cairo_fill(cr);

            {
                char n[8];
                g_snprintf(n, sizeof n, "%d", p->count[ch]);
                cairo_set_source_rgba(cr, 0.92, 0.95, 0.98, 0.95);
                cairo_set_font_size(cr, 10.0);
                cairo_move_to(cr, x + bw / 2.0 - 3.0, y - 3.0);
                cairo_show_text(cr, n);
            }
        }

        /* channel label */
        {
            char cl[8];
            g_snprintf(cl, sizeof cl, "%d", ch);
            cairo_set_source_rgba(cr, 0.66, 0.72, 0.79, 0.95);
            cairo_set_font_size(cr, 10.0);
            cairo_move_to(cr, pad_l + gap * (ch - 1) + gap / 2.0 - 4.0,
                          (double) h - 7.0);
            cairo_show_text(cr, cl);
        }
    }

    /* axis titles */
    cairo_set_source_rgba(cr, 0.60, 0.67, 0.74, 0.9);
    cairo_set_font_size(cr, 10.0);
    cairo_move_to(cr, pad_l, (double) h - 7.0);
    cairo_show_text(cr, "ch");
    cairo_save(cr);
    cairo_translate(cr, 12.0, pad_t + plot_h / 2.0 + 18.0);
    cairo_rotate(cr, -G_PI / 2.0);
    cairo_show_text(cr, "APs");
    cairo_restore(cr);
}

static void
channel_refresh_ui(ChannelPage *p)
{
    double occ[RECON_CHANNELS];
    int i;

    for (i = 0; i < RECON_CHANNELS; i++) occ[i] = (double) p->count[i + 1];

    if (p->sum_s != NULL) {
        for (i = 0; i < RECON_CHANNELS; i++) p->sum_s->v[i] = occ[i];
        p->sum_s->n = RECON_CHANNELS;
    }
    if (p->busy_s != NULL) {
        for (i = 0; i < RECON_CHANNELS; i++) p->busy_s->v[i] = occ[i];
        p->busy_s->n = RECON_CHANNELS;
    }
    if (p->pick_s != NULL) {
        p->pick_s->v[0] = (double) p->count[1];
        p->pick_s->v[1] = (double) p->count[6];
        p->pick_s->v[2] = (double) p->count[11];
        p->pick_s->n = 3;
    }

    if (p->l_total != NULL) {
        g_autofree char *m = g_strdup_printf("%d", p->total);
        gtk_label_set_text(GTK_LABEL(p->l_total), m);
    }
    if (p->l_busy != NULL) {
        g_autofree char *m = g_strdup_printf("ch %d  (%d)",
            p->busiest, p->busiest ? p->count[p->busiest] : 0);
        gtk_label_set_text(GTK_LABEL(p->l_busy), m);
    }
    if (p->l_pick != NULL) {
        g_autofree char *m = g_strdup_printf("ch %d  (%d)",
            p->suggested, p->count[p->suggested]);
        gtk_label_set_text(GTK_LABEL(p->l_pick), m);
    }
    if (p->map != NULL) gtk_widget_queue_draw(p->map);
    if (p->sum_area  != NULL) gtk_widget_queue_draw(p->sum_area);
    if (p->busy_area != NULL) gtk_widget_queue_draw(p->busy_area);
    if (p->pick_area != NULL) gtk_widget_queue_draw(p->pick_area);
}

static void
channel_loaded(GObject *source, GAsyncResult *result, gpointer user_data)
{
    ChannelPage *p = user_data;
    g_autoptr(GError) error = NULL;
    g_autofree char *out = NULL;
    g_autofree char *err = NULL;
    gboolean ok = g_subprocess_communicate_utf8_finish(
        G_SUBPROCESS(source), result, &out, &err, &error);

    g_clear_object(&p->proc);
    memset(p->count, 0, sizeof p->count);
    p->total = 0; p->busiest = 0;

    if (!ok || out == NULL || *out == '\0') {
        if (p->l_status != NULL)
            gtk_label_set_text(GTK_LABEL(p->l_status),
                (err != NULL && *err != '\0') ? err
                    : "no scan yet — run Scan first");
        channel_refresh_ui(p);
        return;
    }

    {
        g_auto(GStrv) lines = g_strsplit(out, "\n", -1);
        for (guint i = 0; lines[i] != NULL; i++) {
            g_auto(GStrv) f = g_strsplit(lines[i], "\t", 6);
            int ch;
            if (g_strv_length(f) < 4) continue;
            if (g_strcmp0(f[0], "BSSID") == 0) continue;
            ch = atoi(f[2]);
            if (ch < 1 || ch > RECON_CHANNELS) continue;
            p->count[ch]++;
            p->total++;
        }
    }

    for (int ch = 1; ch <= RECON_CHANNELS; ch++)
        if (p->count[ch] > p->count[p->busiest]) p->busiest = ch;

    /* Of the three non-overlapping channels, the emptiest. Ties go to the
       lower channel, which is the conventional choice. */
    p->suggested = 1;
    if (p->count[6]  < p->count[p->suggested]) p->suggested = 6;
    if (p->count[11] < p->count[p->suggested]) p->suggested = 11;

    if (p->l_status != NULL) {
        g_autofree char *m = g_strdup_printf(
            "%d network(s) across %d channel(s) — suggested ch %d",
            p->total, RECON_CHANNELS, p->suggested);
        gtk_label_set_text(GTK_LABEL(p->l_status), m);
    }
    channel_refresh_ui(p);
}

static void
channel_reload(ChannelPage *p)
{
    g_autoptr(GError) error = NULL;
    const char *argv[] = { RECON_SCRIPT, "--targets-json-tsv", NULL };

    if (p->proc != NULL) return;
    p->proc = g_subprocess_newv(argv,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE,
        &error);
    if (p->proc == NULL) {
        if (p->l_status != NULL)
            gtk_label_set_text(GTK_LABEL(p->l_status),
                error ? error->message : "could not read targets");
        return;
    }
    g_subprocess_communicate_utf8_async(p->proc, NULL, NULL,
        channel_loaded, p);
}

/* One summary card: label, big value, sparkline. */
static GtkWidget *
channel_card(const char *label, GtkWidget **value_out, GtkWidget *spark)
{
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *accent = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *l_lbl = gtk_label_new(label);
    GtkWidget *l_val = gtk_label_new("—");

    gtk_widget_add_css_class(card, "section-card");
    gtk_widget_add_css_class(l_lbl, "dependency-summary");
    gtk_widget_add_css_class(l_val, "stat-value");
    gtk_label_set_xalign(GTK_LABEL(l_lbl), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(l_val), 0.0f);
    gtk_widget_set_size_request(accent, 4, -1);
    gtk_widget_add_css_class(accent, "stat-accent");
    gtk_widget_set_hexpand(col, TRUE);

    gtk_box_append(GTK_BOX(col), l_lbl);
    gtk_box_append(GTK_BOX(col), l_val);
    gtk_box_append(GTK_BOX(card), accent);
    gtk_box_append(GTK_BOX(card), col);
    if (spark != NULL) {
        gtk_widget_set_valign(spark, GTK_ALIGN_CENTER);
        gtk_box_append(GTK_BOX(card), spark);
    }
    *value_out = l_val;
    return card;
}

static GtkWidget *
recon_build_channel(AppState *state, gpointer module_data)
{
    ChannelPage *p = g_new0(ChannelPage, 1);
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *title = gtk_label_new("Channel Occupancy");
    GtkWidget *sub = gtk_label_new(
        "How crowded each 2.4 GHz channel is. The suggested channel is the "
        "emptiest of 1, 6 and 11 — the three that do not overlap each other — "
        "which is what you want before standing up an access point.");
    GtkWidget *cards = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *ccard = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *ctitle = gtk_label_new("OCCUPANCY");
    GtkWidget *map = gtk_drawing_area_new();
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *reload = gtk_button_new_with_label("Reload");
    GtkWidget *status = gtk_label_new("reading targets…");

    (void) module_data;

    gtk_widget_add_css_class(page, "dependency-page");
    gtk_widget_add_css_class(title, "page-title");
    gtk_widget_add_css_class(sub, "page-subtitle");
    gtk_widget_add_css_class(ccard, "section-card");
    gtk_widget_add_css_class(ctitle, "section-title");
    gtk_widget_add_css_class(status, "dependency-summary");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(sub), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(ctitle), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(status), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(sub), TRUE);
    gtk_widget_set_halign(row, GTK_ALIGN_START);
    gtk_widget_set_size_request(map, -1, 240);
    gtk_widget_set_vexpand(map, TRUE);

    p->state = state;
    p->map = map;
    gtk_drawing_area_set_draw_func(GTK_DRAWING_AREA(map), map_draw, p, NULL);

    /* Series are allocated once and updated in place; the draw funcs hold
       these pointers, so rebuilding the widgets on every refresh leaked and
       left the sparklines unparented. */
    p->sum_s  = g_new0(SparkSeries, 1);
    p->sum_s->r = 0.30; p->sum_s->g = 0.62; p->sum_s->b = 0.95;
    p->busy_s = g_new0(SparkSeries, 1);
    p->busy_s->r = 0.95; p->busy_s->g = 0.45; p->busy_s->b = 0.30;
    p->pick_s = g_new0(SparkSeries, 1);
    p->pick_s->r = 0.20; p->pick_s->g = 0.85; p->pick_s->b = 0.45;
    p->sum_area  = spark_new(p->sum_s);
    p->busy_area = spark_new(p->busy_s);
    p->pick_area = spark_new(p->pick_s);

    gtk_box_append(GTK_BOX(cards),
        channel_card("NETWORKS", &p->l_total, p->sum_area));
    gtk_box_append(GTK_BOX(cards),
        channel_card("BUSIEST", &p->l_busy, p->busy_area));
    gtk_box_append(GTK_BOX(cards),
        channel_card("SUGGESTED", &p->l_pick, p->pick_area));

    gtk_box_append(GTK_BOX(row), reload);
    gtk_box_append(GTK_BOX(ccard), ctitle);
    gtk_box_append(GTK_BOX(ccard), cards);
    gtk_box_append(GTK_BOX(ccard), row);
    gtk_box_append(GTK_BOX(ccard), status);

    gtk_box_append(GTK_BOX(page), title);
    gtk_box_append(GTK_BOX(page), sub);
    gtk_box_append(GTK_BOX(ccard), map);
    gtk_box_append(GTK_BOX(page), ccard);

    p->l_status = status;
    g_signal_connect_swapped(reload, "clicked",
                             G_CALLBACK(channel_reload), p);
    channel_reload(p);
    return page;
}

