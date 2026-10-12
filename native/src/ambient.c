/* ==================================================================== */
/*  AMBIENT ANIMATIONS                                                  */
/*  Three cairo-driven effects, all included by main1.c:                */
/*    - drifting graph-paper grid behind content                        */
/*    - sweeping scan line at the top of the event drawer               */
/*    - pulse strip at the bottom of the target panel (MITM active)     */
/* ==================================================================== */

/* ---------- 11. drifting graph paper ---------- */
/*
 * Painted into another layer rather than given its own GtkDrawingArea.
 *
 * Each overlay child is a separate surface that GTK composites over the whole
 * window every frame, and this effect on its own cost a full-surface clear
 * plus two stroked line sets per tick. Merging it into the VHS backdrop took
 * the app from ~80% of a core at idle to a fraction of that: one surface
 * instead of two, one clear instead of two, one composite instead of two.
 *
 * The clear is deliberately NOT here - the caller owns the surface and clears
 * once, so this only draws.
 */
static void
ambient_grid_paint(cairo_t *cr, int width, int height, double offset)
{
    const double cell = 32.0;
    double ox = offset;
    double x, y;

    while (ox < 0)       ox += cell;
    while (ox >= cell)   ox -= cell;

    cairo_set_line_width(cr, 1.0);

    cairo_set_source_rgba(cr, 1.0, 0.23, 0.23, 0.045);
    for (x = -cell + ox; x < width + cell; x += cell) {
        cairo_move_to(cr, (int) x + 0.5, 0);
        cairo_line_to(cr, (int) x + 0.5, height);
    }
    cairo_stroke(cr);

    cairo_set_source_rgba(cr, 1.0, 0.23, 0.23, 0.028);
    for (y = 0; y < height + cell; y += cell) {
        cairo_move_to(cr, 0, (int) y + 0.5);
        cairo_line_to(cr, width, (int) y + 0.5);
    }
    cairo_stroke(cr);
}

/* ---------- 6. sweeping scan line for the event drawer ---------- */

typedef struct {
    GtkWidget *area;
    guint      timer;
    double     pos;
} AmbientScan;

static void
ambient_scan_draw(GtkDrawingArea *area, cairo_t *cr,
                  int width, int height, gpointer user_data)
{
    AmbientScan *s = user_data;
    double x = s->pos * (double) width;
    double band = 60.0;
    cairo_pattern_t *pat;

    (void) area;

    cairo_set_source_rgba(cr, 0, 0, 0, 0);
    cairo_paint(cr);

    pat = cairo_pattern_create_linear(x - band, 0, x + band, 0);
    cairo_pattern_add_color_stop_rgba(pat, 0.0, 1.0, 0.23, 0.23, 0.0);
    cairo_pattern_add_color_stop_rgba(pat, 0.5, 1.0, 0.23, 0.23, 0.55);
    cairo_pattern_add_color_stop_rgba(pat, 1.0, 1.0, 0.23, 0.23, 0.0);
    cairo_set_source(cr, pat);
    cairo_rectangle(cr, 0, 0, width, height);
    cairo_fill(cr);
    cairo_pattern_destroy(pat);
}

static gboolean
ambient_scan_tick(gpointer user_data)
{
    AmbientScan *s = user_data;
    if (s->area == NULL) return G_SOURCE_REMOVE;
    /* Nothing to do while the drawer is closed or the window is minimised:
       an unmapped widget is not on screen, so repainting it is pure waste. */
    if (!gtk_widget_get_mapped(s->area)) return G_SOURCE_CONTINUE;
    s->pos += 0.007;
    if (s->pos > 1.0) s->pos = 0.0;
    gtk_widget_queue_draw(s->area);
    return G_SOURCE_CONTINUE;
}

static void
ambient_scan_free(gpointer data)
{
    AmbientScan *s = data;
    if (s->timer != 0) g_source_remove(s->timer);
    g_free(s);
}

static GtkWidget *
ambient_scanline_new(void)
{
    AmbientScan *s = g_new0(AmbientScan, 1);

    s->area = gtk_drawing_area_new();
    gtk_widget_set_can_target(s->area, FALSE);
    gtk_widget_set_size_request(s->area, -1, 3);
    gtk_drawing_area_set_draw_func(
        GTK_DRAWING_AREA(s->area), ambient_scan_draw, s, NULL);

    g_object_set_data_full(G_OBJECT(s->area), "ambient-scan",
                           s, ambient_scan_free);

    s->timer = g_timeout_add(60, ambient_scan_tick, s);
    return s->area;
}

/* ---------- 9. target panel connection pulse ---------- */

typedef struct {
    AppState  *state;
    GtkWidget *area;
    guint      timer;
    double     pos;
    gboolean   active;
} AmbientPulse;

static gboolean
ambient_pulse_attack_running(void)
{
    FILE *fp;
    int   pid = -1;
    int   rc;
    char  buf[32];

    fp = fopen("/tmp/wifisting/arp/current.pid", "r");
    if (fp == NULL) return FALSE;
    if (fgets(buf, sizeof buf, fp) != NULL)
        pid = atoi(buf);
    fclose(fp);
    if (pid <= 0) return FALSE;

    errno = 0;
    rc = kill(pid, 0);
    if (rc == 0) return TRUE;
    return (errno == EPERM);
}

static void
ambient_pulse_draw(GtkDrawingArea *area, cairo_t *cr,
                   int width, int height, gpointer user_data)
{
    AmbientPulse *p = user_data;
    double track_y = height / 2.0;
    double head_x;
    int i;

    (void) area;

    cairo_set_source_rgba(cr, 0, 0, 0, 0);
    cairo_paint(cr);

    cairo_set_source_rgba(cr, 1.0, 0.23, 0.23,
                          p->active ? 0.40 : 0.10);
    cairo_set_line_width(cr, 1.0);
    cairo_move_to(cr, 6, track_y + 0.5);
    cairo_line_to(cr, width - 6, track_y + 0.5);
    cairo_stroke(cr);

    if (!p->active) return;

    head_x = 6 + p->pos * (width - 12);

    for (i = 6; i >= 1; i--) {
        double gx = head_x - i * 3.0;
        double a  = 0.40 / (double) i;
        if (gx < 6) continue;
        cairo_set_source_rgba(cr, 1.0, 0.30, 0.30, a);
        cairo_arc(cr, gx, track_y, 1.5, 0, 6.2831);
        cairo_fill(cr);
    }

    cairo_set_source_rgba(cr, 1.0, 0.35, 0.35, 0.95);
    cairo_arc(cr, head_x, track_y, 2.5, 0, 6.2831);
    cairo_fill(cr);
}

static gboolean
ambient_pulse_tick(gpointer user_data)
{
    AmbientPulse *p = user_data;
    /* Not on screen (panel hidden, window minimised): nothing to repaint. */
    if (p->area == NULL || !gtk_widget_get_mapped(p->area)) return G_SOURCE_CONTINUE;
    gboolean now_active;

    if (p->area == NULL) return G_SOURCE_REMOVE;

    now_active = ambient_pulse_attack_running();
    if (now_active != p->active) {
        p->active = now_active;
        if (p->active) p->pos = 0.0;
    }

    if (p->active) {
        p->pos += 0.015;
        if (p->pos > 1.0) p->pos = 0.0;
    }
    gtk_widget_queue_draw(p->area);
    return G_SOURCE_CONTINUE;
}

static void
ambient_pulse_free(gpointer data)
{
    AmbientPulse *p = data;
    if (p->timer != 0) g_source_remove(p->timer);
    g_free(p);
}

static GtkWidget *
ambient_target_pulse_new(AppState *state)
{
    AmbientPulse *p = g_new0(AmbientPulse, 1);

    p->state = state;
    p->area  = gtk_drawing_area_new();
    gtk_widget_set_can_target(p->area, FALSE);
    gtk_widget_set_size_request(p->area, -1, 24);
    gtk_widget_set_margin_top(p->area, 10);
    gtk_widget_set_margin_bottom(p->area, 6);
    gtk_drawing_area_set_draw_func(
        GTK_DRAWING_AREA(p->area), ambient_pulse_draw, p, NULL);

    g_object_set_data_full(G_OBJECT(p->area), "ambient-pulse",
                           p, ambient_pulse_free);

    p->timer = g_timeout_add(60, ambient_pulse_tick, p);
    return p->area;
}
