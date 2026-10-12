
/* ==================================================================== */
/*  PUBLIC WI-FI AUDIT — scan results                                   */
/*                                                                      */
/*  The scaffold rendered this page as a group of buttons. What it       */
/*  should be is a list of what the scan found, graded - the same shape  */
/*  as the recon target list, but carrying audit information instead of  */
/*  signal strength: severity, the finding, and why.                     */
/* ==================================================================== */

#define AUDIT_SCAN_SCRIPT wf_path("modules/46_public_wifi_audit.sh")

typedef struct {
    AppState    *state;
    GtkWidget   *list;
    GtkWidget   *status;
    GSubprocess *proc;
} AuditScanPage;

static void
audit_row_add(AuditScanPage *p, const char *bssid, const char *ssid,
              const char *channel, const char *privacy,
              const char *severity, const char *finding, const char *detail)
{
    GtkWidget *row = gtk_list_box_row_new();
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *top = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *left = gtk_box_new(GTK_ORIENTATION_VERTICAL, 1);
    GtkWidget *l_ssid = gtk_label_new(
        (ssid != NULL && *ssid != '\0') ? ssid : "(hidden)");
    g_autofree char *sev = g_strdup_printf(" %s ",
        (severity != NULL && *severity != '\0') ? severity : "?");
    GtkWidget *l_sev = gtk_label_new(sev);
    g_autofree char *sub = g_strdup_printf("%s  ·  %s  ·  ch %s",
        (finding != NULL && *finding != '\0') ? finding : "-",
        (privacy != NULL && *privacy != '\0') ? privacy : "-",
        (channel != NULL && *channel != '\0') ? channel : "-");
    GtkWidget *l_sub = gtk_label_new(sub);
    GtkWidget *l_detail = gtk_label_new(
        (detail != NULL && *detail != '\0') ? detail : "");
    g_autofree char *mac = g_strdup_printf("%s",
        (bssid != NULL) ? bssid : "");
    GtkWidget *l_mac = gtk_label_new(mac);

    gtk_widget_add_css_class(row, "dependency-row");
    gtk_widget_add_css_class(l_ssid, "dependency-name");
    gtk_widget_add_css_class(l_sub, "dependency-package");
    gtk_widget_add_css_class(l_detail, "dependency-package");
    gtk_widget_add_css_class(l_mac, "dependency-package");

    /* Severity carries the verdict, so colour it. The classes are the ones
       the theme already defines for state; nothing new is invented. */
    switch (severity != NULL ? severity[0] : '?') {
        case 'c': gtk_widget_add_css_class(l_sev, "status-error"); break;
        case 'h': gtk_widget_add_css_class(l_sev, "status-running"); break;
        case 'm': gtk_widget_add_css_class(l_sev, "status-warn"); break;
        default:  gtk_widget_add_css_class(l_sev, "dependency-package"); break;
    }

    gtk_label_set_xalign(GTK_LABEL(l_ssid), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(l_sub), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(l_detail), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(l_mac), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(l_ssid), PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(left, TRUE);
    gtk_widget_set_valign(l_sev, GTK_ALIGN_START);

    gtk_box_append(GTK_BOX(left), l_ssid);
    gtk_box_append(GTK_BOX(left), l_sub);
    gtk_box_append(GTK_BOX(left), l_detail);
    gtk_box_append(GTK_BOX(top), left);
    gtk_box_append(GTK_BOX(top), l_sev);
    gtk_box_append(GTK_BOX(box), top);
    gtk_box_append(GTK_BOX(box), l_mac);
    gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), box);
    gtk_list_box_append(GTK_LIST_BOX(p->list), row);
}

static void
audit_scan_clear(AuditScanPage *p)
{
    GtkWidget *child;

    if (p->list == NULL) return;
    child = gtk_widget_get_first_child(p->list);
    while (child != NULL) {
        GtkWidget *next = gtk_widget_get_next_sibling(child);
        gtk_list_box_remove(GTK_LIST_BOX(p->list), child);
        child = next;
    }
}

static void
audit_scan_finished(GObject *source, GAsyncResult *result, gpointer user_data)
{
    AuditScanPage *p = user_data;
    g_autoptr(GError) error = NULL;
    g_autofree char *out = NULL;
    g_autofree char *err = NULL;
    gboolean ok = g_subprocess_communicate_utf8_finish(
        G_SUBPROCESS(source), result, &out, &err, &error);
    guint n = 0;

    g_clear_object(&p->proc);
    audit_scan_clear(p);

    if (!ok || out == NULL || *out == '\0') {
        const char *m = (err != NULL && *err != '\0') ? err : "(no output)";
        if (p->status != NULL) gtk_label_set_text(GTK_LABEL(p->status), m);
        show_toast_module(p->state, "46_public_wifi_audit", m, "warn");
        return;
    }

    {
        g_auto(GStrv) lines = g_strsplit(out, "\n", -1);
        for (guint i = 0; lines[i] != NULL; i++) {
            g_auto(GStrv) f = g_strsplit(lines[i], "\t", 7);
            if (g_strv_length(f) < 7) continue;
            if (g_strcmp0(f[0], "BSSID") == 0) continue;   /* header */
            audit_row_add(p, f[0], f[1], f[2], f[3], f[4], f[5], f[6]);
            n++;
        }
    }

    if (p->status != NULL) {
        g_autofree char *m = g_strdup_printf("%u network(s) graded", n);
        gtk_label_set_text(GTK_LABEL(p->status), m);
    }
}

/* mode 1 = run a scan first (needs root), mode 0 = just reload the last one */
static void
audit_scan_run(GtkButton *button, gpointer user_data)
{
    AuditScanPage *p = user_data;
    g_autoptr(GError) error = NULL;
    int mode = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(button), "as-mode"));
    const char *argv[4];

    if (p->proc != NULL) return;

    if (mode == 1) {
        /* --scan does the capture and then grades it, so one button is
           enough; it needs root for the iw scan. */
        argv[0] = "pkexec";
        argv[1] = AUDIT_SCAN_SCRIPT;
        argv[2] = "--scan";
    } else {
        argv[0] = AUDIT_SCAN_SCRIPT;
        argv[1] = "--show";
        argv[2] = NULL;
    }
    argv[3] = NULL;

    p->proc = g_subprocess_newv(argv,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE,
        &error);
    if (p->proc == NULL) {
        show_toast_module(p->state, "46_public_wifi_audit",
            error ? error->message : "could not start", "error");
        return;
    }
    if (p->status != NULL)
        gtk_label_set_text(GTK_LABEL(p->status),
            (mode == 1) ? "scanning…" : "loading…");
    g_subprocess_communicate_utf8_async(p->proc, NULL, NULL,
        audit_scan_finished, p);
}

static GtkWidget *
audit_build_scan(AppState *state, gpointer module_data)
{
    AuditScanPage *p = g_new0(AuditScanPage, 1);
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *title = gtk_label_new("Scan");
    GtkWidget *sub = gtk_label_new(
        "Every access point in range, graded by how damaging its "
        "configuration is rather than how exotic the flaw is. The scan needs "
        "root for the radio; Reload re-reads the last result offline.");
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *ctitle = gtk_label_new("NETWORKS");
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *scan = gtk_button_new_with_label("Scan now (needs root)");
    GtkWidget *reload = gtk_button_new_with_label("Reload");
    GtkWidget *status = gtk_label_new("not scanned yet");
    GtkWidget *list = gtk_list_box_new();
    GtkWidget *scroll = gtk_scrolled_window_new();

    (void) module_data;

    gtk_widget_add_css_class(page, "dependency-page");
    gtk_widget_add_css_class(title, "page-title");
    gtk_widget_add_css_class(sub, "page-subtitle");
    gtk_widget_add_css_class(card, "section-card");
    gtk_widget_add_css_class(ctitle, "section-title");
    gtk_widget_add_css_class(status, "dependency-summary");
    gtk_widget_add_css_class(scan, "accent");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(sub), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(ctitle), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(status), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(sub), TRUE);
    gtk_widget_set_halign(row, GTK_ALIGN_START);

    p->state = state;
    p->list = list;
    p->status = status;

    g_object_set_data(G_OBJECT(scan), "as-mode", GINT_TO_POINTER(1));
    g_object_set_data(G_OBJECT(reload), "as-mode", GINT_TO_POINTER(0));
    g_signal_connect(scan, "clicked", G_CALLBACK(audit_scan_run), p);
    g_signal_connect(reload, "clicked", G_CALLBACK(audit_scan_run), p);

    gtk_box_append(GTK_BOX(row), scan);
    gtk_box_append(GTK_BOX(row), reload);
    gtk_box_append(GTK_BOX(card), ctitle);
    gtk_box_append(GTK_BOX(card), row);
    gtk_box_append(GTK_BOX(card), status);

    gtk_list_box_set_selection_mode(GTK_LIST_BOX(list), GTK_SELECTION_NONE);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
        GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), list);
    gtk_widget_set_vexpand(scroll, TRUE);

    gtk_box_append(GTK_BOX(page), title);
    gtk_box_append(GTK_BOX(page), sub);
    gtk_box_append(GTK_BOX(page), card);
    gtk_box_append(GTK_BOX(page), scroll);
    return page;
}

