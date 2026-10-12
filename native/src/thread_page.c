/* Thread (802.15.4) analysis. Registered as 57_thread.
   Offline pcap analysis is the default path because it needs no radio. */
#define THREAD_SCRIPT PROJECT_DIR "/modules/57_thread.sh"

typedef struct {
    AppState    *state;
    GtkWidget   *file;
    GtkWidget   *view;
    GSubprocess *proc;
} ThreadPage;

static void th_fin(GObject *src, GAsyncResult *res, gpointer ud)
{
    ThreadPage *p = ud;
    g_autoptr(GError) e = NULL;
    g_autofree char *o = NULL, *r = NULL;
    gboolean ok = g_subprocess_communicate_utf8_finish(G_SUBPROCESS(src), res, &o, &r, &e);
    g_clear_object(&p->proc);
    if (o && *o)             wf_output_set(p->view, o);
    else if (!ok && r && *r) wf_output_set(p->view, r);
    else                     wf_output_set(p->view, "(no output)");
}

static void th_run(GtkButton *b, gpointer ud)
{
    ThreadPage *p = ud;
    g_autoptr(GError) e = NULL;
    const char *verb = g_object_get_data(G_OBJECT(b), "th-verb");
    const char *argv[8];
    int n = 0;

    if (verb == NULL || p->proc != NULL) return;

    if (g_strcmp0(verb, "--analyze") == 0 ||
        g_strcmp0(verb, "--border-router") == 0) {
        const char *f = gtk_editable_get_text(GTK_EDITABLE(p->file));
        if (f == NULL || *f == '\0') {
            show_toast_module(p->state, "57_thread",
                "Choose a capture file first", "warn");
            return;
        }
        argv[n++] = THREAD_SCRIPT; argv[n++] = verb; argv[n++] = f;
        argv[n] = NULL;
    } else if (g_strcmp0(verb, "--scan") == 0) {
        argv[n++] = "pkexec"; argv[n++] = THREAD_SCRIPT;
        argv[n++] = "--scan"; argv[n] = NULL;
    } else {
        argv[n++] = THREAD_SCRIPT; argv[n++] = verb; argv[n] = NULL;
    }

    p->proc = g_subprocess_newv(argv,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE, &e);
    if (p->proc == NULL) {
        show_toast_module(p->state, "57_thread",
            e ? e->message : "could not start", "error");
        return;
    }
    wf_output_set(p->view, "working…");
    g_subprocess_communicate_utf8_async(p->proc, NULL, NULL, th_fin, p);
}

static GtkWidget *thread_build(AppState *state, gpointer md)
{
    ThreadPage *p = g_new0(ThreadPage, 1);
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *title = gtk_label_new("Thread");
    GtkWidget *sub = gtk_label_new(
        "Thread is an IPv6 smart-home mesh on 802.15.4 at 2.4 GHz — the same "
        "radio as Zigbee, different stack. Matter runs over it, and every "
        "HomePod, Nest Hub and Echo is a Thread border router.");
    GtkWidget *why = gtk_label_new(
        "A border router is dual-homed: an 802.15.4 radio for the mesh and a "
        "Wi-Fi or Ethernet link to the LAN. It advertises a prefix from the "
        "home network into the mesh and relays mDNS between them. So a Thread "
        "foothold is not a Wi-Fi compromise, but it is a second door into the "
        "same house — one that bypasses whatever was hardened on the Wi-Fi side.");
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *ct = gtk_label_new("CAPTURE");
    GtkWidget *r1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *r2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *l_f = gtk_label_new("File:");
    GtkWidget *file = gtk_entry_new();
    GtkWidget *b_an = gtk_button_new_with_label("Analyze");
    GtkWidget *b_br = gtk_button_new_with_label("Border router");
    GtkWidget *b_sc = gtk_button_new_with_label("Channel sweep");
    GtkWidget *b_ch = gtk_button_new_with_label("Channels");
    GtkWidget *b_st = gtk_button_new_with_label("Status");
    GtkWidget *note = gtk_label_new(
        "Analyze and Border router work on a saved capture with no radio "
        "attached — that is the path to use for reviewing a capture someone "
        "else took. Channel sweep needs an 802.15.4 dongle (CC2531, CC2652, "
        "nRF52840); without one it says so rather than reporting an empty scan.");
    GtkWidget *scroll = fp_text_view();

    (void) md;
    gtk_widget_add_css_class(page, "dependency-page");
    gtk_widget_add_css_class(title, "page-title");
    gtk_widget_add_css_class(sub, "page-subtitle");
    gtk_widget_add_css_class(why, "dependency-summary");
    gtk_widget_add_css_class(card, "section-card");
    gtk_widget_add_css_class(ct, "section-title");
    gtk_widget_add_css_class(note, "dependency-summary");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(sub), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(why), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(ct), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(sub), TRUE);
    gtk_label_set_wrap(GTK_LABEL(why), TRUE);
    gtk_label_set_wrap(GTK_LABEL(note), TRUE);
    gtk_widget_set_hexpand(file, TRUE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(file), "/path/to/thread.pcap");
    gtk_widget_set_size_request(scroll, -1, 240);

    p->state = state; p->file = file;
    p->view = gtk_scrolled_window_get_child(GTK_SCROLLED_WINDOW(scroll));

    {
        struct { GtkWidget *b; const char *v; } a[] = {
            { b_an, "--analyze" }, { b_br, "--border-router" },
            { b_sc, "--scan" }, { b_ch, "--channels-tsv" },
            { b_st, "--status-tsv" },
        };
        for (guint i = 0; i < G_N_ELEMENTS(a); i++) {
            g_object_set_data(G_OBJECT(a[i].b), "th-verb", (gpointer) a[i].v);
            g_signal_connect(a[i].b, "clicked", G_CALLBACK(th_run), p);
        }
    }

    gtk_box_append(GTK_BOX(r1), l_f);
    gtk_box_append(GTK_BOX(r1), file);
    gtk_box_append(GTK_BOX(r1), b_an);
    gtk_box_append(GTK_BOX(r1), b_br);
    gtk_box_append(GTK_BOX(r2), b_sc);
    gtk_box_append(GTK_BOX(r2), b_ch);
    gtk_box_append(GTK_BOX(r2), b_st);
    gtk_box_append(GTK_BOX(card), ct);
    gtk_box_append(GTK_BOX(card), r1);
    gtk_box_append(GTK_BOX(card), r2);
    gtk_box_append(GTK_BOX(card), note);
    gtk_box_append(GTK_BOX(page), title);
    gtk_box_append(GTK_BOX(page), sub);
    gtk_box_append(GTK_BOX(page), why);
    gtk_box_append(GTK_BOX(page), card);
    gtk_box_append(GTK_BOX(page), scroll);
    return page;
}

static ModuleSubmenuEntry thread_entries[] = {
    { "Thread", "network-wireless-symbolic", thread_build },
};
