/* Presence watch. Registered as 58_proximity.
   Watches for devices by MAC and fires an action when they arrive or
   leave. The only module that runs for hours and holds state. */
/* Runtime path: PROJECT_DIR is a call now, so it cannot be concatenated. */
#define PROXIMITY_SCRIPT wf_path("modules/58_proximity.sh")

typedef struct {
    AppState    *state;
    GtkWidget   *mac;
    GtkWidget   *label;
    GtkWidget   *action;
    GtkWidget   *view;
    GSubprocess *proc;
} ProximityPage;

static void px_fin(GObject *src, GAsyncResult *res, gpointer ud)
{
    ProximityPage *p = ud;
    g_autoptr(GError) e = NULL;
    g_autofree char *o = NULL, *r = NULL;
    gboolean ok = g_subprocess_communicate_utf8_finish(G_SUBPROCESS(src), res, &o, &r, &e);
    g_clear_object(&p->proc);
    if (o && *o)             wf_output_set(p->view, o);
    else if (!ok && r && *r) wf_output_set(p->view, r);
    else                     wf_output_set(p->view, "(no output)");
}

static void px_run(GtkButton *b, gpointer ud)
{
    ProximityPage *p = ud;
    g_autoptr(GError) e = NULL;
    const char *verb = g_object_get_data(G_OBJECT(b), "px-verb");
    const char *argv[8];
    int n = 0;

    if (verb == NULL || p->proc != NULL) return;

    if (g_strcmp0(verb, "--watch") == 0) {
        const char *mac = gtk_editable_get_text(GTK_EDITABLE(p->mac));
        const char *lbl = gtk_editable_get_text(GTK_EDITABLE(p->label));
        if (mac == NULL || *mac == '\0') {
            show_toast_module(p->state, "58_proximity", "Enter a MAC first", "warn");
            return;
        }
        argv[n++] = PROXIMITY_SCRIPT; argv[n++] = "--watch"; argv[n++] = mac;
        if (lbl != NULL && *lbl != '\0') argv[n++] = lbl;
        argv[n] = NULL;
    } else if (g_strcmp0(verb, "--unwatch") == 0) {
        const char *mac = gtk_editable_get_text(GTK_EDITABLE(p->mac));
        if (mac == NULL || *mac == '\0') {
            show_toast_module(p->state, "58_proximity", "Enter a MAC first", "warn");
            return;
        }
        argv[n++] = PROXIMITY_SCRIPT; argv[n++] = "--unwatch"; argv[n++] = mac;
        argv[n] = NULL;
    } else if (g_strcmp0(verb, "--on-appear") == 0 ||
               g_strcmp0(verb, "--on-leave") == 0) {
        const char *cmd = gtk_editable_get_text(GTK_EDITABLE(p->action));
        if (cmd == NULL || *cmd == '\0') {
            show_toast_module(p->state, "58_proximity",
                "Enter a command for the action first", "warn");
            return;
        }
        argv[n++] = PROXIMITY_SCRIPT; argv[n++] = verb; argv[n++] = cmd;
        argv[n] = NULL;
    } else if (g_strcmp0(verb, "--start") == 0) {
        argv[n++] = "pkexec"; argv[n++] = PROXIMITY_SCRIPT; argv[n++] = "--start";
        argv[n] = NULL;
    } else {
        argv[n++] = PROXIMITY_SCRIPT; argv[n++] = verb; argv[n] = NULL;
    }

    p->proc = g_subprocess_newv(argv,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE, &e);
    if (p->proc == NULL) {
        show_toast_module(p->state, "58_proximity",
            e ? e->message : "could not start", "error");
        return;
    }
    wf_output_set(p->view, "working…");
    g_subprocess_communicate_utf8_async(p->proc, NULL, NULL, px_fin, p);
}

static GtkWidget *proximity_build(AppState *state, gpointer md)
{
    ProximityPage *p = g_new0(ProximityPage, 1);
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *title = gtk_label_new("Proximity");
    GtkWidget *sub = gtk_label_new(
        "Watch for devices by MAC and act when they arrive or leave. Watches "
        "Wi-Fi probe requests and Bluetooth inquiry. Unlike everything else "
        "in the toolkit, this runs for hours and holds state between polls.");
    GtkWidget *lawful = gtk_label_new(
        "Watching for a device is surveillance. Use it on your own equipment, "
        "or where you have permission. It is also the honest half of the "
        "tracking story: the same technique that follows a person can tell "
        "you that you are being followed.");
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *ct = gtk_label_new("WATCHLIST");
    GtkWidget *r1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *r2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *l_m = gtk_label_new("MAC:");
    GtkWidget *mac = gtk_entry_new();
    GtkWidget *l_l = gtk_label_new("Label:");
    GtkWidget *label = gtk_entry_new();
    GtkWidget *action = gtk_entry_new();
    GtkWidget *b_watch = gtk_button_new_with_label("Watch");
    GtkWidget *b_unwatch = gtk_button_new_with_label("Unwatch");
    GtkWidget *b_list = gtk_button_new_with_label("List");
    GtkWidget *b_caps = gtk_button_new_with_label("Capabilities");
    GtkWidget *b_start = gtk_button_new_with_label("Start");
    GtkWidget *b_events = gtk_button_new_with_label("Events");
    GtkWidget *b_status = gtk_button_new_with_label("Status");
    GtkWidget *b_stop = gtk_button_new_with_label("Stop");
    GtkWidget *b_onapp = gtk_button_new_with_label("On appear");
    GtkWidget *b_onleave = gtk_button_new_with_label("On leave");
    GtkWidget *note = gtk_label_new(
        "A departure is only reported after three consecutive quiet polls, "
        "because a device that stops probing has not necessarily left — it "
        "has gone quiet. Wi-Fi watching needs a monitor interface; Bluetooth "
        "needs an adapter. Capabilities reports which are available rather "
        "than monitoring nothing and appearing to work.");
    GtkWidget *scroll = fp_text_view();

    (void) md;
    gtk_widget_add_css_class(page, "dependency-page");
    gtk_widget_add_css_class(title, "page-title");
    gtk_widget_add_css_class(sub, "page-subtitle");
    gtk_widget_add_css_class(lawful, "dependency-summary");
    gtk_widget_add_css_class(card, "section-card");
    gtk_widget_add_css_class(ct, "section-title");
    gtk_widget_add_css_class(note, "dependency-summary");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(sub), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(lawful), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(ct), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(sub), TRUE);
    gtk_label_set_wrap(GTK_LABEL(lawful), TRUE);
    gtk_label_set_wrap(GTK_LABEL(note), TRUE);
    gtk_widget_set_hexpand(mac, TRUE);
    gtk_widget_set_hexpand(label, TRUE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(mac), "aa:bb:cc:dd:ee:ff");
    gtk_entry_set_placeholder_text(GTK_ENTRY(label), "my laptop");
    gtk_widget_set_hexpand(action, TRUE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(action),
        "command to run on appear/leave (receives MAC and label)");
    gtk_widget_set_size_request(scroll, -1, 240);

    p->state = state; p->mac = mac; p->label = label;
    p->view = gtk_scrolled_window_get_child(GTK_SCROLLED_WINDOW(scroll));

    {
        struct { GtkWidget *b; const char *v; } a[] = {
            { b_watch,   "--watch" },
            { b_unwatch, "--unwatch" },
            { b_list,    "--list-tsv" },
            { b_caps,    "--caps-tsv" },
            { b_start,   "--start" },
            { b_events,  "--events-tsv" },
            { b_status,  "--status-tsv" },
            { b_stop,    "--stop" },
            { b_onapp,   "--on-appear" },
            { b_onleave, "--on-leave" },
        };
        for (guint i = 0; i < G_N_ELEMENTS(a); i++) {
            g_object_set_data(G_OBJECT(a[i].b), "px-verb", (gpointer) a[i].v);
            g_signal_connect(a[i].b, "clicked", G_CALLBACK(px_run), p);
        }
    }

    gtk_box_append(GTK_BOX(r1), l_m);
    gtk_box_append(GTK_BOX(r1), mac);
    gtk_box_append(GTK_BOX(r1), l_l);
    gtk_box_append(GTK_BOX(r1), label);
    gtk_box_append(GTK_BOX(r1), b_watch);
    gtk_box_append(GTK_BOX(r1), b_unwatch);
    gtk_box_append(GTK_BOX(r2), b_list);
    gtk_box_append(GTK_BOX(r2), b_caps);
    gtk_box_append(GTK_BOX(r2), b_start);
    gtk_box_append(GTK_BOX(r2), b_events);
    gtk_box_append(GTK_BOX(r2), b_status);
    gtk_box_append(GTK_BOX(r2), b_stop);
    {
        GtkWidget *r3 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        GtkWidget *l_a = gtk_label_new("Action:");
        gtk_box_append(GTK_BOX(r3), l_a);
        gtk_box_append(GTK_BOX(r3), action);
        gtk_box_append(GTK_BOX(r3), b_onapp);
        gtk_box_append(GTK_BOX(r3), b_onleave);
        gtk_box_append(GTK_BOX(card), r3);
    }
    gtk_box_append(GTK_BOX(card), ct);
    gtk_box_append(GTK_BOX(card), r1);
    gtk_box_append(GTK_BOX(card), r2);
    gtk_box_append(GTK_BOX(card), note);
    gtk_box_append(GTK_BOX(page), title);
    gtk_box_append(GTK_BOX(page), sub);
    gtk_box_append(GTK_BOX(page), lawful);
    gtk_box_append(GTK_BOX(page), card);
    gtk_box_append(GTK_BOX(page), scroll);
    return page;
}

static ModuleSubmenuEntry proximity_entries[] = {
    { "Proximity", "network-wireless-symbolic", proximity_build },
};
