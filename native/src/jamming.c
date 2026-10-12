/* Frame-level jamming via the modwifi driver. Registered as 53_jamming. */
#define JAMMING_SCRIPT wf_path("modules/53_jamming.sh")

typedef struct {
    AppState    *state;
    GtkWidget   *bssid;
    GtkWidget   *ms;
    GtkWidget   *view;
    GSubprocess *proc;
} JammingPage;

static void jm_fin(GObject *src, GAsyncResult *res, gpointer ud)
{
    JammingPage *p = ud;
    g_autoptr(GError) e = NULL;
    g_autofree char *o = NULL, *r = NULL;
    gboolean ok = g_subprocess_communicate_utf8_finish(G_SUBPROCESS(src), res, &o, &r, &e);
    g_clear_object(&p->proc);
    if (o && *o)             wf_output_set(p->view, o);
    else if (!ok && r && *r) wf_output_set(p->view, r);
    else                     wf_output_set(p->view, "(no output)");
}

static void jm_run(GtkButton *b, gpointer ud)
{
    JammingPage *p = ud;
    g_autoptr(GError) e = NULL;
    const char *verb = g_object_get_data(G_OBJECT(b), "jm-verb");
    const char *argv[8];
    int n = 0;

    if (verb == NULL || p->proc != NULL) return;

    if (g_strcmp0(verb, "--reactive-jam") == 0) {
        const char *bssid = gtk_editable_get_text(GTK_EDITABLE(p->bssid));
        g_autofree char *ms = g_strdup_printf("%d",
            gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(p->ms)));
        if (bssid == NULL || *bssid == '\0') {
            show_toast_module(p->state, "53_jamming",
                "Enter the target BSSID", "warn");
            return;
        }
        argv[n++] = "pkexec"; argv[n++] = JAMMING_SCRIPT;
        argv[n++] = "--reactive-jam"; argv[n++] = bssid; argv[n++] = ms;
        argv[n] = NULL;
    } else if (g_object_get_data(G_OBJECT(b), "jm-arg") != NULL) {
        /* Verb and its argument are separate fields so both are visible as
           literals - a pipe-joined string hid them from the verb audit. */
        const char *arg = g_object_get_data(G_OBJECT(b), "jm-arg");
        argv[n++] = "pkexec"; argv[n++] = JAMMING_SCRIPT;
        argv[n++] = verb; argv[n++] = arg;
        argv[n] = NULL;
    } else {
        argv[n++] = "pkexec"; argv[n++] = JAMMING_SCRIPT;
        argv[n++] = verb; argv[n] = NULL;
    }

    p->proc = g_subprocess_newv(argv,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE, &e);
    if (p->proc == NULL) {
        show_toast_module(p->state, "53_jamming",
            e ? e->message : "could not start", "error");
        return;
    }
    wf_output_set(p->view, "working…");
    g_subprocess_communicate_utf8_async(p->proc, NULL, NULL, jm_fin, p);
}

static GtkWidget *jamming_build(AppState *state, gpointer md)
{
    JammingPage *p = g_new0(JammingPage, 1);
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *title = gtk_label_new("Jamming");
    GtkWidget *sub = gtk_label_new(
        "Frame-level jamming through the modwifi driver. Unlike a deauth "
        "flood, which forges frames the target obeys, these work below the "
        "protocol: the radio is told to transmit over a frame, or to stop "
        "listening before it does.");
    GtkWidget *warn = gtk_label_new(
        "Transmitting on radio spectrum is regulated in most countries, and "
        "owning the network is not a defence — the interference is not "
        "confined to your property. Carrier-sense manipulation and FCS "
        "corruption degrade the shared channel. Use on equipment you control.");
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *ct = gtk_label_new("TARGET");
    GtkWidget *r1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *r2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *l_b = gtk_label_new("BSSID:");
    GtkWidget *bssid = gtk_entry_new();
    GtkWidget *l_ms = gtk_label_new("Duration (ms):");
    GtkWidget *ms = gtk_spin_button_new_with_range(100, 600000, 100);
    GtkWidget *b_caps = gtk_button_new_with_label("Driver capabilities");
    GtkWidget *b_jam = gtk_button_new_with_label("Reactive jam");
    GtkWidget *b_cj = gtk_button_new_with_label("Constant jam");
    GtkWidget *b_cs = gtk_button_new_with_label("Carrier sense off");
    GtkWidget *b_cs_on = gtk_button_new_with_label("Carrier sense on");
    GtkWidget *b_fcs = gtk_button_new_with_label("Corrupt FCS");
    GtkWidget *b_fcs_ok = gtk_button_new_with_label("Valid FCS");
    GtkWidget *b_stop = gtk_button_new_with_label("Stop and restore");
    GtkWidget *note = gtk_label_new(
        "Reactive jamming blocks only the chosen access point's beacons and "
        "probe responses, leaving the rest of the channel alone. Constant "
        "jamming is not publicly released by the modwifi authors — the page "
        "reports it unavailable rather than pretending. Stop always restores "
        "carrier sense and the FCS, so a jam is never left enabled.");
    GtkWidget *scroll = fp_text_view();

    (void) md;
    gtk_widget_add_css_class(page, "dependency-page");
    gtk_widget_add_css_class(title, "page-title");
    gtk_widget_add_css_class(sub, "page-subtitle");
    gtk_widget_add_css_class(warn, "dependency-summary");
    gtk_widget_add_css_class(card, "section-card");
    gtk_widget_add_css_class(ct, "section-title");
    gtk_widget_add_css_class(note, "dependency-summary");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(sub), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(warn), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(ct), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(sub), TRUE);
    gtk_label_set_wrap(GTK_LABEL(warn), TRUE);
    gtk_label_set_wrap(GTK_LABEL(note), TRUE);
    gtk_widget_set_hexpand(bssid, TRUE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(bssid), "aa:bb:cc:dd:ee:ff");
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(ms), 10000);
    gtk_widget_set_size_request(scroll, -1, 240);

    p->state = state; p->bssid = bssid; p->ms = ms;
    p->view = gtk_scrolled_window_get_child(GTK_SCROLLED_WINDOW(scroll));

    {
        struct { GtkWidget *b; const char *v; const char *arg; } a[] = {
            { b_caps,   "--caps-tsv",     NULL      },
            { b_jam,    "--reactive-jam", NULL      },
            { b_cj,     "--constant-jam", NULL      },
            { b_cs,     "--cs",           "off"     },
            { b_cs_on,  "--cs",           "on"      },
            { b_fcs,    "--fcs",          "corrupt" },
            { b_fcs_ok, "--fcs",          "valid"   },
            { b_stop,   "--stop",         NULL      },
        };
        for (guint i = 0; i < G_N_ELEMENTS(a); i++) {
            g_object_set_data(G_OBJECT(a[i].b), "jm-verb", (gpointer) a[i].v);
            g_object_set_data(G_OBJECT(a[i].b), "jm-arg",  (gpointer) a[i].arg);
            g_signal_connect(a[i].b, "clicked", G_CALLBACK(jm_run), p);
        }
    }

    gtk_box_append(GTK_BOX(r1), l_b);
    gtk_box_append(GTK_BOX(r1), bssid);
    gtk_box_append(GTK_BOX(r1), l_ms);
    gtk_box_append(GTK_BOX(r1), ms);
    gtk_box_append(GTK_BOX(r2), b_caps);
    gtk_box_append(GTK_BOX(r2), b_jam);
    gtk_box_append(GTK_BOX(r2), b_cj);
    gtk_box_append(GTK_BOX(r2), b_cs);
    gtk_box_append(GTK_BOX(r2), b_cs_on);
    gtk_box_append(GTK_BOX(r2), b_fcs);
    gtk_box_append(GTK_BOX(r2), b_fcs_ok);
    gtk_box_append(GTK_BOX(r2), b_stop);
    gtk_box_append(GTK_BOX(card), ct);
    gtk_box_append(GTK_BOX(card), r1);
    gtk_box_append(GTK_BOX(card), r2);
    gtk_box_append(GTK_BOX(card), note);
    gtk_box_append(GTK_BOX(page), title);
    gtk_box_append(GTK_BOX(page), sub);
    gtk_box_append(GTK_BOX(page), warn);
    gtk_box_append(GTK_BOX(page), card);
    gtk_box_append(GTK_BOX(page), scroll);
    return page;
}

static ModuleSubmenuEntry jamming_entries[] = {
    { "Jamming", "network-offline-symbolic", jamming_build },
};
