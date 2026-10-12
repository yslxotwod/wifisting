/* SSID-borne buffer overflow, with injection in the same payload.
   Registered as 55_ssid_overflow. */
#define SSID_OVERFLOW_SCRIPT PROJECT_DIR "/modules/55_ssid_overflow.sh"

typedef struct {
    AppState    *state;
    GtkWidget   *ssid;
    GtkWidget   *seconds;
    GtkWidget   *channel;
    GtkWidget   *view;
    GSubprocess *proc;
} SsidOverflowPage;

static void so_fin(GObject *src, GAsyncResult *res, gpointer ud)
{
    SsidOverflowPage *p = ud;
    g_autoptr(GError) e = NULL;
    g_autofree char *o = NULL, *r = NULL;
    gboolean ok = g_subprocess_communicate_utf8_finish(G_SUBPROCESS(src), res, &o, &r, &e);
    g_clear_object(&p->proc);
    if (o && *o)                wf_output_set(p->view, o);
    else if (!ok && r && *r)    wf_output_set(p->view, r);
    else                        wf_output_set(p->view, "(no output)");
}

static void so_run(GtkButton *b, gpointer ud)
{
    SsidOverflowPage *p = ud;
    g_autoptr(GError) e = NULL;
    const char *verb = g_object_get_data(G_OBJECT(b), "so-verb");
    const char *argv[8];
    int n = 0;

    if (verb == NULL || p->proc != NULL) return;

    if (g_strcmp0(verb, "--inject") == 0) {
        g_autofree char *s = g_strdup_printf("%d",
            gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(p->seconds)));
        g_autofree char *c = g_strdup_printf("%d",
            gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(p->channel)));
        argv[n++] = "pkexec"; argv[n++] = SSID_OVERFLOW_SCRIPT;
        argv[n++] = "--inject"; argv[n++] = "lie"; argv[n++] = s; argv[n++] = c;
        argv[n] = NULL;
    } else if (g_strcmp0(verb, "--rogue-ap") == 0) {
        const char *ssid = gtk_editable_get_text(GTK_EDITABLE(p->ssid));
        g_autofree char *c = g_strdup_printf("%d",
            gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(p->channel)));
        if (ssid == NULL || *ssid == '\0') {
            show_toast_module(p->state, "55_ssid_overflow", "Type an SSID first", "warn");
            return;
        }
        argv[n++] = "pkexec"; argv[n++] = SSID_OVERFLOW_SCRIPT;
        argv[n++] = "--rogue-ap"; argv[n++] = ssid; argv[n++] = c;
        argv[n] = NULL;
    } else {
        argv[n++] = SSID_OVERFLOW_SCRIPT; argv[n++] = verb; argv[n] = NULL;
    }

    p->proc = g_subprocess_newv(argv,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE, &e);
    if (p->proc == NULL) {
        show_toast_module(p->state, "55_ssid_overflow",
            e ? e->message : "could not start", "error");
        return;
    }
    wf_output_set(p->view, "working…");
    g_subprocess_communicate_utf8_async(p->proc, NULL, NULL, so_fin, p);
}

static GtkWidget *ssid_overflow_build(AppState *state, gpointer md)
{
    SsidOverflowPage *p = g_new0(SsidOverflowPage, 1);
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *title = gtk_label_new("SSID Overflow");
    GtkWidget *sub = gtk_label_new(
        "Beacons whose SSID exceeds the 32-byte limit and carries malicious "
        "content in the same bytes. A device that merely scans is enough — no "
        "association, no user action. DoS or code execution, depending on what "
        "sits next to the buffer. Authorised testing only.");
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *ct = gtk_label_new("INJECTION");
    GtkWidget *r1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *r2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *l_ssid = gtk_label_new("SSID:");
    GtkWidget *ssid = gtk_entry_new();
    GtkWidget *l_s = gtk_label_new("Seconds:");
    GtkWidget *secs = gtk_spin_button_new_with_range(5, 3600, 5);
    GtkWidget *l_c = gtk_label_new("Channel:");
    GtkWidget *chan = gtk_spin_button_new_with_range(1, 165, 1);
    GtkWidget *b_lat = gtk_button_new_with_label("Lengths");
    GtkWidget *b_shape = gtk_button_new_with_label("Shapes");
    GtkWidget *b_pay = gtk_button_new_with_label("Payloads");
    GtkWidget *b_inj = gtk_button_new_with_label("Inject");
    GtkWidget *b_rap = gtk_button_new_with_label("Rogue AP");
    GtkWidget *b_obs = gtk_button_new_with_label("Observations");
    GtkWidget *b_stop = gtk_button_new_with_label("Stop");
    GtkWidget *note = gtk_label_new(
        "Payloads are both at once: a fill that overruns a fixed buffer AND an "
        "injection shape placed at a chosen offset, so whichever flaw the target "
        "has is exercised by the same bytes. Over-length SSIDs need raw frames — "
        "the kernel driver and hostapd both truncate at 32 bytes, which is why "
        "Rogue AP warns on anything longer and Inject is the path for them.");
    GtkWidget *scroll = fp_text_view();

    (void) md;
    gtk_widget_add_css_class(page, "dependency-page");
    gtk_widget_add_css_class(title, "page-title");
    gtk_widget_add_css_class(sub, "page-subtitle");
    gtk_widget_add_css_class(card, "section-card");
    gtk_widget_add_css_class(ct, "section-title");
    gtk_widget_add_css_class(note, "dependency-summary");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(sub), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(ct), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(sub), TRUE);
    gtk_label_set_wrap(GTK_LABEL(note), TRUE);
    gtk_widget_set_hexpand(ssid, TRUE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(ssid), "payload SSID (<=32 for hostapd)");
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(secs), 60);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(chan), 6);
    gtk_widget_set_size_request(scroll, -1, 260);

    p->state = state; p->ssid = ssid; p->seconds = secs; p->channel = chan;
    p->view = gtk_scrolled_window_get_child(GTK_SCROLLED_WINDOW(scroll));

    {
        struct { GtkWidget *b; const char *v; } a[] = {
            { b_lat, "--lattice-tsv" }, { b_shape, "--shapes-tsv" },
            { b_pay, "--payloads-tsv" }, { b_inj, "--inject" },
            { b_rap, "--rogue-ap" }, { b_obs, "--observe-tsv" },
            { b_stop, "--stop" },
        };
        for (guint i = 0; i < G_N_ELEMENTS(a); i++) {
            g_object_set_data(G_OBJECT(a[i].b), "so-verb", (gpointer) a[i].v);
            g_signal_connect(a[i].b, "clicked", G_CALLBACK(so_run), p);
        }
    }

    gtk_box_append(GTK_BOX(r1), l_ssid);
    gtk_box_append(GTK_BOX(r1), ssid);
    gtk_box_append(GTK_BOX(r2), l_s);
    gtk_box_append(GTK_BOX(r2), secs);
    gtk_box_append(GTK_BOX(r2), l_c);
    gtk_box_append(GTK_BOX(r2), chan);
    gtk_box_append(GTK_BOX(r2), b_lat);
    gtk_box_append(GTK_BOX(r2), b_shape);
    gtk_box_append(GTK_BOX(r2), b_pay);
    gtk_box_append(GTK_BOX(r2), b_inj);
    gtk_box_append(GTK_BOX(r2), b_rap);
    gtk_box_append(GTK_BOX(r2), b_obs);
    gtk_box_append(GTK_BOX(r2), b_stop);
    gtk_box_append(GTK_BOX(card), ct);
    gtk_box_append(GTK_BOX(card), r1);
    gtk_box_append(GTK_BOX(card), r2);
    gtk_box_append(GTK_BOX(card), note);
    gtk_box_append(GTK_BOX(page), title);
    gtk_box_append(GTK_BOX(page), sub);
    gtk_box_append(GTK_BOX(page), card);
    gtk_box_append(GTK_BOX(page), scroll);
    return page;
}

static ModuleSubmenuEntry ssid_overflow_entries[] = {
    { "Overflow", "security-low-symbolic", ssid_overflow_build },
};
