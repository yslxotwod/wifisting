
/* ==================================================================== */
/*  USB ETHERNET MITM (PoisonTap-style)                                  */
/*                                                                       */
/*  The module had no page at all, so none of its verbs were reachable.  */
/*  The split that matters: the gadget half needs a USB peripheral port  */
/*  and is gated, while the responder half runs against any interface    */
/*  and is therefore testable without hardware.                          */
/* ==================================================================== */

typedef struct {
    AppState      *state;
    GtkWidget     *gadget_status;
    GtkWidget     *resp_status;
    GtkWidget     *mode_dd;
    GtkWidget     *iface_dd;
    GtkStringList *iface_names;
    GtkWidget     *claim_view;
    GtkWidget     *siphon_view;
    GSubprocess   *proc;
} UsbMitmPage;

#define USB_MITM_ID "49_usb_mitm"

/* Defined below; the runner above them references both. */
static void usbmitm_finished(GObject *source, GAsyncResult *result,
                             gpointer user_data);
static void usbmitm_refresh(UsbMitmPage *p);

static void
usbmitm_show_into(GtkWidget *view, const char *text)
{
    wf_output_set(view, text);
}

/* Append a line to one of the two output panes. */
static void
usbmitm_note(UsbMitmPage *p, gboolean siphon, const char *fmt, ...)
{
    va_list ap;
    g_autofree char *msg = NULL;
    GtkWidget *view = siphon ? p->siphon_view : p->claim_view;
    GtkTextBuffer *buf;
    GtkTextIter end;

    va_start(ap, fmt);
    msg = g_strdup_vprintf(fmt, ap);
    va_end(ap);

    if (view == NULL) return;
    buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
    gtk_text_buffer_get_end_iter(buf, &end);
    gtk_text_buffer_insert(buf, &end, msg, -1);
    gtk_text_buffer_insert(buf, &end, "\n", -1);
}

/* One runner for the verbs whose argv rides on the button. */
static void
usbmitm_run_argv(GtkButton *button, gpointer user_data)
{
    UsbMitmPage *p = user_data;
    g_autoptr(GError) error = NULL;
    const char *const *argv = g_object_get_data(G_OBJECT(button), "um-argv");

    if (p == NULL || argv == NULL || p->proc != NULL) return;
    p->proc = g_subprocess_newv(argv,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE,
        &error);
    if (p->proc == NULL) {
        show_toast_module(p->state, USB_MITM_ID,
            error ? error->message : "could not start", "error");
        return;
    }
    g_subprocess_communicate_utf8_async(p->proc, NULL, NULL,
        usbmitm_finished, p);
}

static const gchar *
usbmitm_iface_picked(UsbMitmPage *p)
{
    guint idx;

    if (p == NULL || p->iface_dd == NULL || p->iface_names == NULL) return NULL;
    idx = gtk_drop_down_get_selected(GTK_DROP_DOWN(p->iface_dd));
    if (idx == GTK_INVALID_LIST_POSITION) return NULL;
    return gtk_string_list_get_string(p->iface_names, idx);
}

static void
usbmitm_iface_reload(UsbMitmPage *p)
{
    const gchar *argv[] = { USB_MITM_SCRIPT, "--gadget-status-tsv", NULL };
    g_autoptr(GError) error = NULL;
    g_autofree gchar *out = NULL;
    g_autofree gchar *err = NULL;
    GSubprocess *proc;

    if (p == NULL || p->iface_names == NULL) return;
    gtk_string_list_splice(p->iface_names, 0,
        g_list_model_get_n_items(G_LIST_MODEL(p->iface_names)), NULL);

    proc = g_subprocess_newv(argv,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE,
        &error);
    if (proc != NULL) {
        if (g_subprocess_communicate_utf8(proc, NULL, NULL, &out, &err, &error)
            && out != NULL) {
            g_auto(GStrv) lines = g_strsplit(out, "\n", -1);
            for (guint i = 0; lines[i] != NULL; i++) {
                g_auto(GStrv) kv = g_strsplit(lines[i], "\t", 2);
                if (g_strcmp0(kv[0], "iface") == 0 && kv[1] != NULL && *kv[1])
                    gtk_string_list_append(p->iface_names, kv[1]);
            }
        }
        g_object_unref(proc);
    }
    /* Always offer the common names, so the responder can be driven against
       a veth pair - which is how it is tested with no gadget hardware. */
    gtk_string_list_append(p->iface_names, "usb0");
    gtk_string_list_append(p->iface_names, "veth0");
    gtk_drop_down_set_selected(GTK_DROP_DOWN(p->iface_dd), 0);
}

static void
usbmitm_refresh(UsbMitmPage *p)
{
    const gchar *g_argv[] = { USB_MITM_SCRIPT, "--gadget-status-tsv", NULL };
    const gchar *r_argv[] = { USB_MITM_SCRIPT, "--responder-status-tsv", NULL };
    g_autoptr(GError) error = NULL;
    g_autofree gchar *out = NULL;
    g_autofree gchar *err = NULL;
    GSubprocess *proc;
    g_autofree char *line = NULL;

    if (p == NULL) return;

    proc = g_subprocess_newv(g_argv,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE, &error);
    if (proc != NULL) {
        if (g_subprocess_communicate_utf8(proc, NULL, NULL, &out, &err, &error)
            && out != NULL) {
            g_auto(GStrv) lines = g_strsplit(out, "\n", -1);
            g_autofree char *joined = g_strjoinv("  ", lines);
            line = g_strdup_printf("gadget: %s", joined);
        }
        g_object_unref(proc);
        if (p->gadget_status != NULL && line != NULL)
            gtk_label_set_text(GTK_LABEL(p->gadget_status), line);
    }

    g_clear_pointer(&line, g_free);
    g_clear_pointer(&out, g_free);
    g_clear_pointer(&err, g_free);
    proc = g_subprocess_newv(r_argv,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE, &error);
    if (proc != NULL) {
        if (g_subprocess_communicate_utf8(proc, NULL, NULL, &out, &err, &error)
            && out != NULL) {
            g_auto(GStrv) lines = g_strsplit(out, "\n", -1);
            g_autofree char *joined = g_strjoinv("  ", lines);
            line = g_strdup_printf("responder: %s", joined);
        }
        g_object_unref(proc);
        if (p->resp_status != NULL && line != NULL)
            gtk_label_set_text(GTK_LABEL(p->resp_status), line);
    }
}

static void
usbmitm_finished(GObject *source, GAsyncResult *result, gpointer user_data)
{
    UsbMitmPage *p = user_data;
    g_autoptr(GError) error = NULL;
    g_autofree char *out = NULL;
    g_autofree char *err = NULL;
    gboolean ok;
    gboolean siphon = GPOINTER_TO_INT(
        g_object_get_data(G_OBJECT(source), "um-siphon"));

    ok = g_subprocess_communicate_utf8_finish(
        G_SUBPROCESS(source), result, &out, &err, &error);
    g_clear_object(&p->proc);

    if (!ok || out == NULL || *out == '\0') {
        /* Surface the reason: "nothing happened" and "it refused" are
           indistinguishable in a text pane otherwise. */
        usbmitm_note(p, siphon, "%s",
                     (err != NULL && *err != '\0') ? err : "(no output)");
        show_toast_module(p->state, USB_MITM_ID,
            (err != NULL && *err != '\0') ? err : "no output", "warn");
        return;
    }
    usbmitm_show_into(siphon ? p->siphon_view : p->claim_view, out);
    usbmitm_refresh(p);
}

static void
usbmitm_responder_start(GtkButton *button, gpointer user_data)
{
    UsbMitmPage *p = user_data;
    const char *iface = usbmitm_iface_picked(p);
    guint mode_idx;
    const char *mode;
    g_autoptr(GError) error = NULL;

    (void) button;

    if (p == NULL || p->proc != NULL) return;
    if (iface == NULL || *iface == '\0') {
        show_toast_module(p->state, USB_MITM_ID,
            "Pick an interface first", "warn");
        return;
    }
    mode_idx = gtk_drop_down_get_selected(GTK_DROP_DOWN(p->mode_dd));
    mode = (mode_idx == 1) ? "transparent" : "portal";

    /* Needs root: it configures an address, starts dnsmasq and, in
       transparent mode, installs an iptables redirect. */
    {
        const char *argv[] = { "pkexec", USB_MITM_SCRIPT, "--responder-start",
                               mode, iface, NULL };
        p->proc = g_subprocess_newv(argv,
            G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE,
            &error);
    }
    if (p->proc == NULL) {
        show_toast_module(p->state, USB_MITM_ID,
            error ? error->message : "could not start", "error");
        return;
    }
    show_toast_module(p->state, USB_MITM_ID, "Responder starting",
                      "status-running");
    g_subprocess_communicate_utf8_async(p->proc, NULL, NULL,
        usbmitm_finished, p);
}

static GtkWidget *
usbmitm_card(const char *title)
{
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *lbl = gtk_label_new(title);

    gtk_widget_add_css_class(card, "section-card");
    gtk_widget_add_css_class(lbl, "section-title");
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0f);
    gtk_box_append(GTK_BOX(card), lbl);
    return card;
}

static GtkWidget *
usbmitm_build_overview(AppState *state, gpointer module_data)
{
    UsbMitmPage *p = g_new0(UsbMitmPage, 1);
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    GtkWidget *title = gtk_label_new("USB Ethernet MitM");
    GtkWidget *sub = gtk_label_new(
        "The implant enumerates as a USB network adapter, not a keyboard. The "
        "host trusts a wired link, asks it for an address, and the answer is "
        "the attack: DHCP option 3 (router) and option 6 (DNS) both point at "
        "the implant, so all traffic routes through it with nothing for the "
        "user to install.  Gadget needs a USB peripheral port; the responder "
        "needs no gadget hardware — point it at a veth pair to test.");

    (void) state; (void) module_data;

    gtk_widget_add_css_class(page, "dependency-page");
    gtk_widget_add_css_class(title, "page-title");
    gtk_widget_add_css_class(sub, "page-subtitle");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(sub), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(sub), TRUE);

    p->state = state;
    gtk_box_append(GTK_BOX(page), title);
    gtk_box_append(GTK_BOX(page), sub);

    /* ---- gadget ---- */
    {
        GtkWidget *card = usbmitm_card("GADGET   needs USB peripheral hardware");
        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        GtkWidget *up = gtk_button_new_with_label("Bring up");
        GtkWidget *down = gtk_button_new_with_label("Tear down");
        GtkWidget *refresh = gtk_button_new_with_label("Refresh");
        GtkWidget *st = gtk_label_new("gadget: …");
        static const char *const a_up[]   = { "pkexec", USB_MITM_SCRIPT, "--gadget-up", NULL };
        static const char *const a_down[] = { "pkexec", USB_MITM_SCRIPT, "--gadget-down", NULL };
        static const char *const a_st[]   = { USB_MITM_SCRIPT, "--gadget-status-tsv", NULL };

        gtk_widget_add_css_class(st, "dependency-summary");
        gtk_label_set_xalign(GTK_LABEL(st), 0.0f);
        g_object_set_data_full(G_OBJECT(up), "um-argv",
            g_strdupv((gchar **) a_up), (GDestroyNotify) g_strfreev);
        g_object_set_data_full(G_OBJECT(down), "um-argv",
            g_strdupv((gchar **) a_down), (GDestroyNotify) g_strfreev);
        g_object_set_data_full(G_OBJECT(refresh), "um-argv",
            g_strdupv((gchar **) a_st), (GDestroyNotify) g_strfreev);
        g_signal_connect(up, "clicked", G_CALLBACK(usbmitm_run_argv), p);
        g_signal_connect(down, "clicked", G_CALLBACK(usbmitm_run_argv), p);
        g_signal_connect(refresh, "clicked", G_CALLBACK(usbmitm_run_argv), p);

        gtk_box_append(GTK_BOX(row), up);
        gtk_box_append(GTK_BOX(row), down);
        gtk_box_append(GTK_BOX(row), refresh);
        gtk_box_append(GTK_BOX(card), row);
        gtk_box_append(GTK_BOX(card), st);
        p->gadget_status = st;
        gtk_box_append(GTK_BOX(page), card);
    }

    /* ---- responder ---- */
    {
        GtkWidget *card = usbmitm_card("RESPONDER   DHCP + DNS + portal or proxy");
        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        GtkWidget *mlbl = gtk_label_new("Mode:");
        const char *modes[] = { "portal", "transparent", NULL };
        GtkWidget *mode = gtk_drop_down_new_from_strings(modes);
        GtkWidget *ilbl = gtk_label_new("Interface:");
        GtkWidget *iface_dd;
        GtkWidget *rescan = gtk_button_new_with_label("Rescan");
        GtkWidget *start = gtk_button_new_with_label("Start responder");
        GtkWidget *stop = gtk_button_new_with_label("Stop");
        GtkWidget *st = gtk_label_new("responder: …");
        static const char *const a_stop[] = { "pkexec", USB_MITM_SCRIPT, "--responder-stop", NULL };

        p->iface_names = gtk_string_list_new(NULL);
        iface_dd = gtk_drop_down_new(G_LIST_MODEL(p->iface_names), NULL);
        p->iface_dd = iface_dd;
        p->mode_dd = mode;
        gtk_widget_set_valign(mlbl, GTK_ALIGN_CENTER);
        gtk_widget_set_valign(ilbl, GTK_ALIGN_CENTER);
        gtk_widget_add_css_class(st, "dependency-summary");
        gtk_label_set_xalign(GTK_LABEL(st), 0.0f);
        gtk_widget_add_css_class(start, "accent");

        g_object_set_data_full(G_OBJECT(stop), "um-argv",
            g_strdupv((gchar **) a_stop), (GDestroyNotify) g_strfreev);
        g_signal_connect(stop, "clicked", G_CALLBACK(usbmitm_run_argv), p);
        g_signal_connect(start, "clicked",
                         G_CALLBACK(usbmitm_responder_start), p);
        g_signal_connect_swapped(rescan, "clicked",
                         G_CALLBACK(usbmitm_iface_reload), p);

        gtk_box_append(GTK_BOX(row), mlbl);
        gtk_box_append(GTK_BOX(row), mode);
        gtk_box_append(GTK_BOX(row), ilbl);
        gtk_box_append(GTK_BOX(row), iface_dd);
        gtk_box_append(GTK_BOX(row), rescan);
        gtk_box_append(GTK_BOX(row), start);
        gtk_box_append(GTK_BOX(row), stop);
        gtk_box_append(GTK_BOX(card), row);
        gtk_box_append(GTK_BOX(card), st);
        p->resp_status = st;
        gtk_box_append(GTK_BOX(page), card);
    }

    /* ---- what we claim ---- */
    {
        GtkWidget *card = usbmitm_card("WHAT WE CLAIM   the attack, inspectable");
        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        GtkWidget *show = gtk_button_new_with_label("Show claimed routes");
        GtkWidget *scroll = fp_text_view();
        static const char *const a_claim[] = { USB_MITM_SCRIPT, "--claim-route-tsv", NULL };

        g_object_set_data_full(G_OBJECT(show), "um-argv",
            g_strdupv((gchar **) a_claim), (GDestroyNotify) g_strfreev);
        g_signal_connect(show, "clicked", G_CALLBACK(usbmitm_run_argv), p);
        p->claim_view = gtk_scrolled_window_get_child(
            GTK_SCROLLED_WINDOW(scroll));
        gtk_widget_set_size_request(scroll, -1, 120);
        gtk_box_append(GTK_BOX(row), show);
        gtk_box_append(GTK_BOX(card), row);
        gtk_box_append(GTK_BOX(card), scroll);
        gtk_box_append(GTK_BOX(page), card);
    }

    /* ---- siphoned ---- */
    {
        GtkWidget *card = usbmitm_card(
            "SIPHONED   portal submissions, proxied requests and cookies");
        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        GtkWidget *show = gtk_button_new_with_label("Show siphoned");
        GtkWidget *clr = gtk_button_new_with_label("Clear");
        GtkWidget *scroll = fp_text_view();
        static const char *const a_show[] = { USB_MITM_SCRIPT, "--siphon-tsv", NULL };
        static const char *const a_clr[]  = { "pkexec", USB_MITM_SCRIPT, "--siphon-clear", NULL };

        g_object_set_data_full(G_OBJECT(show), "um-argv",
            g_strdupv((gchar **) a_show), (GDestroyNotify) g_strfreev);
        g_object_set_data_full(G_OBJECT(clr), "um-argv",
            g_strdupv((gchar **) a_clr), (GDestroyNotify) g_strfreev);
        g_signal_connect(show, "clicked", G_CALLBACK(usbmitm_run_argv), p);
        g_signal_connect(clr, "clicked", G_CALLBACK(usbmitm_run_argv), p);
        p->siphon_view = gtk_scrolled_window_get_child(
            GTK_SCROLLED_WINDOW(scroll));
        gtk_widget_set_size_request(scroll, -1, 160);
        gtk_box_append(GTK_BOX(row), show);
        gtk_box_append(GTK_BOX(row), clr);
        gtk_box_append(GTK_BOX(card), row);
        gtk_box_append(GTK_BOX(card), scroll);
        gtk_box_append(GTK_BOX(page), card);
    }

    usbmitm_iface_reload(p);
    usbmitm_refresh(p);
    return page;
}

static ModuleSubmenuEntry usbmitm_entries[] = {
    { "MitM", "network-wired-symbolic", usbmitm_build_overview },
};

