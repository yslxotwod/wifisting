
/* ==================================================================== */
/*  ROUTER LAN ATTACKS (50_router_lan)                                  */
/*                                                                      */
/*  The module had no page and was not registered, so its define was     */
/*  referenced by nothing and every verb was unreachable. Worse, a       */
/*  shared dispatch arm made the audit believe they were fine:           */
/*                                                                      */
/*    --scan-tsv|--tr064-tsv|--hnap-tsv|--snmp-tsv|--rebind-plan|...)    */
/*                                                                      */
/*  is one handler for seven distinct verbs, not seven spellings of one. */
/* ==================================================================== */

typedef struct {
    AppState    *state;
    GtkWidget   *host;
    GtkWidget   *url;
    GtkWidget   *view;
    GSubprocess *proc;
} RouterLanPage;

#define ROUTER_LAN_ID "50_router_lan"

static void
rl_show(GtkWidget *view, const char *text)
{
    wf_output_set(view, text);
}

static void
rl_finished(GObject *source, GAsyncResult *result, gpointer user_data)
{
    RouterLanPage *p = user_data;
    g_autoptr(GError) error = NULL;
    g_autofree char *out = NULL;
    g_autofree char *err = NULL;
    gboolean ok = g_subprocess_communicate_utf8_finish(
        G_SUBPROCESS(source), result, &out, &err, &error);

    g_clear_object(&p->proc);
    if (ok && out != NULL && *out != '\0')   rl_show(p->view, out);
    else                                     rl_show(p->view,
        (err != NULL && *err != '\0') ? err : "(no output)");
}

static void
rl_run(GtkButton *button, gpointer user_data)
{
    RouterLanPage *p = user_data;
    g_autoptr(GError) error = NULL;
    const char *verb = g_object_get_data(G_OBJECT(button), "rl-verb");
    int arg = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(button), "rl-arg"));
    const char *host = p->host != NULL
        ? gtk_editable_get_text(GTK_EDITABLE(p->host)) : "";
    const char *argv[6];
    int n = 0;

    if (verb == NULL || p->proc != NULL) return;

    if (arg == 1 && (host == NULL || *host == '\0')) {
        show_toast_module(p->state, ROUTER_LAN_ID,
            "Enter the router address first", "warn");
        return;
    }
    /* --upnp-tsv wants the device's description URL, not its address. */
    if (arg == 2 && (p->url == NULL ||
        *(gtk_editable_get_text(GTK_EDITABLE(p->url))) == '\0')) {
        show_toast_module(p->state, ROUTER_LAN_ID,
            "Paste the device description URL first", "warn");
        return;
    }

    argv[n++] = ROUTER_LAN_SCRIPT;
    argv[n++] = verb;
    if (arg == 1) argv[n++] = host;
    if (arg == 2) argv[n++] = gtk_editable_get_text(GTK_EDITABLE(p->url));
    argv[n] = NULL;

    p->proc = g_subprocess_newv(argv,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE,
        &error);
    if (p->proc == NULL) {
        show_toast_module(p->state, ROUTER_LAN_ID,
            error ? error->message : "could not start", "error");
        return;
    }
    rl_show(p->view, "working…");
    g_subprocess_communicate_utf8_async(p->proc, NULL, NULL, rl_finished, p);
}

static GtkWidget *
router_lan_build(AppState *state, gpointer module_data)
{
    RouterLanPage *p = g_new0(RouterLanPage, 1);
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    GtkWidget *title = gtk_label_new("Router LAN Attacks");
    GtkWidget *sub = gtk_label_new(
        "Reads a router's management surface from the LAN side. The three "
        "*-tsv verbs interrogate the device; the two plans describe an "
        "attack without running it.");
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *ctitle = gtk_label_new("TARGET");
    GtkWidget *r1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *r2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *host = gtk_entry_new();
    GtkWidget *url = gtk_entry_new();
    GtkWidget *b_tr064 = gtk_button_new_with_label("TR-064");
    GtkWidget *b_hnap = gtk_button_new_with_label("HNAP");
    GtkWidget *b_snmp = gtk_button_new_with_label("SNMP");
    GtkWidget *b_ssdp = gtk_button_new_with_label("SSDP / UPnP");
    GtkWidget *b_upnp = gtk_button_new_with_label("WAN service");
    GtkWidget *b_rebind = gtk_button_new_with_label("Rebind plan");
    GtkWidget *b_csrf = gtk_button_new_with_label("CSRF plan");
    GtkWidget *note = gtk_label_new(
        "TR-064, HNAP and SNMP need the router address. SSDP discovers on "
        "its own, and the two plans are offline: they describe the sequence "
        "rather than performing it.");
    GtkWidget *scroll = fp_text_view();

    (void) module_data;

    gtk_widget_add_css_class(page, "dependency-page");
    gtk_widget_add_css_class(title, "page-title");
    gtk_widget_add_css_class(sub, "page-subtitle");
    gtk_widget_add_css_class(card, "section-card");
    gtk_widget_add_css_class(ctitle, "section-title");
    gtk_widget_add_css_class(note, "dependency-summary");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(sub), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(ctitle), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(sub), TRUE);
    gtk_label_set_wrap(GTK_LABEL(note), TRUE);
    gtk_widget_set_hexpand(host, TRUE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(host), "192.168.1.1");
    gtk_widget_set_size_request(scroll, -1, 240);

    p->state = state;
    p->host = host;
    p->url = url;
    gtk_widget_set_hexpand(url, TRUE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(url),
        "http://192.168.1.1:5000/rootDesc.xml");
    gtk_box_append(GTK_BOX(r2), url);
    gtk_box_append(GTK_BOX(r2), b_upnp);
    p->view = gtk_scrolled_window_get_child(GTK_SCROLLED_WINDOW(scroll));

    {
        struct { GtkWidget *b; const char *verb; int arg; } acts[] = {
            { b_tr064,  "--tr064-tsv",   1 },
            { b_hnap,   "--hnap-tsv",    1 },
            { b_snmp,   "--snmp-tsv",    1 },
            { b_ssdp,   "--ssdp-tsv",    0 },
            { b_upnp,   "--upnp-tsv",    2 },
            { b_rebind, "--rebind-plan", 0 },
            { b_csrf,   "--csrf-plan",   0 },
        };
        for (guint i = 0; i < G_N_ELEMENTS(acts); i++) {
            g_object_set_data(G_OBJECT(acts[i].b), "rl-verb",
                              (gpointer) acts[i].verb);
            g_object_set_data(G_OBJECT(acts[i].b), "rl-arg",
                              GINT_TO_POINTER(acts[i].arg));
            g_signal_connect(acts[i].b, "clicked", G_CALLBACK(rl_run), p);
        }
    }

    gtk_box_append(GTK_BOX(r1), host);
    gtk_box_append(GTK_BOX(r1), b_tr064);
    gtk_box_append(GTK_BOX(r1), b_hnap);
    gtk_box_append(GTK_BOX(r1), b_snmp);
    gtk_box_append(GTK_BOX(r2), b_ssdp);
    gtk_box_append(GTK_BOX(r2), b_rebind);
    gtk_box_append(GTK_BOX(r2), b_csrf);

    gtk_box_append(GTK_BOX(card), ctitle);
    gtk_box_append(GTK_BOX(card), r1);
    gtk_box_append(GTK_BOX(card), r2);
    gtk_box_append(GTK_BOX(card), note);

    gtk_box_append(GTK_BOX(page), title);
    gtk_box_append(GTK_BOX(page), sub);
    gtk_box_append(GTK_BOX(page), card);
    gtk_box_append(GTK_BOX(page), scroll);
    return page;
}

static ModuleSubmenuEntry router_lan_entries[] = {
    { "LAN", "network-workgroup-symbolic", router_lan_build },
};

