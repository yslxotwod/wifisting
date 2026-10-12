
/* ==================================================================== */
/*  ROUTER WEB UI (51_router_web)                                       */
/*                                                                      */
/*  Three of these verbs only ever READ a router's web interface:       */
/*  discover what is there, see whether the admin pages are reachable   */
/*  without credentials, and fetch the rom-0 config blob. The other two */
/*  are the interesting pair: a default-credential lookup for a vendor, */
/*  and a read-only injection probe that says whether a parameter was   */
/*  EXECUTED or merely REFLECTED back.                                  */
/* ==================================================================== */

typedef struct {
    AppState    *state;
    GtkWidget   *view;
    GSubprocess *proc;
} RouterWebPage;

#define ROUTER_WEB_ID "51_router_web"

static void
rw_show(GtkWidget *view, const char *text)
{
    wf_output_set(view, text);
}

static void
rw_finished(GObject *source, GAsyncResult *result, gpointer user_data)
{
    RouterWebPage *p = user_data;
    g_autoptr(GError) error = NULL;
    g_autofree char *out = NULL;
    g_autofree char *err = NULL;
    gboolean ok = g_subprocess_communicate_utf8_finish(
        G_SUBPROCESS(source), result, &out, &err, &error);

    g_clear_object(&p->proc);
    if (ok && out != NULL && *out != '\0')   rw_show(p->view, out);
    else                                     rw_show(p->view,
        (err != NULL && *err != '\0') ? err : "(no output)");
}

/* One runner. Each button carries its verb and says which of the two
   entries supplies its argument. */
static void
rw_run(GtkButton *button, gpointer user_data)
{
    RouterWebPage *p = user_data;
    g_autoptr(GError) error = NULL;
    const char *verb = g_object_get_data(G_OBJECT(button), "rw-verb");
    GtkWidget *host_e = g_object_get_data(G_OBJECT(button), "rw-host");
    GtkWidget *arg_e = g_object_get_data(G_OBJECT(button), "rw-arg");
    const char *host = host_e != NULL
        ? gtk_editable_get_text(GTK_EDITABLE(host_e)) : "";
    const char *arg = arg_e != NULL
        ? gtk_editable_get_text(GTK_EDITABLE(arg_e)) : "";
    const char *argv[8];
    g_auto(GStrv) parts = NULL;
    int n = 0;

    if (verb == NULL || p->proc != NULL) return;

    /* --creds-tsv is the one verb that does not talk to a host: it answers
       from the vendor table, so a host is not required for it. */
    if (g_strcmp0(verb, "--creds-tsv") != 0) {
        if (*host == '\0') {
            show_toast_module(p->state, ROUTER_WEB_ID,
                "Enter a host first", "warn");
            return;
        }
    } else if (*arg == '\0') {
        show_toast_module(p->state, ROUTER_WEB_ID,
            "Enter a vendor first", "warn");
        return;
    }

    argv[n++] = ROUTER_WEB_SCRIPT;
    argv[n++] = verb;

    if (g_strcmp0(verb, "--creds-tsv") == 0) {
        /* VENDOR [SSID] [MAC] [SERIAL] - extras come from the host field so
           one entry serves both purposes without a third box. */
        parts = g_strsplit_set(arg, " ", -1);
        for (int i = 0; parts[i] != NULL && n < 6; i++)
            if (*parts[i] != '\0') argv[n++] = parts[i];
        if (*host != '\0') {
            g_auto(GStrv) more = g_strsplit_set(host, " ", -1);
            for (int i = 0; more[i] != NULL && n < 7; i++)
                if (*more[i] != '\0') argv[n++] = more[i];
        }
    } else if (g_strcmp0(verb, "--cgi-test-tsv") == 0) {
        argv[n++] = host;                      /* HOST */
        argv[n++] = (*arg != '\0') ? arg : "/";/* PATH */
    } else {
        argv[n++] = host;
        if (g_strcmp0(verb, "--discover-tsv") == 0 && *arg != '\0')
            argv[n++] = arg;                   /* PORT */
        if (g_strcmp0(verb, "--rom0") == 0 && *arg != '\0')
            argv[n++] = arg;                   /* OUT */
    }
    argv[n] = NULL;

    p->proc = g_subprocess_newv(argv,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE,
        &error);
    if (p->proc == NULL) {
        show_toast_module(p->state, ROUTER_WEB_ID,
            error ? error->message : "could not start", "error");
        return;
    }
    rw_show(p->view, "working…");
    g_subprocess_communicate_utf8_async(p->proc, NULL, NULL, rw_finished, p);
}

static GtkWidget *
router_web_build(AppState *state, gpointer module_data)
{
    RouterWebPage *p = g_new0(RouterWebPage, 1);
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    GtkWidget *title = gtk_label_new("Router Web UI");
    GtkWidget *sub = gtk_label_new(
        "Read-only probing of a router's web interface. Discovery and the "
        "auth check only read. The CGI probe is deliberately read-only: it "
        "reports whether a parameter was EXECUTED or merely REFLECTED back, "
        "which is the difference between a finding and a false positive.");
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *ctitle = gtk_label_new("TARGET");
    GtkWidget *r1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *r2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *host = gtk_entry_new();
    GtkWidget *arg = gtk_entry_new();
    GtkWidget *b_disc = gtk_button_new_with_label("Discover");
    GtkWidget *b_auth = gtk_button_new_with_label("Auth check");
    GtkWidget *b_rom0 = gtk_button_new_with_label("Fetch rom-0");
    GtkWidget *b_cgi = gtk_button_new_with_label("CGI probe");
    GtkWidget *b_creds = gtk_button_new_with_label("Default creds");
    GtkWidget *note = gtk_label_new(
        "Host is the router address. The second field is the port for "
        "Discover, the output path for rom-0, the CGI path for the probe, "
        "and the vendor for Default creds (extra SSID/MAC/serial can follow "
        "in the host field).");
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
    gtk_widget_set_hexpand(arg, TRUE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(host), "192.168.1.1");
    gtk_entry_set_placeholder_text(GTK_ENTRY(arg),
        "port / output path / CGI path / vendor");
    gtk_widget_set_size_request(scroll, -1, 240);

    p->state = state;
    p->view = gtk_scrolled_window_get_child(GTK_SCROLLED_WINDOW(scroll));

    {
        struct { GtkWidget *b; const char *verb; } acts[] = {
            { b_disc,  "--discover-tsv"  },
            { b_auth,  "--auth-tsv"      },
            { b_rom0,  "--rom0"          },
            { b_cgi,   "--cgi-test-tsv"  },
            { b_creds, "--creds-tsv"     },
        };
        for (guint i = 0; i < G_N_ELEMENTS(acts); i++) {
            g_object_set_data(G_OBJECT(acts[i].b), "rw-verb",
                              (gpointer) acts[i].verb);
            g_object_set_data(G_OBJECT(acts[i].b), "rw-host", host);
            g_object_set_data(G_OBJECT(acts[i].b), "rw-arg", arg);
            g_signal_connect(acts[i].b, "clicked", G_CALLBACK(rw_run), p);
        }
    }

    gtk_box_append(GTK_BOX(r1), host);
    gtk_box_append(GTK_BOX(r1), b_disc);
    gtk_box_append(GTK_BOX(r1), b_auth);
    gtk_box_append(GTK_BOX(r1), b_rom0);
    gtk_box_append(GTK_BOX(r2), arg);
    gtk_box_append(GTK_BOX(r2), b_cgi);
    gtk_box_append(GTK_BOX(r2), b_creds);

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

static ModuleSubmenuEntry router_web_entries[] = {
    { "Web UI", "security-high-symbolic", router_web_build },
};

