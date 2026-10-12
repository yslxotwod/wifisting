
/* ==================================================================== */
/*  CLIENT ISOLATION (54_client_isolation)                              */
/*                                                                      */
/*  Tests whether client isolation can actually be bypassed. Needs TWO   */
/*  associated interfaces - one simulating the victim, one the attacker. */
/*                                                                      */
/*  The GTK test is delegated, not reimplemented: reading the group key  */
/*  needs a patched wpa_supplicant, and the page says so rather than     */
/*  showing a pass it cannot substantiate.                               */
/* ==================================================================== */

#define CLIENT_ISOLATION_SCRIPT wf_path("modules/54_client_isolation.sh")

typedef struct {
    AppState    *state;
    GtkWidget   *conf;
    GtkWidget   *victim;
    GtkWidget   *attacker;
    GtkWidget   *view;
    GSubprocess *proc;
} ClientIsolationPage;

static void
ci_finished(GObject *source, GAsyncResult *result, gpointer user_data)
{
    ClientIsolationPage *p = user_data;
    g_autoptr(GError) error = NULL;
    g_autofree char *out = NULL;
    g_autofree char *err = NULL;
    gboolean ok = g_subprocess_communicate_utf8_finish(
        G_SUBPROCESS(source), result, &out, &err, &error);

    g_clear_object(&p->proc);
    if (out != NULL && *out != '\0')     wf_output_set(p->view, out);
    else if (!ok && err != NULL && *err) wf_output_set(p->view, err);
    else                                 wf_output_set(p->view, "(no output)");
}

static void
ci_run(GtkButton *button, gpointer user_data)
{
    ClientIsolationPage *p = user_data;
    g_autoptr(GError) error = NULL;
    const char *verb = g_object_get_data(G_OBJECT(button), "ci-verb");
    const char *argv[8];
    int n = 0;
    gboolean needs_targets;

    if (verb == NULL || p->proc != NULL) return;

    needs_targets = (g_strcmp0(verb, "--gtk-shared") == 0 ||
                     g_strcmp0(verb, "--relay") == 0 ||
                     g_strcmp0(verb, "--c2c-ip") == 0 ||
                     g_strcmp0(verb, "--c2c-broadcast") == 0 ||
                     g_strcmp0(verb, "--port-steal") == 0);

    if (needs_targets) {
        const char *conf = gtk_editable_get_text(GTK_EDITABLE(p->conf));
        const char *v = gtk_editable_get_text(GTK_EDITABLE(p->victim));
        const char *a = gtk_editable_get_text(GTK_EDITABLE(p->attacker));

        if (conf == NULL || *conf == '\0' ||
            v == NULL || *v == '\0' || a == NULL || *a == '\0') {
            show_toast_module(p->state, "54_client_isolation",
                "Config, victim interface and attacker interface are all required",
                "warn");
            return;
        }
        argv[n++] = "pkexec";
        argv[n++] = CLIENT_ISOLATION_SCRIPT;
        argv[n++] = verb;
        argv[n++] = conf;
        argv[n++] = v;
        argv[n++] = a;
        argv[n] = NULL;
    } else if (g_strcmp0(verb, "--check-config") == 0) {
        const char *conf = gtk_editable_get_text(GTK_EDITABLE(p->conf));
        if (conf == NULL || *conf == '\0') {
            show_toast_module(p->state, "54_client_isolation",
                "Type the config path first", "warn");
            return;
        }
        argv[n++] = CLIENT_ISOLATION_SCRIPT;
        argv[n++] = verb;
        argv[n++] = conf;
        argv[n] = NULL;
    } else {
        argv[n++] = CLIENT_ISOLATION_SCRIPT;
        argv[n++] = verb;
        argv[n] = NULL;
    }

    p->proc = g_subprocess_newv(argv,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE,
        &error);
    if (p->proc == NULL) {
        show_toast_module(p->state, "54_client_isolation",
            error ? error->message : "could not start", "error");
        return;
    }
    wf_output_set(p->view, "working…");
    g_subprocess_communicate_utf8_async(p->proc, NULL, NULL, ci_finished, p);
}

static GtkWidget *
client_isolation_build(AppState *state, gpointer module_data)
{
    ClientIsolationPage *p = g_new0(ClientIsolationPage, 1);
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *title = gtk_label_new("Client Isolation");
    GtkWidget *sub = gtk_label_new(
        "Whether isolation between clients can be bypassed. Client isolation "
        "is not a standardised Wi-Fi feature, so its guarantees vary by "
        "vendor. Needs two associated interfaces — one simulating the victim, "
        "one the attacker. Authorised testing only.");
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *ctitle = gtk_label_new("TEST");
    GtkWidget *r1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *r2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *r3 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *l_conf = gtk_label_new("Config:");
    GtkWidget *conf = gtk_entry_new();
    GtkWidget *l_v = gtk_label_new("Victim:");
    GtkWidget *victim = gtk_entry_new();
    GtkWidget *l_a = gtk_label_new("Attacker:");
    GtkWidget *attacker = gtk_entry_new();
    GtkWidget *b_chk = gtk_button_new_with_label("Check config");
    GtkWidget *b_if = gtk_button_new_with_label("Interfaces");
    GtkWidget *b_gtk = gtk_button_new_with_label("GTK shared?");
    GtkWidget *b_bounce = gtk_button_new_with_label("Gateway bounce");
    GtkWidget *b_bcast = gtk_button_new_with_label("Broadcast reflect");
    GtkWidget *b_steal = gtk_button_new_with_label("Port stealing");
    GtkWidget *b_relay = gtk_button_new_with_label("Relay");
    GtkWidget *b_rstat = gtk_button_new_with_label("Relay status");
    GtkWidget *b_stop = gtk_button_new_with_label("Stop");
    GtkWidget *note = gtk_label_new(
        "Gateway bounce, broadcast reflection and port stealing are tested "
        "directly. The GTK test is delegated to the AirSnitch tree when it is "
        "present — reading the group key needs a patched wpa_supplicant, so "
        "this page reports it as unavailable rather than guessing. Relay "
        "maintains a bypass once the tests show one exists: frames arriving "
        "on one interface are put back out the other, so the victim keeps "
        "talking while the traffic passes through this host.");
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
    gtk_widget_set_hexpand(conf, TRUE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(conf), "/path/to/client.conf");
    gtk_entry_set_placeholder_text(GTK_ENTRY(victim), "wlan0");
    gtk_entry_set_placeholder_text(GTK_ENTRY(attacker), "wlan1");
    gtk_widget_set_size_request(scroll, -1, 240);

    p->state = state;
    p->conf = conf;
    p->victim = victim;
    p->attacker = attacker;
    p->view = gtk_scrolled_window_get_child(GTK_SCROLLED_WINDOW(scroll));

    {
        struct { GtkWidget *b; const char *verb; } acts[] = {
            { b_chk,    "--check-config"  },
            { b_if,     "--ifaces-tsv"    },
            { b_gtk,    "--gtk-shared"    },
            { b_bounce, "--c2c-ip"        },
            { b_bcast,  "--c2c-broadcast" },
            { b_steal,  "--port-steal"    },
            { b_relay,  "--relay"         },
            { b_rstat,  "--relay-status-tsv" },
            { b_stop,   "--stop"          },
        };
        for (guint i = 0; i < G_N_ELEMENTS(acts); i++) {
            g_object_set_data(G_OBJECT(acts[i].b), "ci-verb",
                              (gpointer) acts[i].verb);
            g_signal_connect(acts[i].b, "clicked", G_CALLBACK(ci_run), p);
        }
    }

    gtk_box_append(GTK_BOX(r1), l_conf);
    gtk_box_append(GTK_BOX(r1), conf);
    gtk_box_append(GTK_BOX(r1), b_chk);
    gtk_box_append(GTK_BOX(r2), l_v);
    gtk_box_append(GTK_BOX(r2), victim);
    gtk_box_append(GTK_BOX(r2), l_a);
    gtk_box_append(GTK_BOX(r2), attacker);
    gtk_box_append(GTK_BOX(r2), b_if);
    gtk_box_append(GTK_BOX(r3), b_gtk);
    gtk_box_append(GTK_BOX(r3), b_bounce);
    gtk_box_append(GTK_BOX(r3), b_bcast);
    gtk_box_append(GTK_BOX(r3), b_steal);
    gtk_box_append(GTK_BOX(r3), b_relay);
    gtk_box_append(GTK_BOX(r3), b_rstat);
    gtk_box_append(GTK_BOX(r3), b_stop);

    gtk_box_append(GTK_BOX(card), ctitle);
    gtk_box_append(GTK_BOX(card), r1);
    gtk_box_append(GTK_BOX(card), r2);
    gtk_box_append(GTK_BOX(card), r3);
    gtk_box_append(GTK_BOX(card), note);

    gtk_box_append(GTK_BOX(page), title);
    gtk_box_append(GTK_BOX(page), sub);
    gtk_box_append(GTK_BOX(page), card);
    gtk_box_append(GTK_BOX(page), scroll);
    return page;
}

static ModuleSubmenuEntry client_isolation_entries[] = {
    { "Isolation", "network-wired-symbolic", client_isolation_build },
};
