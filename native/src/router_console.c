
/* ==================================================================== */
/*  ROUTER CONSOLE (52_router_console)                                  */
/*                                                                      */
/*  Recovery-mode TFTP and offline flash parsing. The module had no page */
/*  at all - the define existed and nothing referenced it.              */
/*                                                                      */
/*  --tftp-push WRITES TO THE DEVICE. It refuses without                */
/*  --yes-write-to-device, and that gate is deliberately preserved here */
/*  as a checkbox rather than folded into the button: a flash write      */
/*  should take two deliberate acts, not one click next to a read.       */
/* ==================================================================== */

typedef struct {
    AppState    *state;
    GtkWidget   *view;
    GtkWidget   *cb_write;
    GSubprocess *proc;
} RouterConsolePage;

#define ROUTER_CONSOLE_ID "52_router_console"

static void
rcon_show(GtkWidget *view, const char *text)
{
    wf_output_set(view, text);
}

static void
rcon_finished(GObject *source, GAsyncResult *result, gpointer user_data)
{
    RouterConsolePage *p = user_data;
    g_autoptr(GError) error = NULL;
    g_autofree char *out = NULL;
    g_autofree char *err = NULL;
    gboolean ok = g_subprocess_communicate_utf8_finish(
        G_SUBPROCESS(source), result, &out, &err, &error);

    g_clear_object(&p->proc);
    if (ok && out != NULL && *out != '\0')   rcon_show(p->view, out);
    else                                     rcon_show(p->view,
        (err != NULL && *err != '\0') ? err : "(no output)");
}

static void
rcon_run(GtkButton *button, gpointer user_data)
{
    RouterConsolePage *p = user_data;
    g_autoptr(GError) error = NULL;
    const char *verb = g_object_get_data(G_OBJECT(button), "rc-verb");
    GtkWidget *e1 = g_object_get_data(G_OBJECT(button), "rc-e1");
    const char *args = e1 != NULL ? gtk_editable_get_text(GTK_EDITABLE(e1)) : "";
    const char *argv[10];
    g_auto(GStrv) parts = NULL;
    int n = 0;

    if (verb == NULL || p->proc != NULL) return;

    /* The guides take no argument at all; only the operation verbs do. */
    {
        gboolean needs_arg =
            g_strcmp0(verb, "--uart-guide") != 0 &&
            g_strcmp0(verb, "--spi-guide") != 0 &&
            g_strcmp0(verb, "--uboot-commands") != 0;
        if (needs_arg && (args == NULL || *args == '\0')) {
            show_toast_module(p->state, ROUTER_CONSOLE_ID,
                "Fill the arguments field first", "warn");
            return;
        }
    }

    argv[n++] = ROUTER_CONSOLE_SCRIPT;
    argv[n++] = verb;

    parts = g_strsplit_set(args, " \t", -1);
    for (int i = 0; parts[i] != NULL && n < 8; i++)
        if (*parts[i] != '\0') argv[n++] = parts[i];

    /* The write gate: only ever added when the operator ticked the box. */
    if (g_strcmp0(verb, "--tftp-push") == 0 &&
        p->cb_write != NULL &&
        gtk_check_button_get_active(GTK_CHECK_BUTTON(p->cb_write))) {
        argv[n++] = "--yes-write-to-device";
    }
    argv[n] = NULL;

    p->proc = g_subprocess_newv(argv,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE,
        &error);
    if (p->proc == NULL) {
        show_toast_module(p->state, ROUTER_CONSOLE_ID,
            error ? error->message : "could not start", "error");
        return;
    }
    rcon_show(p->view, "working…");
    g_subprocess_communicate_utf8_async(p->proc, NULL, NULL, rcon_finished, p);
}

static GtkWidget *
router_console_build(AppState *state, gpointer module_data)
{
    RouterConsolePage *p = g_new0(RouterConsolePage, 1);
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    GtkWidget *title = gtk_label_new("Router Console");
    GtkWidget *sub = gtk_label_new(
        "Recovery-mode TFTP and offline firmware analysis. Parsing works on "
        "an image you already have; the TFTP verbs talk to a router sitting "
        "in recovery mode.");
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *ctitle = gtk_label_new("OPERATIONS");
    GtkWidget *r1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *r2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *e_img = gtk_entry_new();
    GtkWidget *e_pull = gtk_entry_new();
    GtkWidget *e_push = gtk_entry_new();
    GtkWidget *b_parse = gtk_button_new_with_label("Parse flash image");
    GtkWidget *b_pull = gtk_button_new_with_label("TFTP pull");
    GtkWidget *b_push = gtk_button_new_with_label("TFTP push");
    GtkWidget *b_probe = gtk_button_new_with_label("TFTP probe");
    GtkWidget *b_uart = gtk_button_new_with_label("UART guide");
    GtkWidget *b_spi = gtk_button_new_with_label("SPI guide");
    GtkWidget *b_uboot = gtk_button_new_with_label("U-Boot commands");
    GtkWidget *cb_write = gtk_check_button_new_with_label(
        "allow writing to the device");
    GtkWidget *note = gtk_label_new(
        "Parse takes IMAGE. Pull takes HOST REMOTE OUT. Push takes HOST "
        "LOCAL REMOTE and refuses unless the write box is ticked — it "
        "overwrites a file on the router.");
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
    gtk_widget_set_hexpand(e_img, TRUE);
    gtk_widget_set_hexpand(e_pull, TRUE);
    gtk_widget_set_hexpand(e_push, TRUE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(e_img), "/path/to/firmware.bin");
    gtk_entry_set_placeholder_text(GTK_ENTRY(e_pull), "192.168.1.1 config.xml /tmp/out.xml");
    gtk_entry_set_placeholder_text(GTK_ENTRY(e_push), "192.168.1.1 /tmp/fw.bin firmware.bin");
    gtk_widget_set_size_request(scroll, -1, 220);

    p->state = state;
    p->cb_write = cb_write;
    p->view = gtk_scrolled_window_get_child(GTK_SCROLLED_WINDOW(scroll));

    {
        struct { GtkWidget *b; const char *verb; GtkWidget *e; } acts[] = {
            { b_parse, "--flash-parse", e_img  },
            { b_pull,  "--tftp-pull",   e_pull },
            { b_push,  "--tftp-push",   e_push },
            /* The probe and the three guides: reading a router's console
               without opening it, and the references for doing it by hand. */
            { b_probe, "--tftp-probe-tsv",   e_pull },
            { b_uart,  "--uart-guide",       NULL   },
            { b_spi,   "--spi-guide",        NULL   },
            { b_uboot, "--uboot-commands",   NULL   },
        };
        for (guint i = 0; i < G_N_ELEMENTS(acts); i++) {
            g_object_set_data(G_OBJECT(acts[i].b), "rc-verb",
                              (gpointer) acts[i].verb);
            g_object_set_data(G_OBJECT(acts[i].b), "rc-e1", acts[i].e);
            g_signal_connect(acts[i].b, "clicked", G_CALLBACK(rcon_run), p);
        }
    }

    gtk_box_append(GTK_BOX(r1), e_img);
    gtk_box_append(GTK_BOX(r1), b_parse);
    gtk_box_append(GTK_BOX(r2), e_pull);
    gtk_box_append(GTK_BOX(r2), b_pull);

    gtk_box_append(GTK_BOX(card), ctitle);
    gtk_box_append(GTK_BOX(card), r1);
    gtk_box_append(GTK_BOX(card), r2);
    gtk_box_append(GTK_BOX(card), e_push);
    gtk_box_append(GTK_BOX(card), b_push);
    {
        GtkWidget *r3 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        gtk_box_append(GTK_BOX(r3), b_probe);
        gtk_box_append(GTK_BOX(r3), b_uart);
        gtk_box_append(GTK_BOX(r3), b_spi);
        gtk_box_append(GTK_BOX(r3), b_uboot);
        gtk_box_append(GTK_BOX(card), r3);
    }
    gtk_box_append(GTK_BOX(card), cb_write);
    gtk_box_append(GTK_BOX(card), note);

    gtk_box_append(GTK_BOX(page), title);
    gtk_box_append(GTK_BOX(page), sub);
    gtk_box_append(GTK_BOX(page), card);
    gtk_box_append(GTK_BOX(page), scroll);
    return page;
}

static ModuleSubmenuEntry router_console_entries[] = {
    { "Console", "utilities-terminal-symbolic", router_console_build },
};

