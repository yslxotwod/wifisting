
/* ==================================================================== */
/*  REUSABLE VERB PANEL                                                 */
/*                                                                      */
/*  A card of buttons wired to one module's verbs, plus a list showing   */
/*  what they return. Several modules had verbs with no control at all,  */
/*  and the readers among them need somewhere to put their rows - a      */
/*  toast would close the audit gap while showing nothing.               */
/*                                                                      */
/*  Not a generic "run any verb" escape hatch: each panel names the      */
/*  verbs it offers and where each one's argument comes from.            */
/* ==================================================================== */

/* fp_text_view() is defined with the fingerprint pages much later in the
   file; the panel reuses it rather than duplicating a scroller + text view. */
static GtkWidget *fp_text_view(void);

typedef struct {
    AppState    *state;
    const char  *module_id;
    const char  *script;
    GtkWidget   *view;
    GtkWidget   *entry_a;
    GtkWidget   *entry_b;
    GSubprocess *proc;
} VerbPanel;

/* arg: 0 = no argument, 1 = entry A, 2 = entry B, 3 = entry B split on
   spaces (several positional arguments). */
typedef struct {
    const char *label;
    const char *verb;
    int         arg;
    gboolean    privileged;
} VerbPanelItem;

/* Colour by severity, so a single ERROR inside a screenful of NOTE lines is
   visible without reading any of it. The toolkit's verbs already prefix
   their output consistently (ERROR, WARN, OK, NOTE, ...), so the prefix is
   the signal and nothing has to be parsed. */
static const char *
verb_panel_tag_for(const char *line)
{
    while (*line == ' ' || *line == '\t') line++;
    if (*line == '[') line++;                 /* [err] / [ok] / [info] */

    if (g_ascii_strncasecmp(line, "error", 5) == 0 ||
        g_ascii_strncasecmp(line, "err",   3) == 0 ||
        g_ascii_strncasecmp(line, "fail",  4) == 0 ||
        g_ascii_strncasecmp(line, "missing", 7) == 0)
        return "vp-error";

    if (g_ascii_strncasecmp(line, "warn", 4) == 0)
        return "vp-warn";

    if (g_ascii_strncasecmp(line, "ok",   2) == 0 ||
        g_ascii_strncasecmp(line, "pass", 4) == 0)
        return "vp-ok";

    if (g_ascii_strncasecmp(line, "note", 4) == 0 ||
        g_ascii_strncasecmp(line, "info", 4) == 0 ||
        g_ascii_strncasecmp(line, "hint", 4) == 0 ||
        g_ascii_strncasecmp(line, "plan", 4) == 0)
        return "vp-dim";

    return NULL;
}

/* Shared by every page that shows verb output. Defined here because this
   file is included before the rest; the pages below it call it directly. */
static void
wf_output_set(GtkWidget *view, const char *text)
{
    GtkTextBuffer *buf;
    static gboolean tags_ready = FALSE;

    if (view == NULL || text == NULL) return;
    buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));

    if (!tags_ready) {
        /* Chosen to stay legible on both the Matrix and Ghost backgrounds,
           rather than picking up the theme accent - an error must read as an
           error in either. */
        gtk_text_buffer_create_tag(buf, "vp-error",
            "foreground", "#ff6b6b", NULL);
        gtk_text_buffer_create_tag(buf, "vp-warn",
            "foreground", "#ffb454", NULL);
        gtk_text_buffer_create_tag(buf, "vp-ok",
            "foreground", "#4ade80", NULL);
        gtk_text_buffer_create_tag(buf, "vp-dim",
            "foreground", "#8b93a1", NULL);
        tags_ready = TRUE;
    }

    gtk_text_buffer_set_text(buf, "", -1);
    {
        g_auto(GStrv) lines = g_strsplit(text, "\n", -1);
        for (guint i = 0; lines[i] != NULL; i++) {
            GtkTextIter end;
            const char *tag = verb_panel_tag_for(lines[i]);

            gtk_text_buffer_get_end_iter(buf, &end);
            if (tag != NULL)
                gtk_text_buffer_insert_with_tags_by_name(
                    buf, &end, lines[i], -1, tag, NULL);
            else
                gtk_text_buffer_insert(buf, &end, lines[i], -1);
            gtk_text_buffer_get_end_iter(buf, &end);
            gtk_text_buffer_insert(buf, &end, "\n", -1);
        }
    }
}

static void
verb_panel_show(VerbPanel *p, const char *text)
{
    wf_output_set(p->view, text);
}

static void
verb_panel_finished(GObject *source, GAsyncResult *result, gpointer user_data)
{
    VerbPanel *p = user_data;
    g_autoptr(GError) error = NULL;
    g_autofree char *out = NULL;
    g_autofree char *err = NULL;
    gboolean ok = g_subprocess_communicate_utf8_finish(
        G_SUBPROCESS(source), result, &out, &err, &error);

    g_clear_object(&p->proc);
    if (ok && out != NULL && *out != '\0')   verb_panel_show(p, out);
    else                                     verb_panel_show(p,
        (err != NULL && *err != '\0') ? err : "(no output)");
}

static void
verb_panel_run(GtkButton *button, gpointer user_data)
{
    VerbPanel *p = user_data;
    g_autoptr(GError) error = NULL;
    const char *verb = g_object_get_data(G_OBJECT(button), "vp-verb");
    int arg = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(button), "vp-arg"));
    gboolean priv = GPOINTER_TO_INT(
        g_object_get_data(G_OBJECT(button), "vp-priv"));
    const char *argv[10];
    const char *text = NULL;
    g_auto(GStrv) parts = NULL;
    int n = 0;

    if (verb == NULL || p->proc != NULL) return;

    if (arg == 1 && p->entry_a != NULL)
        text = gtk_editable_get_text(GTK_EDITABLE(p->entry_a));
    else if (arg >= 2 && p->entry_b != NULL)
        text = gtk_editable_get_text(GTK_EDITABLE(p->entry_b));

    /* arg 4 is an optional argument: pass it when filled, omit it when not,
       so --tail-log [LINES] and --assoc-attack [IFACE] work with an empty
       field instead of refusing. */
    if (arg != 0 && arg != 4 && (text == NULL || *text == '\0')) {
        show_toast_module(p->state, p->module_id,
            "Fill the field this action needs first", "warn");
        return;
    }

    if (priv) argv[n++] = "pkexec";
    argv[n++] = p->script;
    argv[n++] = verb;

    if (arg == 3) {
        parts = g_strsplit_set(text, " \t", -1);
        for (int i = 0; parts[i] != NULL && n < 9; i++)
            if (*parts[i] != '\0') argv[n++] = parts[i];
    } else if (arg == 4) {
        if (text != NULL && *text != '\0') argv[n++] = text;
    } else if (arg != 0) {
        argv[n++] = text;
    }
    argv[n] = NULL;

    p->proc = g_subprocess_newv(argv,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE,
        &error);
    if (p->proc == NULL) {
        show_toast_module(p->state, p->module_id,
            error ? error->message : "could not start", "error");
        return;
    }
    verb_panel_show(p, "working…");
    g_subprocess_communicate_utf8_async(p->proc, NULL, NULL,
        verb_panel_finished, p);
}

/* Build the card. entry_a and entry_b may be NULL if no item uses them. */
static GtkWidget *
verb_panel_new(AppState *state, const char *module_id, const char *script,
               const char *title, const char *note,
               const VerbPanelItem *items, guint n_items,
               const char *ph_a, const char *ph_b, int height)
{
    VerbPanel *p = g_new0(VerbPanel, 1);
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *lbl = gtk_label_new(title);
    GtkWidget *row_a = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *row_b = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *scroll = fp_text_view();

    p->state = state;
    p->module_id = module_id;
    p->script = script;
    p->view = gtk_scrolled_window_get_child(GTK_SCROLLED_WINDOW(scroll));
    p->entry_a = ph_a != NULL ? gtk_entry_new() : NULL;
    p->entry_b = ph_b != NULL ? gtk_entry_new() : NULL;

    gtk_widget_add_css_class(card, "section-card");
    gtk_widget_add_css_class(lbl, "section-title");
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0f);
    gtk_box_append(GTK_BOX(card), lbl);

    if (p->entry_a != NULL) {
        gtk_widget_set_hexpand(p->entry_a, TRUE);
        gtk_entry_set_placeholder_text(GTK_ENTRY(p->entry_a), ph_a);
        gtk_box_append(GTK_BOX(row_a), p->entry_a);
    }
    if (p->entry_b != NULL) {
        gtk_widget_set_hexpand(p->entry_b, TRUE);
        gtk_entry_set_placeholder_text(GTK_ENTRY(p->entry_b), ph_b);
        gtk_box_append(GTK_BOX(row_b), p->entry_b);
    }

    for (guint i = 0; i < n_items; i++) {
        GtkWidget *b = gtk_button_new_with_label(items[i].label);
        GtkWidget *row = (items[i].arg >= 2) ? row_b : row_a;
        g_object_set_data(G_OBJECT(b), "vp-verb", (gpointer) items[i].verb);
        g_object_set_data(G_OBJECT(b), "vp-arg",
                          GINT_TO_POINTER(items[i].arg));
        g_object_set_data(G_OBJECT(b), "vp-priv",
                          GINT_TO_POINTER(items[i].privileged));
        g_signal_connect(b, "clicked", G_CALLBACK(verb_panel_run), p);
        gtk_box_append(GTK_BOX(row), b);
    }

    if (p->entry_a != NULL) gtk_box_append(GTK_BOX(card), row_a);
    if (p->entry_b != NULL) gtk_box_append(GTK_BOX(card), row_b);

    if (note != NULL) {
        GtkWidget *nl = gtk_label_new(note);
        gtk_widget_add_css_class(nl, "dependency-summary");
        gtk_label_set_xalign(GTK_LABEL(nl), 0.0f);
        gtk_label_set_wrap(GTK_LABEL(nl), TRUE);
        gtk_box_append(GTK_BOX(card), nl);
    }

    gtk_widget_set_size_request(scroll, -1, height);
    gtk_box_append(GTK_BOX(card), scroll);
    return card;
}
