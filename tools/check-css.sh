#!/usr/bin/env bash
# check-css.sh — parse resources/style.css with GTK's own CSS parser.
#
# GTK reports CSS problems at runtime through its log handler, which the GUI
# mirrors into wifisting.log. That means a typo in style.css shows up as log
# noise on every launch instead of as a build failure. This runs the same
# parser GTK uses (gtk_css_provider_load_from_path) ahead of time, so the
# mistake is caught here rather than in the log.
#
# It also checks brace balance first: an unbalanced file makes GTK drop the
# rest of the sheet, which looks like "the theme silently reverted".
#
# Usage:
#   tools/check-css.sh            # check the GUI stylesheet
#   tools/check-css.sh FILE.css   # check something else
#
# Exit: 0 clean, 1 problems found, 2 could not build the checker.

set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CSS="${1:-$ROOT/native/resources/style.css}"

[[ -f "$CSS" ]] || { echo "no such file: $CSS" >&2; exit 2; }

# --- brace balance ---------------------------------------------------------
# Counted with awk rather than a regex so the check cannot be fooled by the
# same brace-in-a-comment trap that corrupted this file once already.
balance=$(awk '
    { for (i = 1; i <= length($0); i++) {
          c = substr($0, i, 1)
          if (c == "{") n++
          else if (c == "}") n--
      } }
    END { print n }
' "$CSS")

if [[ "$balance" != "0" ]]; then
    echo "FAIL: $CSS brace depth is $balance, expected 0" >&2
    exit 1
fi

# --- GTK parser ------------------------------------------------------------
if ! pkg-config --exists gtk4; then
    echo "SKIP: gtk4 development files not found (brace balance is OK)" >&2
    exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/lint.c" <<'EOF'
#include <gtk/gtk.h>

static int n_err = 0, n_warn = 0;

static void
on_error(GtkCssProvider *p, GtkCssSection *sec, const GError *err, gpointer u)
{
    GFile *f = gtk_css_section_get_file(sec);
    const GtkCssLocation *loc = gtk_css_section_get_start_location(sec);
    const char *m = err->message;
    /* GTK funnels unknown-property complaints and hard parse errors through
       the same signal; only the message distinguishes them. */
    gboolean unknown = strstr(m, "Unknown property") != NULL ||
                       strstr(m, "not supported") != NULL ||
                       strstr(m, "deprecated") != NULL;
    if (unknown) n_warn++; else n_err++;
    g_printerr("%s:%lu: %s: %s\n",
        f != NULL ? g_file_get_basename(f) : "?",
        loc != NULL ? (unsigned long) loc->lines : 0UL,
        unknown ? "warning" : "error", m);
    (void) p; (void) u;
}

int main(int argc, char **argv)
{
    GtkCssProvider *p;

    if (argc < 2) { g_printerr("usage: css-lint FILE.css\n"); return 2; }

    p = gtk_css_provider_new();
    g_signal_connect(p, "parsing-error", G_CALLBACK(on_error), NULL);
    gtk_css_provider_load_from_path(p, argv[1]);
    g_object_unref(p);

    if (n_err == 0 && n_warn == 0) return 0;
    g_printerr("--- %d error(s), %d warning(s)\n", n_err, n_warn);
    return 1;
}
EOF

if ! gcc -O0 -o "$WORK/css-lint" "$WORK/lint.c" \
        $(pkg-config --cflags --libs gtk4) 2>"$WORK/cc.log"; then
    echo "SKIP: could not build the GTK checker" >&2
    sed -n '1,5p' "$WORK/cc.log" >&2
    exit 2
fi

# No display needed: GtkCssProvider is not a widget.
if "$WORK/css-lint" "$CSS"; then
    echo "OK: $CSS parses cleanly, braces balanced"
else
    echo "FAIL: $CSS has parsing problems (listed above)" >&2
    exit 1
fi
