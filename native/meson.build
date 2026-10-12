project(
  'wifisting-native',
  'c',
  version: '0.1.0',
  default_options: [
    'c_std=c17',
    'warning_level=3',
    'werror=false',
  ],
)

# ------------------------------------------------------------------ #
#  Generate config.h with the absolute project root baked in.       #
#  Lets the toolkit be built and run from any directory without     #
#  editing main1.c — the friend's build tree becomes their root.    #
# ------------------------------------------------------------------ #

_wifisting_root = run_command(
  'dirname', meson.current_source_dir(),
  check: true,
).stdout().strip()

conf = configuration_data()
conf.set('WIFISTING_ROOT', _wifisting_root)

configure_file(
  input: 'src/config.h.in',
  output: 'config.h',
  configuration: conf,
)

gnome = import('gnome')

gtk_dep = dependency('gtk4', version: '>=4.10')
vte_dep = dependency('vte-2.91-gtk4')

wifisting_resources = gnome.compile_resources(
  'wifisting-resources',
  'resources/wifisting.gresource.xml',
  source_dir: 'resources',
  c_name: 'wifisting',
)

executable(
  'wifisting-gui',
  [
    'src/main1.c',
    wifisting_resources,
  ],
  dependencies: [
    gtk_dep,
    vte_dep,
  ],
  install: true,
)
