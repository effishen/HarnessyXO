"""Theme tokens shared by the controller and its pre-login screens.

Keep this module independent of NiceGUI so authentication can render before the
application is available, using the same saved light/dark preference.
"""

PRIMARY_COLOR = '#10a37f'

THEME_CSS = r'''
:root {
  --hy-primary: #10a37f;
  --hy-border: rgba(127,127,127,.20);
  --hy-soft: rgba(127,127,127,.075);
  --hy-dialog-surface: #ffffff;
  --hy-dialog-border: rgba(127,127,127,.28);
  --hy-page-surface: #ffffff;
  --hy-text: #202226;
  --hy-muted-text: #63666b;
  --hy-error-text: #b42318;
  --hy-font: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, Helvetica, Arial, sans-serif;
  --hy-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
}
body.body--dark {
  --hy-dialog-surface: #202226;
  --hy-dialog-border: rgba(255,255,255,.12);
  --hy-page-surface: #121212;
  --hy-text: #f2f2f2;
  --hy-muted-text: #b7b8bb;
  --hy-error-text: #ffb4ab;
}
'''
