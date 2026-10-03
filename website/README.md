# Project page for frickl.de/aissa

Static HTML/CSS, no build step, JavaScript, external fonts or analytics.
The two public files are `index.html` and `style.css`. Both must be installed
in the same `/aissa/` directory of the existing frickl.de virtual host.

Use the actual virtual-host document root, not an assumed mail-server path.
Do not replace the host's nginx/Apache configuration. Existing host-wide legal
and privacy navigation can be added to the footer as appropriate.

After a Git pull on the host, for an already identified document root:

```bash
# Replace this value with the configured frickl.de document root.
aissa_web_root='/actual/frickl.de/document-root'
install -d -m 0755 "$aissa_web_root/aissa"
install -m 0644 website/index.html website/style.css "$aissa_web_root/aissa/"
```

Verify `https://frickl.de/aissa/` and the stylesheet before announcing the URL.
Check HTTPS, `/aissa` to `/aissa/` handling, desktop/mobile rendering and GitHub
links. No web-server reload is normally needed when copying static files into
an existing document root. Preserve the virtual host's normal ownership policy.

The README/source links point to main. Publish the documentation changes there
before publishing the page so those links resolve. Public performance figures
are selected observations, not an accuracy benchmark. Keep them in sync with
`docs/field-notes.md` if the page changes.
