# Cybersecurity Filament plugin — directory art

Palette: **rojo + negro** (security / threat posture).

| Token | Hex |
| --- | --- |
| Red | `#E11D48` |
| Red bright | `#FB7185` |
| Black | `#050505` |
| Panel | `#111111` |

## Files

| File | Size | Filament field |
| --- | --- | --- |
| `banner.jpg` | 2560×1440 | Image (required) |
| `thumbnail.jpg` | 1920×1080 | Thumbnail (optional) |

Regenerate JPGs (Chrome headless):

```bash
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --headless=new --window-size=2560,1440 --hide-scrollbars \
  --screenshot=art/banner.jpg "file://$PWD/art/banner.html"

"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --headless=new --window-size=1920,1080 --hide-scrollbars \
  --screenshot=art/thumbnail.jpg "file://$PWD/art/thumbnail.html"
```
