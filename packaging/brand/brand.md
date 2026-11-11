# SecuritySuite: logo kit

Mark: orange rounded tile with a white stepped lightning bolt, as supplied. The bolt and tile were traced from a ~85 px screenshot of the icon and rebuilt as clean vector geometry (see Limits).

## Palette

| Name | HEX | RGB | Role |
|---|---|---|---|
| Orange | `#E06639` | 224, 102, 57 | Primary, the tile and "Suite". Sampled from your image |
| White | `#FFFFFF` | 255, 255, 255 | Bolt and reverse text |
| Ink | `#23252B` | 35, 37, 43 | Wordmark "Security" on light backgrounds. Added for this kit |
| Panel | `#17181C` | 23, 24, 28 | Dark background for the reverse lockups. Added for this kit |
| Black | `#000000` | 0, 0, 0 | Mono one-colour use |

Contrast (WCAG 2.x relative luminance, computed):

| Pair | Ratio | Use |
|---|---|---|
| Ink on White | 15.32:1 | Any text |
| White on Panel | 17.74:1 | Any text |
| Orange on Panel | 5.18:1 | Text and graphics |
| White on Orange | 3.43:1 | Large graphics and large text only (the bolt qualifies) |
| Orange on White | 3.43:1 | Large text and graphics only. Never body or small text |

## Typeface

Wordmark: Inter Bold, tracking -2 at 170 px (about -1.2%), "Security" in Ink (White on dark), "Suite" in Orange. Inter is a free download from rsms.me/inter. SVG lockups use live text, so install Inter to render them correctly. PNG lockups already have Inter baked in.

## Files

| Path | Use |
|---|---|
| `svg/mark-tile.svg` | The logo: orange tile with white bolt |
| `svg/mark-tile-black.svg`, `svg/mark-tile-white.svg` | One-colour tile with the bolt knocked out, so it works on any background |
| `svg/bolt-{orange,white,black}.svg` | Bolt alone, for use inside your own container or on a plain background |
| `svg/lockup-horizontal-*.svg`, `svg/lockup-stacked-*.svg` | Tile plus wordmark: `color`, `reverse` (baked dark Panel background), `black`, `white` |
| `svg/app-icon.svg`, `svg/favicon.svg` | App icon and favicon source |
| `png/app-icon/app-icon-{1024,512,256,180,128,64,32,16}.png` | App and store icons, each rendered from vector at its size. 16 to 32 px use a bolt enlarged 20% |
| `png/app-icon/maskable-512.png` | Android maskable. Full bleed, bolt sits inside the 80% safe zone |
| `png/app-icon/apple-touch-icon.png` | 180 px, square full-bleed. iOS applies its own corner mask |
| `favicon.ico` | 16, 32 and 48 px |
| `png/mark/`, `png/lockup/` | Transparent PNG exports (marks 1024, 512 and 256; bolts 1024; lockups 2800 and 1600 wide) |
| `png/social-avatar-800.png` | Profile picture, square full-bleed. Platforms crop it to a circle, and the bolt stays inside the circle |

## Rules

- Clear space: at least the stroke width of two bolt segments (about 1/8 of the tile height) on all sides.
- Minimum size: tile 16 px on screen (use the app-icon file) and 8 mm in print. Horizontal lockup 160 px wide on screen and 35 mm in print.
- Colour: use `color` on light backgrounds and `reverse` on dark ones. Use the `black` or `white` one-colour versions only where a single colour is mandated.
- Don't: recolour the bolt, stretch or rotate the tile, add effects (shadow, glow, gradient), change the corner radius, or set the wordmark in another typeface. Don't use Orange text on White below large-text size.

## Limits

- Source was ~85 px, so the vector is a faithful redraw, not an original file. The bolt area is within about 3% of the traced contour, and its edges are regularised to straight lines. Replace it with your original vector if you have one.
- Flat Orange only. The screenshot showed a slight lighter highlight at the top edge, which I treated as a screenshot artefact and not part of the logo.
- Corner radius is 20% of tile size, matched by eye to the screenshot. The bolt is centred in the tile (it sat about 1% right of centre in the screenshot, within tracing error).
- The bolt's strokes are about 1 px at 16 px, so it is crude there. The 16 to 32 px icons use a bolt enlarged 20% to compensate.
- No trademark clearance was done. INFERRED: "SecuritySuite" is a descriptive name for a security product and likely hard to protect or to register as a word mark, and I have not checked for similar marks. Run a search before committing.
