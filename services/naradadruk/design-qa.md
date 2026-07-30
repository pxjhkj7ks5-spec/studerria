# Design QA — Narada Druk

## Reference and environment

- Source reference: `C:\Users\andri\.codex\generated_images\019fb37a-bd93-7f73-bab1-e8e67e296f12\call_KsnsHloiScks8XVRdF4gwZb9.png`
- Source size: 864 × 1821 px, 72 dpi.
- Local preview: `http://127.0.0.1:4173/naradadruk`
- Desktop capture viewport: 1024 × 1000 CSS px at 1× density; full-page output 1009 × 3462 px.
- Mobile capture viewport: 390 × 844 CSS px at 1× density.
- Comparison image: `C:\Users\andri\OneDrive\Desktop\proj\kma\output\playwright\naradadruk-after\home-comparison.png`. Both desktop views are normalized to 864 px width and placed side by side.
- State: seeded site settings and categories; empty-catalog state captured before adding a local-only product fixture. The fixture was used only to verify product, variant, gallery, and Telegram behavior and is not part of the committed data.

## Evidence

- Full home, desktop: `C:\Users\andri\OneDrive\Desktop\proj\kma\output\playwright\naradadruk-after\home-desktop.png`
- Full home, mobile: `C:\Users\andri\OneDrive\Desktop\proj\kma\output\playwright\naradadruk-after\home-mobile.png`
- Full catalog, desktop: `C:\Users\andri\OneDrive\Desktop\proj\kma\output\playwright\naradadruk-after\catalog-desktop.png`
- Full catalog, mobile: `C:\Users\andri\OneDrive\Desktop\proj\kma\output\playwright\naradadruk-after\catalog-mobile.png`
- Full product, desktop: `C:\Users\andri\OneDrive\Desktop\proj\kma\output\playwright\naradadruk-after\product-desktop.png`
- Full product, mobile: `C:\Users\andri\OneDrive\Desktop\proj\kma\output\playwright\naradadruk-after\product-mobile.png`
- Focus evidence: `C:\Users\andri\OneDrive\Desktop\proj\kma\output\playwright\naradadruk-after\home-mobile-focus.png`. The mobile Telegram CTA receives a visible 3 px orange outline by keyboard.

## Findings and iteration history

1. The first implementation matched the selected warm Liquid Glass direction but kept the more editorial spacing of option 3. This is intentional; the shared glass header and category dock follow option 1.
2. Product-free local data initially showed the designed custom-order fallback instead of invented merchandise. Product-only behavior was then checked with a local fixture.
3. The generated hero asset was converted from a 1.5 MB PNG to a 53 KB WebP. The hero now uses eager loading and high fetch priority; the final browser run reported no LCP warning.
4. Footer navigation, wordmark, header CTA, and category chips were adjusted to meet or exceed 44 px mobile tap targets.
5. No P0, P1, P2, or unresolved P3 visual issues remain.

## Primary interactions

- FAQ disclosure opens correctly.
- Catalog search updates the URL and displays the empty result state.
- Category route displays its heading and filtered product count.
- Product variant selection updates the displayed price from 320 грн to 460 грн.
- Product Telegram link contains the product title, selected variant, and canonical URL.
- A click produces exactly one `Telegram Lead` event with safe properties only.
- Desktop and mobile product CTAs remain visible without searching the page; mobile uses a sticky purchase bar.
- Keyboard focus is visible. Reduced-motion styles are present.
- Final browser console check: 0 errors, 0 warnings.

Final result: passed
