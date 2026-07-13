# ShieldLine mobile live-mode design QA

- Reference: https://play.google.com/store/apps/details?id=com.doradogames.conflictnations.worldwar3
- Viewport: `390 × 844`
- Reference capture: `design-qa-reference.png`
- Implementation capture: `design-qa-implementation.png`
- Side-by-side comparison: `design-qa-comparison.png`
- Full-screen panel capture: `design-qa-panel.png`

## Comparison

The implementation follows the reference's map-first hierarchy: a compact resource strip, an uninterrupted tactical map, and a five-action bottom navigation. ShieldLine intentionally keeps its own dark Liquid Glass visual language, map treatment, sprites, colors, and icon set.

| Priority | Finding | Resolution |
| --- | --- | --- |
| P0 | No blocking visual or interaction defects found. | Passed. |
| P1 | The map must remain the dominant surface and panels must not compete with it. | HUD and navigation total `120 px` of `844 px` (14.2%); an open panel is opaque, hides the map, disables pointer events, and leaves navigation visible. |
| P2 | Five navigation targets need readable labels and mobile-size hit areas. | All five actions are present in Ukrainian with targets of at least `44 px`; the layout works at `390 × 844` and `844 × 390`. |
| P2 | The large panel needs clear hierarchy without exposing the map. | Added a dedicated header, close action, map layers, embedded legend, help, and a guarded return-to-mode action. |
| P3 | The reference uses a brighter military-game skin than ShieldLine. | Deliberately retained ShieldLine's dark Liquid Glass design instead of copying the reference's graphic style. |

## Interaction checks

- Opened and closed the full-screen menu; the bottom navigation remained available.
- Confirmed the map is `visibility: hidden`, `opacity: 0`, `pointer-events: none`, and `aria-hidden="true"` while a panel is open.
- Confirmed no horizontal overflow at the target viewport.
- Confirmed the browser console has no errors in the checked mobile live-mode state.
- Automated coverage includes PПО placement, invalid placement recovery, cancel, stable radius DOM across zoom, non-selectable installed units, toast priority, WebKit, landscape, and accessibility.

## History

1. Captured the official phone screenshot and the implementation at the same portrait viewport.
2. Compared the two captures side by side and verified the map-first hierarchy.
3. Inspected the full-screen menu state and measured HUD/navigation proportions.
4. Fixed landscape navigation sizing and mobile tutorial language during QA.
5. Re-ran the affected browser flows and confirmed the final state.

Final result: **passed**.

## 2026-07-13 Telegram top safe-area adjustment

- Source visual truth: `/tmp/codex-remote-attachments/019f5bc3-17cd-7730-b2ac-0afc6dfd2702/FD2444F5-D7A0-427F-B04A-D1064EA19015/1-Photo-1.jpg`
- Implementation screenshot: `/tmp/shieldline-design-qa-telegram-safe-area.png`
- Full-view comparison: `/tmp/shieldline-design-qa-safe-area-comparison.png`
- Focused top-region comparison: `/tmp/shieldline-design-qa-top-comparison.png`
- Viewport: `390 × 844`, portrait mobile
- State: training live map, drawer closed, Telegram content safe-area top simulated at `78 px`

### Findings and fidelity surfaces

- No remaining P0, P1, or P2 findings in the requested top-HUD scope.
- Fonts and typography: the existing compact resource labels are preserved; the centered brand uses the existing heading family and weight.
- Spacing and layout rhythm: the HUD now begins below Telegram's content safe area, with a centered `26 px` brand row followed by the existing `52 px` resource row. The bottom navigation remains unobstructed.
- Colors and visual tokens: the new brand capsule reuses Shieldline's existing dark glass, blue border, white text, and icon colors.
- Image quality and asset fidelity: no raster asset was substituted or degraded; the existing Lucide Shield icon is reused as the product mark.
- Copy and content: resource copy is unchanged; the added centered label is the existing product name, `Shieldline`.

### Comparison history

1. Initial P1: Telegram native controls overlapped the HUD because the Telegram Mini Apps SDK was not loaded, leaving content-safe-area values unavailable.
2. Fix: loaded the official SDK without blocking app startup, allowed it in CSP, subscribed to safe-area events, and positioned the HUD from the reported content safe area.
3. Initial P2: after reserving native-control space, the mobile HUD had no centered product identity.
4. Fix: restored a compact centered Shieldline logo row using the existing Shield icon and visual tokens.
5. Post-fix evidence: the safe-area capture and side-by-side comparison show a clear native-control reserve above the logo and resource row, with no HUD overlap.

### Interaction and runtime checks

- Opened the live mobile map in the Codex in-app browser.
- Verified that `Меню` opens the full-screen menu panel.
- Checked captured browser console errors: none.
- Focused comparison was required because the requested change is concentrated in the top HUD and Telegram safe-area boundary.
- The mobile Chromium e2e remains blocked by the pre-existing persisted-state fixture error `latestReportId`; it occurs before the HUD renders and is outside this scoped layout change.

final result: passed
