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
