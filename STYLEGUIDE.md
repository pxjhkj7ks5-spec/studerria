# Studerria UI Style Guide (Liquid Glass)

## Tokens
- Use CSS variables from `public/css/tokens.css`.
- Theme is driven by `body.theme-dark` / `body.theme-light`.

## Surfaces
- `.glass-card`: hero / large containers.
- `.glass-panel`: section containers.
- `.glass-inset`: inner blocks.
- `.glass` and `.card` are mapped to Liquid Glass by default.

## Buttons
- `.btn` base (pill).
- `.btn-primary`, `.btn-secondary`, `.btn-outline-primary`, `.btn-outline-secondary`, `.btn-danger`.
- `.chip` for pill tags.

## Segmented
- `.segmented` / `.segment-control` container.
- `.segmented__item` / `.segment` items.
- `.is-active` / `.is-selected` for active state.

## Forms
- `.form-control`, `.form-select` are styled globally.
- Focus ring is subtle and Apple-like.

## Modals
- `.modal-content` / `.modal-backdrop` styled globally.

## Page overrides
- `public/css/pages/auth.css` for auth screens.
- `public/css/pages/schedule.css` for schedule layout.
- `public/css/pages/admin.css` for admin tables/panels.
- `public/css/pages/teamwork.css` for chips/cards.
- `public/css/pages/profile.css` for stats.
- `public/css/pages/my-day.css` for daily view.
- `public/css/pages/landing.css` for landing hero.
