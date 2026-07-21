# Shieldline audio cue sheet

Direction: realistic hybrid, restrained command-interface design, no music or speech. Runtime processing in `soundCues.ts` applies gain, playback-rate, offsets, duration limits, cooldowns, priority ducking, and variation selection. All shipped source recordings are CC0 and were downloaded as Freesound HQ MP3 previews on 2026-07-22, then re-encoded at 48 kHz with a -20 LUFS / -1.5 dBTP normalization target; short UI and transient files are mono, spatial and environmental files remain stereo.

| Cue family | Character and function | Target length | Variations | Priority | Source material | Processing and acceptance notes |
| --- | --- | ---: | ---: | --- | --- | --- |
| UI open/select/confirm | Short, dry electronic confirmation | 0.1–0.4 s | 2 | Low | `confirm`, `chime` | Quiet mix; no sound on hover, map pan, or zoom |
| UI cancel/error | Mechanical down-click or restrained warning pulse | 0.3–0.6 s | 2 | Low | `mechanical`, `timer` | Playback-rate variants; error cooldown prevents chatter |
| Placement/redeploy/service | Physical command-console latch | 0.3–0.7 s | 2 | Low | `mechanical`, `chime` | Played only after a meaningful command; service failure uses error cue |
| Operation countdown/start | Timer plus brief radio-channel opening | 0.7–3.7 s | 2 | Medium | `timer`, `radio-static`, `mechanical` | Countdown is single-voice; never loops |
| Prelaunch/contact/radar | Short radio interference and high confirmation tick | 0.4–1.2 s | 2 | Medium | `radio-static`, `confirm` | Grouped by cooldown during dense waves |
| Drone launch/engagement | Distant propeller texture with subdued launch layer | 1.5–2.0 s | 2 | Medium | `drone`, `rocket-distant` | Selected excerpts avoid sustained ambience |
| Cruise/ballistic launch | Distant rocket wash or close missile ignition | 2.0–3.2 s | 2 | Medium/Critical | `rocket-distant`, `missile-launch` | Ballistic warning ducks lower-priority voices |
| Air raid/all clear | Neutral synthesized siren, not a live geographic recording | 4–9 s | 2 excerpts | Critical | `siren` | One global cue per escalation; minimum 12 s cooldown |
| Gun/missile/EW engagement | Distinct kinetic burst, launch wash, or radio disruption | 0.4–2.3 s | 2 per frequent kinetic cue | Medium | `gun-burst-1`, `gun-burst-2`, `missile-launch`, `radio-static` | Maximum three simultaneous voices; no immediate variation repeat |
| Reload | Short metallic mechanism | 0.5–0.7 s | 1 | Medium | `mechanical` | Fires when the battery actually enters reload |
| Intercept/soft kill/miss | Controlled impact, interference fade, or contact loss | 0.6–2.3 s | 2 | Medium | `impact`, `radio-static`, `chime` | Kept below the impact alarm level |
| Impact | Low, short explosion excerpt | 4.5 s maximum | 1 | Critical | `impact` | Ducks UI/combat buses; never stacked beyond one voice |
| Mission outcome | Clean chime or slowed warning sequence | 0.4–2.4 s | 2 | Critical | `chime`, `timer` | Played after operation-complete cue |

## Rejected source categories

- Contemporary real-world attack footage or recordings.
- Dispatch, radio speech, callsigns, or identifiable voices.
- Sirens tied to a recognizable city or current emergency.
- CC BY-NC, unclear licenses, or stock-library files that cannot be redistributed in the repository.
