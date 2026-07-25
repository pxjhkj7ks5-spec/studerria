# Shieldline audio cue sheet

Direction: realistic hybrid, restrained command-interface design, no music or speech. Runtime processing in `soundCues.ts` applies gain, playback-rate, offsets, duration limits, cooldowns, priority ducking, and variation selection. All shipped source recordings are CC0 Freesound HQ MP3 previews. Compact UI and transient files use normalized excerpts; longer warning material is bounded by runtime duration and gain.

| Cue family | Character and function | Target length | Variations | Priority | Source material | Processing and acceptance notes |
| --- | --- | ---: | ---: | --- | --- | --- |
| UI actions | One short, dry electronic click | 0.26 s | 1 | Low | `ui-click` | Same file, gain and playback rate for open, close, select, confirm, cancel and error |
| Placement/redeploy/service/planning | The same neutral UI click | 0.26 s | 1 | Low | `ui-click` | No tonal variants; played only after a meaningful command |
| Operation countdown/start | Timer plus brief radio-channel opening | 0.7–3.7 s | 2 | Medium | `timer`, `radio-static`, `mechanical` | Countdown is single-voice; pause and resume use the neutral UI click |
| Prelaunch/contact/radar | Short radio interference and high confirmation tick | 0.4–1.2 s | 2 | Medium | `radio-static`, `confirm` | Grouped by cooldown during dense waves |
| Drone launch/engagement | Distant launch wash or propeller texture, fixed by context | 1.5–2.0 s | 1 per cue | Medium | `rocket-distant`, `drone` | Launch and interceptor-drone cues no longer alternate unrelated sources |
| Cruise/ballistic launch | Distant rocket wash or close missile ignition | 2.0–3.2 s | 2 | Medium/Critical | `rocket-distant`, `missile-launch` | Ballistic warning ducks lower-priority voices |
| Air raid/all clear | Dedicated warning signal followed by a restrained clear chime | 0.4–9 s | 1 per cue | Critical | `air-raid`, `chime` | Air-raid signal fades over its final 1.5 s; one global cue per escalation |
| Gun/missile/EW engagement | Distinct kinetic burst, missile ignition, or radio disruption | 0.4–2.3 s | 1 per cue | Medium | `gun-burst-1`, `missile-launch`, `radio-static` | Maximum three simultaneous voices; fixed source per context |
| Reload | Short metallic mechanism | 0.5–0.7 s | 1 | Medium | `mechanical` | Fires when the battery actually enters reload |
| Intercept/soft kill/miss | Short kinetic impact, interference fade, or contact loss | 0.6–1.8 s | 1 per cue | Medium | `intercept-impact`, `radio-static` | Successful PVO impact uses its own fixed source below the city-impact level |
| City impact | Deep explosion with a long natural tail | 11.4 s maximum | 1 | Critical | `city-impact` | Ducks UI/combat buses; never stacked beyond one voice |
| Mission outcome | Clean chime or slowed warning sequence | 0.4–2.4 s | 2 | Critical | `chime`, `timer` | Played after operation-complete cue |

## Rejected source categories

- Contemporary real-world attack footage or recordings.
- Dispatch, radio speech, callsigns, or identifiable voices.
- Sirens tied to a recognizable city or current emergency.
- CC BY-NC, unclear licenses, or stock-library files that cannot be redistributed in the repository.
