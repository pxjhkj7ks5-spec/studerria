import threatBallistic from "./threats/ballistic.png";
import threatCruise from "./threats/cruise.png";
import threatDecoy from "./threats/decoy.png";
import threatDrone from "./threats/drone.png";
import threatSaturation from "./threats/saturation.png";
import confirmedThreat from "./icons/confirmed-threat.png";
import detectedTrack from "./icons/detected-track.png";
import impactEvent from "./icons/impact-event.png";
import interceptedThreat from "./icons/intercepted-threat.png";
import interceptorShot from "./icons/interceptor-shot.png";
import unknownTrack from "./icons/unknown-track.png";
import boatUnit from "./units/boat.png";
import bukUnit from "./units/buk.png";
import ewUnit from "./units/ew.png";
import gepardUnit from "./units/gepard.png";
import irisTUnit from "./units/iris-t.png";
import manpadsUnit from "./units/manpads.png";
import mvgUnit from "./units/mvg.png";
import nasamsUnit from "./units/nasams.png";
import patriotUnit from "./units/patriot.png";
import radarUnit from "./units/radar.png";
import s300Unit from "./units/s300.png";
import type { ThreatKind, UnitKind } from "../../types/game";

export const threatSprites: Record<ThreatKind, string> = {
  drone: threatDrone,
  ballistic: threatBallistic,
  cruise: threatCruise,
  decoy: threatDecoy,
  combined: threatCruise,
  saturation: threatSaturation,
};

export const unitSprites: Record<UnitKind, string> = {
  radar: radarUnit,
  mvg: mvgUnit,
  boat: boatUnit,
  ew: ewUnit,
  manpads: manpadsUnit,
  gepard: gepardUnit,
  buk: bukUnit,
  s300: s300Unit,
  "iris-t": irisTUnit,
  nasams: nasamsUnit,
  patriot: patriotUnit,
};

export const markerSprites = {
  unknownTrack,
  detectedTrack,
  confirmedThreat,
  interceptedThreat,
  impactEvent,
  interceptorShot,
};
