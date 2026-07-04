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
import decoyUnit from "./units/decoy.png";
import gunUnit from "./units/gun.png";
import intelUnit from "./units/intel.png";
import logisticsUnit from "./units/logistics.png";
import logisticsHub from "./units/logistics-hub.png";
import mediumUnit from "./units/medium.png";
import mobileUnit from "./units/mobile.png";
import radarUnit from "./units/radar.png";
import repairUnit from "./units/repair.png";
import shortUnit from "./units/short.png";
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
  mobile: mobileUnit,
  short: shortUnit,
  medium: mediumUnit,
  repair: repairUnit,
  logistics: logisticsHub,
  intel: intelUnit,
  decoy: decoyUnit,
};

export const supportUnitSprites = {
  gun: gunUnit,
  logisticsVehicle: logisticsUnit,
};

export const markerSprites = {
  unknownTrack,
  detectedTrack,
  confirmedThreat,
  interceptedThreat,
  impactEvent,
  interceptorShot,
};
