export interface MapZoomInputProfile {
  pixelsPerZoomLevel: number;
  smoothing: number;
  maxDelta: number;
}

const touchZoomProfile: MapZoomInputProfile = {
  pixelsPerZoomLevel: 320,
  smoothing: 0.3,
  maxDelta: 0.6,
};

const finePointerZoomProfile: MapZoomInputProfile = {
  pixelsPerZoomLevel: 240,
  smoothing: 0.38,
  maxDelta: 0.75,
};

export function mapZoomInputProfile(finePointer: boolean): MapZoomInputProfile {
  return finePointer ? finePointerZoomProfile : touchZoomProfile;
}

export function wheelZoomDelta(
  deltaY: number,
  deltaMode: number,
  profile: MapZoomInputProfile,
  viewportHeight = 800,
) {
  const pixelDelta = deltaMode === 1
    ? deltaY * 16
    : deltaMode === 2
      ? deltaY * viewportHeight
      : deltaY;
  const zoomDelta = -pixelDelta / profile.pixelsPerZoomLevel;
  return Math.max(-profile.maxDelta, Math.min(profile.maxDelta, zoomDelta));
}
