export interface MapZoomInputProfile {
  zoomDelta: number;
  wheelPxPerZoomLevel: number;
  wheelDebounceTime: number;
}

const touchZoomProfile: MapZoomInputProfile = {
  zoomDelta: 0.5,
  wheelPxPerZoomLevel: 160,
  wheelDebounceTime: 35,
};

const finePointerZoomProfile: MapZoomInputProfile = {
  zoomDelta: 0.35,
  wheelPxPerZoomLevel: 70,
  wheelDebounceTime: 18,
};

export function mapZoomInputProfile(finePointer: boolean): MapZoomInputProfile {
  return finePointer ? finePointerZoomProfile : touchZoomProfile;
}
