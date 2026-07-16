export interface MapZoomInputProfile {
  zoomSnap: number;
  zoomDelta: number;
  wheelPxPerZoomLevel: number;
  wheelDebounceTime: number;
}

const touchZoomProfile: MapZoomInputProfile = {
  zoomSnap: 0,
  zoomDelta: 0.5,
  wheelPxPerZoomLevel: 160,
  wheelDebounceTime: 35,
};

const finePointerZoomProfile: MapZoomInputProfile = {
  zoomSnap: 0.25,
  zoomDelta: 0.25,
  wheelPxPerZoomLevel: 240,
  wheelDebounceTime: 40,
};

export function mapZoomInputProfile(finePointer: boolean): MapZoomInputProfile {
  return finePointer ? finePointerZoomProfile : touchZoomProfile;
}
