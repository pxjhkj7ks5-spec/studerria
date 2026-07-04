import type { LaunchSector } from "../types/game";

// Fictional sectors for game balance only. They are broad map anchors, not real launch sites.
export const initialLaunchSectors: LaunchSector[] = [
  {
    id: "rf-northwest-uav",
    name: "Northwest UAV Sector",
    coordinates: { lat: 52.35, lng: 34.8 },
    supports: ["drone", "decoy", "saturation"],
    pressure: 1.05,
  },
  {
    id: "rf-northeast-ballistic",
    name: "Northeast Ballistic Sector",
    coordinates: { lat: 51.2, lng: 39.6 },
    supports: ["ballistic", "combined"],
    pressure: 0.85,
  },
  {
    id: "rf-east-cruise",
    name: "Eastern Cruise Sector",
    coordinates: { lat: 49.6, lng: 40.4 },
    supports: ["cruise", "combined", "saturation"],
    pressure: 1,
  },
  {
    id: "rf-southeast-mixed",
    name: "Southeast Mixed Sector",
    coordinates: { lat: 47.35, lng: 39.7 },
    supports: ["drone", "cruise", "decoy", "saturation"],
    pressure: 1.15,
  },
  {
    id: "rf-south-decoy",
    name: "Southern Decoy Sector",
    coordinates: { lat: 45.9, lng: 38.2 },
    supports: ["decoy", "drone", "combined"],
    pressure: 0.95,
  },
];
