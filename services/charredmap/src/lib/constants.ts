export const siteName = "charredmap";
export const siteDescription =
  "Інтерактивна мапа історій людей з деокупованих та окупованих міст України.";
export const mapStyleUrl = "https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json";
export const adminSessionTtlSeconds = 60 * 60 * 24 * 7;
export const maxUploadSizeBytes = 8 * 1024 * 1024;

export const ukraineBounds = [
  [20.8, 43.6],
  [40.4, 52.6],
] as const;

export const occupationStatuses = ["occupied", "deoccupied"] as const;
export const publicationStatuses = ["draft", "submitted", "published"] as const;

export type OccupationStatus = (typeof occupationStatuses)[number];
export type PublicationStatus = (typeof publicationStatuses)[number];

export const occupationMeta: Record<
  OccupationStatus,
  {
    label: string;
    badge: string;
    markerClassName: string;
    markerLabel: string;
  }
> = {
  occupied: {
    label: "Окуповане місто",
    badge: "Помаранчевий сигнал",
    markerClassName: "bg-[--accent-orange] shadow-[0_0_28px_rgba(255,132,56,0.55)]",
    markerLabel: "Окуповане",
  },
  deoccupied: {
    label: "Деокуповане місто",
    badge: "Червоний акцент",
    markerClassName: "bg-[--paper] ring-2 ring-[rgba(218,59,59,0.8)] shadow-[0_0_26px_rgba(218,59,59,0.35)]",
    markerLabel: "Деокуповане",
  },
};

export const publicationMeta: Record<PublicationStatus, string> = {
  draft: "Чернетка",
  submitted: "На модерації",
  published: "Опубліковано",
};
