interface BrandMarkProps {
  className?: string;
  size?: number;
}

export function BrandMark({ className = "", size = 24 }: BrandMarkProps) {
  return (
    <img
      className={`shieldline-brand-mark${className ? ` ${className}` : ""}`}
      src={`${import.meta.env.BASE_URL}shieldline-mark.svg`}
      width={size}
      height={size}
      alt=""
      aria-hidden="true"
      draggable={false}
    />
  );
}
