import { withBasePath } from "@/lib/base-path";
import { defaultTelegramUrl } from "@/lib/constants";
import { PublicFrame } from "@/components/site/public-frame";

export default function NotFound() {
  return (
    <PublicFrame telegramUrl={defaultTelegramUrl}>
      <main className="not-found-page">
        <div className="not-found-card">
          <p className="eyebrow">404</p>
          <h1>Сторінку не знайдено.</h1>
          <p>
            Можливо, товар ще не опублікований або посилання вже неактуальне.
          </p>
          <div>
            <a className="accent-pill" href={withBasePath("/catalog")}>
              До каталогу
            </a>
            <a className="ghost-pill" href={withBasePath("/")}>
              На головну
            </a>
          </div>
        </div>
      </main>
    </PublicFrame>
  );
}
