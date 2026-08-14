"use client";

import Image from "next/image";
import { useEffect, useState } from "react";
import { ArrowsOut, X } from "@phosphor-icons/react";
import { withBasePath } from "@/lib/base-path";

type GalleryImage = {
  id: number;
  urlPath: string;
  alt: string;
};

type ProductGalleryProps = {
  images: GalleryImage[];
  title: string;
};

export function ProductGallery({ images, title }: ProductGalleryProps) {
  const [selectedId, setSelectedId] = useState(images[0]?.id);
  const [isOpen, setIsOpen] = useState(false);
  const selectedImage = images.find((image) => image.id === selectedId) ?? images[0];

  useEffect(() => {
    if (!isOpen) {
      return;
    }

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setIsOpen(false);
      }
    };

    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", handleKeyDown);

    return () => {
      document.body.style.overflow = "";
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [isOpen]);

  if (!selectedImage) {
    return (
      <div className="product-gallery__empty">
        <span>Фото готується</span>
      </div>
    );
  }

  return (
    <>
      <div className="product-gallery">
        <button
          className="product-gallery__main"
          type="button"
          onClick={() => setIsOpen(true)}
          aria-label="Відкрити фото на весь екран"
        >
          <Image
            src={withBasePath(selectedImage.urlPath)}
            alt={selectedImage.alt || title}
            width={1400}
            height={1050}
            unoptimized
            priority
          />
          <span className="product-gallery__zoom">
            <ArrowsOut aria-hidden size={18} />
            Збільшити
          </span>
        </button>

        {images.length > 1 ? (
          <div className="product-gallery__thumbs" aria-label="Фото товару">
            {images.map((image) => (
              <button
                key={image.id}
                type="button"
                className={image.id === selectedImage.id ? "is-active" : ""}
                onClick={() => setSelectedId(image.id)}
                aria-label={`Показати фото: ${image.alt || title}`}
              >
                <Image
                  src={withBasePath(image.urlPath)}
                  alt=""
                  width={260}
                  height={200}
                  unoptimized
                />
              </button>
            ))}
          </div>
        ) : null}
      </div>

      {isOpen ? (
        <div
          className="product-gallery-modal"
          role="dialog"
          aria-modal="true"
          aria-label={`Фото товару ${title}`}
          onClick={() => setIsOpen(false)}
        >
          <button
            className="product-gallery-modal__close"
            type="button"
            onClick={() => setIsOpen(false)}
            aria-label="Закрити"
          >
            <X aria-hidden size={22} />
          </button>
          <Image
            src={withBasePath(selectedImage.urlPath)}
            alt={selectedImage.alt || title}
            width={1800}
            height={1350}
            unoptimized
            onClick={(event) => event.stopPropagation()}
          />
        </div>
      ) : null}
    </>
  );
}
