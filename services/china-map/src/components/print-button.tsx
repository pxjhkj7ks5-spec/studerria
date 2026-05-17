"use client";

export function PrintButton() {
  return (
    <button type="button" className="atlas-action atlas-action--primary print-action" onClick={() => window.print()}>
      Print / Save PDF
    </button>
  );
}
