import { expect, it, vi } from "vitest";
import { Store } from "../src/store.js";

it.each([0, 5000])("bounds risk cleanup with batch result %s", async (rowCount) => {
  const query = vi.fn(async () => ({ rowCount }));
  const transactionQuery = vi.fn(async () => ({ rowCount: 0 }));
  const store = Object.assign(Object.create(Store.prototype), {
    config: { OBRIY_RETENTION_DAYS: 30, OBRIY_RISK_RETENTION_HOURS: 24, OBRIY_RAW_RETENTION_HOURS: 24 },
    pool: { query },
    transaction: async (work: (client: unknown) => Promise<unknown>) => work({ query: transactionQuery }),
  }) as Store;
  await store.cleanup();
  expect(query).toHaveBeenCalledTimes(rowCount === 0 ? 1 : 20);
  expect(query.mock.calls[0]).toEqual([expect.stringContaining("LIMIT 5000 FOR UPDATE SKIP LOCKED"), [24]]);
  expect(transactionQuery.mock.calls.flat().join(" ")).not.toContain("risk_assessments");
});
