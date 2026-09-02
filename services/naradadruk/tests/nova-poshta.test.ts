import assert from "node:assert/strict";
import test from "node:test";
import { searchWarehouses } from "../src/lib/nova-poshta";

test("parcel locker search asks Nova Poshta for the parcel-locker warehouse type", async (context) => {
  const originalFetch = globalThis.fetch;
  const originalApiKey = process.env.NARADADRUK_NOVA_POSHTA_API_KEY;
  const requestBodies: Array<{
    calledMethod: string;
    methodProperties: Record<string, string>;
  }> = [];

  process.env.NARADADRUK_NOVA_POSHTA_API_KEY = "test-key";
  globalThis.fetch = async (_input, init) => {
    const body = JSON.parse(String(init?.body)) as {
      calledMethod: string;
      methodProperties: Record<string, string>;
    };
    requestBodies.push(body);

    if (body.calledMethod === "getWarehouseTypes") {
      return Response.json({
        success: true,
        data: [
          { Ref: "bank-locker-type", Description: "Поштомат ПриватБанку" },
          { Ref: "parcel-locker-type", Description: "Поштомат" },
        ],
      });
    }

    const typeRef = body.methodProperties.TypeOfWarehouseRef;
    return Response.json({
      success: true,
      data: [{
        Ref: typeRef === "bank-locker-type" ? "locker-bank" : "locker-1",
        Description: typeRef === "bank-locker-type" ? "Поштомат ПриватБанку" : "Поштомат №1",
        ShortAddress: "вул. Хрещатик, 1",
        CategoryOfWarehouse: "Поштомат",
        TypeOfWarehouse: typeRef,
      }],
    });
  };

  context.after(() => {
    globalThis.fetch = originalFetch;
    if (originalApiKey === undefined) delete process.env.NARADADRUK_NOVA_POSHTA_API_KEY;
    else process.env.NARADADRUK_NOVA_POSHTA_API_KEY = originalApiKey;
  });

  const result = await searchWarehouses("kyiv-ref", "", "parcel_locker");

  assert.equal(requestBodies[0].calledMethod, "getWarehouseTypes");
  assert.equal(requestBodies[1].calledMethod, "getWarehouses");
  assert.equal(requestBodies[1].methodProperties.TypeOfWarehouseRef, "parcel-locker-type");
  assert.equal(requestBodies.length, 2);
  assert.deepEqual(result.options, [{
    ref: "locker-1",
    label: "Поштомат №1",
    secondary: "вул. Хрещатик, 1",
  }]);
});
