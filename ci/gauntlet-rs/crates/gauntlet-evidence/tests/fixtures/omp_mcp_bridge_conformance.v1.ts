// Root runs this fixture only in the VM with the outside-pinned OMP 18.4.12
// module path. It imports the genuine public MCPTool class; its connection is
// an in-memory result source, with no model, network or credential interface.
import { pathToFileURL } from "node:url";
import { createHash } from "node:crypto";

const modulePath = process.argv[2];
if (!modulePath || !modulePath.startsWith("/")) throw new Error("absolute pinned SDK module path required");
const { MCPTool } = await import(pathToFileURL(modulePath).href);
if (typeof MCPTool?.fromTools !== "function") throw new Error("locked SDK MCPTool export missing");
const catalogPath = process.argv[3];
if (!catalogPath || !catalogPath.startsWith("/") || !catalogPath.endsWith("catalog-python-mcp-1.30.0.v1.json")) throw new Error("absolute source catalog path required");
const catalogBytes = await Bun.file(catalogPath).arrayBuffer();
const catalogSha = createHash("sha256").update(new Uint8Array(catalogBytes)).digest("hex");
if (catalogSha !== "22df4f3850d6d22ef30b6ec45108cde9b4306879c06c99ccce6f3bf53097cafe") throw new Error("source catalog pin mismatch");
const definition = JSON.parse(new TextDecoder().decode(catalogBytes)).families.docs.find((tool: { name: string }) => tool.name === "docs.search");
if (!definition) throw new Error("source tool definition missing");
const args = { collection: "docs.documents", i: "internal intent", intent: "retained data", query: "", cursor: {}, fields: [], tenant_id: null };
const expectedArgs = { collection: "docs.documents", intent: "retained data", fields: [], tenant_id: null };
function assertConformance(condition: unknown, detail: string): asserts condition {
  if (!condition) throw new Error(`SDK conformance failed: ${detail}`);
}
const cases = [
  { name: "duplicate-structured", raw: '{"content":[{"text":"","type":"text"}],"isError":false,"structuredContent":{"record":{"id":"ticket-a"}}}' },
  { name: "merged-error", raw: '{"content":[{"text":"blocked","type":"text"},{"text":"details","type":"text"}],"isError":true}' },
  { name: "structured-error", raw: '{"content":[{"text":"blocked","type":"text"}],"isError":true,"structuredContent":{"error":{"message":"denied","retry":false}}}' },
  { name: "integer-object-order", raw: '{"content":[{"text":"summary","type":"text"}],"isError":false,"structuredContent":{"01":"one","10":"ten","2":"two","a":[1,true,null]}}' },
];
const observations = [];
for (const entry of cases) {
  const result = JSON.parse(entry.raw);
  // Build the duplicate text directly from the exact structured value so this
  // case measures the SDK duplicate detector, independent of source quoting.
  if (entry.name === "duplicate-structured") result.content[0].text = JSON.stringify(result.structuredContent);
  const wire = [];
  const connection = {
    name: "docs",
    config: {},
    capabilities: { tools: {} },
    // Actual locked SDK client.ts SHA d1c8a899, lines 255-270:
    // transport.request("tools/call", {name, arguments}, {signal}).
    transport: { request: async (method: string, params: unknown, options: { signal?: AbortSignal }) => {
      wire.push({ method, params, options });
      assertConformance(method === "tools/call", `${entry.name}: actual transport method`);
      assertConformance(Bun.deepEquals(params, { name: "docs.search", arguments: expectedArgs }), `${entry.name}: actual transport arguments`);
      assertConformance(options !== null && typeof options === "object" && Object.keys(options).length === 1 && Object.hasOwn(options, "signal") && options.signal === undefined, `${entry.name}: actual transport options`);
      return result;
    } },
  };
  const [tool] = MCPTool.fromTools(connection, [definition]);
  const output = await tool.execute("source-conformance-call", args, undefined, {});
  assertConformance(wire.length === 1, `${entry.name}: exactly one real transport call, got ${wire.length}`);
  const expectedContent = entry.name === "duplicate-structured" ? result.content
    : entry.name === "merged-error" ? [{ type: "text", text: "Error: blocked\n\ndetails" }]
    : entry.name === "structured-error" ? [{ type: "text", text: "Error: blocked" }, { type: "text", text: '```json\n{\n  "error": {\n    "message": "denied",\n    "retry": false\n  }\n}\n```' }]
    : [{ type: "text", text: "summary" }, { type: "text", text: '```json\n{\n  "2": "two",\n  "10": "ten",\n  "01": "one",\n  "a": [\n    1,\n    true,\n    null\n  ]\n}\n```' }];
  assertConformance(Bun.deepEquals(output.content, expectedContent), `${entry.name}: exact SDK displayed content: ${JSON.stringify(output.content)}`);
  assertConformance(output.details?.serverName === "docs" && output.details?.mcpToolName === "docs.search", `${entry.name}: actual SDK tool identity`);
  assertConformance(Bun.deepEquals(output.details?.rawContent, result.content), `${entry.name}: original raw content retained`);
  assertConformance(output.details?.isError === result.isError && output.isError === (result.isError ? true : undefined), `${entry.name}: exact SDK error status`);
  assertConformance(Bun.deepEquals(output.details?.structuredContent, result.structuredContent), `${entry.name}: exact structured payload retained`);
  observations.push({ name: entry.name, result, wire, output });
}
assertConformance(observations.length === 4, "all four actual SDK cases completed");
process.stdout.write(JSON.stringify({ schema: "hol-gauntlet-omp-mcp-bridge-conformance.v1", model_requests: 0, qualification_eligible: false, catalog_sha256: catalogSha, observations }) + "\n");
