/** Locked SDK registration; optional sealed Settings fixture runs one fixed trusted shell command. */
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { tmpdir } from 'node:os';
import { developerBuiltinToolNames, pinDeclaredToolInventory, loadEpisodeSdk, assertEpisodeSettings } from './developer_omp_episode.ts';

async function main() {
  const sdkRoot = process.argv[2];
  if (!sdkRoot || !isAbsolute(sdkRoot)) throw new Error('exact absolute installed SDK root required');
  const sealed = process.argv[3] === '--sealed-startup-v1';
  if (process.argv.length !== (sealed ? 4 : 3) || (sealed && process.cwd() !== '/runtime/public')) {
    throw new Error('closed inventory or sealed Settings fixture required');
  }
  const metadata = JSON.parse(await readFile(join(sdkRoot, 'package.json'), 'utf8'));
  if (metadata.version !== '18.4.12') throw new Error('locked SDK version differs');
  const root = await mkdtemp(join(tmpdir(), 'developer-sdk-inventory-'));
  // These assets contain no candidate code or product configuration.
  const workspace = join(root, 'workspace');
  const agentDir = join(root, 'agent');
  await mkdir(workspace); await mkdir(agentDir);
  let hostileHome: string | undefined;
  if (sealed) {
    const home = process.env.HOME;
    if (!home || home !== '/runtime/home') throw new Error('fresh isolated fixture HOME required');
    hostileHome = join(home, '.omp');
    await mkdir(hostileHome, { mode: 0o700 }); // Exclusive: never modify an existing user configuration.
    await mkdir(join(workspace, '.omp'), { mode: 0o700 });
    const hostile = JSON.stringify({ shellPath: '/gauntlet-hostile-settings-must-not-run',
      extensions: [join(workspace, 'hostile-extension.ts')], advisor: { enabled: true }, bash: { direnv: 'off' } });
    await writeFile(join(workspace, 'hostile-extension.ts'), 'throw new Error("hostile SDK configuration loaded");\n', { flag: 'wx' });
    for (const path of [join(workspace, '.omp/settings.json'), join(agentDir, 'config.yml'), join(hostileHome, 'config.yml')]) {
      await writeFile(path, hostile, { flag: 'wx', mode: 0o600 });
    }
  }
  const loaded = sealed ? await loadEpisodeSdk(sdkRoot, workspace, agentDir, 'bun-1.3.14-sealed-v1') : undefined;
  const sdk = loaded?.sdk ?? await import(join(sdkRoot, 'src/index.ts'));
  const { MCPManager } = await import(join(sdkRoot, 'src/mcp/manager.ts'));
  const { MCPTool } = await import(join(sdkRoot, 'src/mcp/tool-bridge.ts'));
  const auth = await sdk.AuthStorage.create(join(agentDir, 'fixture-auth.db'));
  const settings = loaded?.settings ?? await sdk.Settings.init({ cwd: workspace, agentDir, inMemory: true });
  const shellBefore = settings.getShellConfig();
  const registry = new sdk.ModelRegistry(auth, join(agentDir, 'models.yml'), { settings });
  registry.registerProvider('inventory-fixture', { baseUrl: 'http://127.0.0.1:9/v1', api: 'openai-completions',
    authHeader: false, apiKey: 'fixture-no-auth', models: [{ id: 'registration-only', name: 'registration-only',
      reasoning: false, input: ['text'], contextWindow: 10000, maxTokens: 1000,
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } }] });
  const model = registry.find('inventory-fixture', 'registration-only');
  const manager = new MCPManager(workspace, null, async () => ({ configs: {}, sources: {}, exaApiKeys: [] }));
  // A genuine SDK MCPTool declaration; no connection operation can be executed.
  const resourceTools = MCPTool.fromTools({ name: 'inventory-fixture' }, [{ name: 'docs.read',
    description: 'Registration fixture only', inputSchema: { type: 'object', properties: {} } }]);
  resourceTools[0].execute = () => { throw new Error('registration fixture must never execute a tool'); };
  let session: any;
  let providerCalls = 0;
  let toolCalls = 0;
  try {
    const sessionOptions = { cwd: workspace, agentDir, authStorage: auth,
      settings, modelRegistry: registry, model, getApiKey: async () => { providerCalls++; throw new Error('no model'); },
      sessionManager: sdk.SessionManager.inMemory(workspace), toolNames: ['read', 'write', 'edit', 'bash'],
      enableMCP: true, mcpManager: manager, customTools: resourceTools, disableExtensionDiscovery: true,
      extensions: [(api: any) => api.on('tool_call', () => { toolCalls++; throw new Error('no tool execution'); })],
      additionalExtensionPaths: [], enableLsp: false, enableIrc: false, skipPythonPreflight: true,
      skills: [], rules: [], contextFiles: [], promptTemplates: [], slashCommands: [],
      preloadedCustomToolPaths: [], cacheWarming: false };
    ({ session } = await sdk.createAgentSession(sessionOptions));
    if (sealed) await assertEpisodeSettings(sdk, settings, agentDir);
    const expected = ['read', 'write', 'edit', 'bash', resourceTools[0].name];
    await session.setActiveToolsByName(expected);
    const before = { active: session.getActiveToolNames(), enabled: session.getEnabledToolNames(),
      mounted: session.getMountedXdevToolNames() };
    if (!before.enabled.includes(resourceTools[0].name) || !before.mounted.includes(resourceTools[0].name)
        || before.active.includes(resourceTools[0].name)) throw new Error('locked SDK did not reproduce xd:// partition');
    await pinDeclaredToolInventory(session, expected);
    const after = { active: session.getActiveToolNames(), enabled: session.getEnabledToolNames(),
      mounted: session.getMountedXdevToolNames() };
    let missingRejected = false;
    let missingDiagnostic: any;
    try { await pinDeclaredToolInventory(session, [...expected, 'mcp__missing_unregistered']); }
    catch (error) {
      missingDiagnostic = JSON.parse(String(error).split('transports: ')[1]);
      missingRejected = missingDiagnostic.missing.includes('mcp__missing_unregistered');
    }
    let duplicateRejected = false;
    try { await pinDeclaredToolInventory(session, [...expected, expected[0]]); }
    catch (error) { duplicateRejected = String(error).includes('duplicate declared'); }
    if (!missingRejected || !duplicateRejected || providerCalls !== 0 || toolCalls !== 0) {
      throw new Error('inventory failure/no-execution invariant failed');
    }
    const legacyV1 = developerBuiltinToolNames({ schema: 'developer-omp-episode.v1' });
    const legacyV2 = developerBuiltinToolNames({ schema: 'developer-omp-episode.v2',
      mcpAgentSurfaces: 'mcp-agent-surfaces.v1' });
    const mcpProfile = { schema: 'developer-omp-episode.v3' as const,
      builtinToolProfile: 'mcp-only.v1' as const, resourceEndpoints: { docs: {} } };
    const builtins = developerBuiltinToolNames(mcpProfile);
    if (builtins.length || JSON.stringify(legacyV1) !== JSON.stringify(['read', 'write', 'edit', 'bash'])
        || JSON.stringify(legacyV2) !== JSON.stringify(legacyV1)) throw new Error('versioned tool inventory changed');
    let invalidProfilesRejected = 0;
    for (const invalid of [
      { ...mcpProfile, builtinToolProfile: undefined },
      { ...mcpProfile, resourceEndpoints: undefined }, { ...mcpProfile, resourceEndpoints: {} },
      { ...mcpProfile, resourceEndpoints: [] },
      { ...mcpProfile, mcpAgentSurfaces: 'mcp-agent-surfaces.v1' },
      { ...mcpProfile, schema: 'developer-omp-episode.v1' },
    ]) {
      try { developerBuiltinToolNames(invalid as any); }
      catch { invalidProfilesRejected++; }
    }
    if (invalidProfilesRejected !== 6) throw new Error('invalid mixed tool profile accepted');
    await session.dispose(); session = undefined;
    ({ session } = await sdk.createAgentSession({ ...sessionOptions, toolNames: builtins,
      sessionManager: sdk.SessionManager.inMemory(workspace) }));
    await pinDeclaredToolInventory(session, [resourceTools[0].name]);
    const mcpOnly = { active: session.getActiveToolNames(), enabled: session.getEnabledToolNames(),
      mounted: session.getMountedXdevToolNames(), builtins, invalidProfilesRejected, legacyV1, legacyV2 };
    if (providerCalls !== 0 || toolCalls !== 0) throw new Error('MCP-only registration executed work');
    let sealedSettings: any;
    if (sealed) {
      await assertEpisodeSettings(sdk, settings, agentDir);
      const { executeBash } = await import(join(sdkRoot, 'src/exec/bash-executor.ts'));
      const result = await executeBash("printf '%s\\n' GAUNTLET_SEALED_SETTINGS_CACHE_V1", { cwd: workspace, timeout: 10000 });
      await assertEpisodeSettings(sdk, settings, agentDir);
      const shellAfter = settings.getShellConfig();
      if (result.exitCode !== 0 || result.cancelled !== false || result.timedOut === true
          || result.truncated !== false || result.workingDir !== workspace
          || result.output !== 'GAUNTLET_SEALED_SETTINGS_CACHE_V1\n'
          || JSON.stringify(shellBefore) !== JSON.stringify(shellAfter)
          || JSON.stringify(shellAfter).includes('gauntlet-hostile-settings')) {
        throw new Error('genuine executeBash did not retain the sealed Settings singleton');
      }
      sealedSettings = { profile: 'bun-1.3.14-sealed-v1', cwd: settings.getCwd(), agentDir: settings.getAgentDir(),
        shellBefore, shellAfter, result, trustedShellProbeCalls: 1, hostileSettingsSources: 3,
        scope: 'Settings cache and genuine fixed executeBash only; Bun startup and allowed-result custody require separate outside proof' };
    }
    console.log(JSON.stringify({ schema: sealed ? 'developer-sdk-inventory-conformance.v2' : 'developer-sdk-inventory-conformance.v1', version: metadata.version,
      before, after, missingRejected, missingDiagnostic, duplicateRejected, providerCalls, toolCalls,
      mcpOnly,
      ...(sealed ? { sealedSettings } : {}),
      actualModelEpisode: false, qualificationEligible: false,
      scope: 'actual SDK registration in controller process; no agent/product namespace conformance',
      uid: process.getuid?.() }));
  } finally {
    try { if (session) await session.dispose(); }
    finally { try { await manager.disconnectAll(); } finally {
      auth.close(); await rm(root, { recursive: true });
      if (hostileHome) await rm(hostileHome, { recursive: true });
    } }
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
