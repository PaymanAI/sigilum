#!/usr/bin/env node
import { initIdentity, listNamespaces } from "./identity-store.js";
import { pathToFileURL } from "node:url";

type CLIOutput = {
  stdout(line: string): void;
  stderr(line: string): void;
};

const defaultOutput: CLIOutput = {
  stdout: (line) => console.log(line),
  stderr: (line) => console.error(line),
};

function printHelp(output: CLIOutput = defaultOutput): void {
  output.stdout(`Sigilum CLI

Usage:
  sigilum init <namespace> [--force] [--home <path>] [--json]
  sigilum list [--home <path>] [--json]

Environment:
  SIGILUM_HOME        Override identity home directory (default: ~/.sigilum)
  SIGILUM_NAMESPACE   Default namespace for SDK calls
`);
}

function readFlagValue(args: string[], flag: string): string | undefined {
  const index = args.indexOf(flag);
  if (index === -1) {
    return undefined;
  }
  if (index + 1 >= args.length) {
    throw new Error(`Missing value for ${flag}`);
  }
  return args[index + 1];
}

function hasFlag(args: string[], flag: string): boolean {
  return args.includes(flag);
}

export function runCLI(args: string[], output: CLIOutput = defaultOutput): void {
  const command = args[0];

  if (!command || command === "-h" || command === "--help") {
    printHelp(output);
    return;
  }

  if (command === "list") {
    const homeDir = readFlagValue(args, "--home");
    const namespaces = listNamespaces(homeDir);
    if (hasFlag(args, "--json")) {
      output.stdout(
        JSON.stringify({
          command: "list",
          homeDir: homeDir ?? null,
          count: namespaces.length,
          namespaces,
        }),
      );
      return;
    }

    if (namespaces.length === 0) {
      output.stdout("No identities found.");
      return;
    }
    for (const namespace of namespaces) {
      output.stdout(namespace);
    }
    return;
  }

  if (command === "init") {
    const namespace = args[1];
    if (!namespace) {
      throw new Error("Usage: sigilum init <namespace> [--force] [--home <path>]");
    }

    const force = args.includes("--force");
    const homeDir = readFlagValue(args, "--home");

    const result = initIdentity({
      namespace,
      homeDir,
      force,
    });

    if (hasFlag(args, "--json")) {
      output.stdout(
        JSON.stringify({
          command: "init",
          created: result.created,
          namespace: result.namespace,
          did: result.did,
          keyId: result.keyId,
          publicKey: result.publicKey,
          identityPath: result.identityPath,
        }),
      );
      return;
    }

    output.stdout(result.created ? "Created Sigilum identity" : "Loaded existing Sigilum identity");
    output.stdout(`namespace: ${result.namespace}`);
    output.stdout(`did: ${result.did}`);
    output.stdout(`keyId: ${result.keyId}`);
    output.stdout(`publicKey: ${result.publicKey}`);
    output.stdout(`identityPath: ${result.identityPath}`);
    return;
  }

  throw new Error(`Unknown command: ${command}`);
}

function run(): void {
  runCLI(process.argv.slice(2), defaultOutput);
}

function isEntrypoint(): boolean {
  return Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;
}

if (isEntrypoint()) {
  try {
    run();
  } catch (error) {
    defaultOutput.stderr(error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
}
