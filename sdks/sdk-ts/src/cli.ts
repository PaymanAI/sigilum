#!/usr/bin/env node
import { initIdentity, listNamespaces } from "./identity-store.js";

function printHelp(): void {
  console.log(`Sigilum CLI

Usage:
  sigilum init <namespace> [--force] [--home <path>]
  sigilum list [--home <path>]

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

function run(): void {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === "-h" || command === "--help") {
    printHelp();
    return;
  }

  if (command === "list") {
    const homeDir = readFlagValue(args, "--home");
    const namespaces = listNamespaces(homeDir);
    if (namespaces.length === 0) {
      console.log("No identities found.");
      return;
    }
    for (const namespace of namespaces) {
      console.log(namespace);
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

    console.log(result.created ? "Created Sigilum identity" : "Loaded existing Sigilum identity");
    console.log(`namespace: ${result.namespace}`);
    console.log(`did: ${result.did}`);
    console.log(`keyId: ${result.keyId}`);
    console.log(`publicKey: ${result.publicKey}`);
    console.log(`identityPath: ${result.identityPath}`);
    return;
  }

  throw new Error(`Unknown command: ${command}`);
}

try {
  run();
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
