import type { DatabaseAdapter } from "../interfaces.js";

export class CloudflareDatabaseAdapter implements DatabaseAdapter {
  constructor(public readonly binding: D1Database) {}

  prepare(...args: Parameters<D1Database["prepare"]>): ReturnType<D1Database["prepare"]> {
    return this.binding.prepare(...args);
  }

  batch(...args: Parameters<D1Database["batch"]>): ReturnType<D1Database["batch"]> {
    return this.binding.batch(...args);
  }
}
