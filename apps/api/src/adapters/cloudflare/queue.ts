import type { QueueAdapter } from "../interfaces.js";

export class CloudflareQueueAdapter<TMessage = unknown> implements QueueAdapter<TMessage> {
  constructor(private readonly binding: Queue) {}

  async send(
    message: TMessage,
    options?: { delaySeconds?: number },
  ): Promise<void> {
    await this.binding.send(message as any, options);
  }
}
