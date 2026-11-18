/// <reference types="@cloudflare/vitest-plugin/types" />
import { applyD1Migrations } from "cloudflare:test";
import { env } from "cloudflare:workers";
import type { Env } from "../src/core";

type WorkerBindings = Env;

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace -- Workers binds env through this global interface.
  namespace Cloudflare {
    interface Env extends WorkerBindings {
      TEST_MIGRATIONS: Parameters<typeof applyD1Migrations>[1];
    }
  }
}

await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
