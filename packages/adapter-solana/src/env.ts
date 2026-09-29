import type { z } from "zod";

/**
 * Fails fast with every missing or invalid variable named at once, instead of
 * one cryptic runtime error the first time a field is used deep inside an
 * adapter. Each adapter carries its own copy so it can be used without
 * pulling in a package that knows about every other adapter.
 */
export function parseEnv<T extends z.ZodTypeAny>(
  schema: T,
  source: NodeJS.ProcessEnv,
  label: string
): z.infer<T> {
  const result = schema.safeParse(source);
  if (!result.success) {
    const lines = result.error.issues.map((issue) => `  - ${issue.path.join(".")}: ${issue.message}`);
    throw new Error(`Invalid ${label} configuration:\n${lines.join("\n")}`);
  }
  return result.data;
}
