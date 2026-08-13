export function futureExpiry(ms = 3_600_000): string {
  return new Date(Date.now() + ms).toISOString();
}
