import { createHmac, timingSafeEqual } from "node:crypto";

export function verifyWebhook(
  rawBody,
  header,
  secrets,
  now = Math.floor(Date.now() / 1000),
) {
  if (
    !Buffer.isBuffer(rawBody) ||
    typeof header !== "string" ||
    header.length > 4096
  )
    return false;
  if (!Array.isArray(secrets) || !secrets.length || !Number.isSafeInteger(now))
    return false;
  const parts = header.split(",").map((part) => part.trim());
  const timestamps = parts.filter((part) => part.startsWith("t="));
  if (timestamps.length !== 1 || !/^t=[0-9]+$/.test(timestamps[0]))
    return false;
  const timestampText = timestamps[0].slice(2);
  const timestamp = Number(timestampText);
  if (!Number.isSafeInteger(timestamp) || Math.abs(now - timestamp) > 300)
    return false;
  const signatures = parts
    .filter((part) => /^v1=[0-9a-f]{64}$/i.test(part))
    .map((part) => Buffer.from(part.slice(3), "hex"));
  if (!signatures.length) return false;
  return secrets.some((secret) => {
    if (typeof secret !== "string" || !secret.length) return false;
    const expected = createHmac("sha256", secret)
      .update(timestampText + ".", "ascii")
      .update(rawBody)
      .digest();
    return signatures.some((signature) => timingSafeEqual(expected, signature));
  });
}
