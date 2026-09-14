/**
 * Formats an ISO-8601 UTC timestamp string into human-readable Indian Standard Time (IST, UTC+05:30).
 * Example: "2026-09-14T14:07:31.606629+00:00" -> "14 Sep 2026, 07:37:31 PM IST"
 * Uses browser's native Intl.DateTimeFormat with Asia/Kolkata (no manual arithmetic).
 */
export function formatToIST(isoStr?: string | null): string {
  if (!isoStr) return 'N/A';
  try {
    const d = new Date(isoStr);
    if (isNaN(d.getTime())) return isoStr;
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: 'Asia/Kolkata',
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: true
    }).formatToParts(d);

    const p: Record<string, string> = {};
    for (const part of parts) {
      p[part.type] = part.value;
    }

    return `${p.day} ${p.month} ${p.year}, ${p.hour}:${p.minute}:${p.second} ${(p.dayPeriod || '').toUpperCase()} IST`;
  } catch {
    return isoStr;
  }
}
