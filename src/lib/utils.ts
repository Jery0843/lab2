/**
 * Parses a tags property which can be a string[], a JSON string, or a comma-separated string.
 * @param tags The tags property to parse.
 * @returns An array of strings.
 */
export function parseTags(tags: string[] | string | null | undefined): string[] {
  if (!tags) return [];
  if (Array.isArray(tags)) {
    return tags;
  }
  if (typeof tags === 'string') {
    try {
      // Try to parse as JSON array first
      const parsed = JSON.parse(tags);
      return Array.isArray(parsed) ? parsed : [tags];
    } catch {
      // If parsing fails, split by comma or treat as single tag
      return tags.includes(',') ? tags.split(',').map(t => t.trim()) : [tags];
    }
  }
  return [];
}

/**
 * Gets the user's IP address from request headers.
 * @param request The NextRequest object
 * @returns The user's IP address
 */
export function getUserIP(request: Request): string {
  return request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown';
}
