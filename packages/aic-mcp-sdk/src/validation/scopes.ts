/**
 * Parses a space-separated scope string into an array.
 *
 * @param scope - Space-separated scope string (e.g., "read write delete")
 * @returns Array of individual scopes
 */
export const parseScopes = (scope: string | undefined): readonly string[] => {
  if (!scope) {
    return [];
  }
  return scope
    .split(' ')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
};

/**
 * Returns the scopes from `requiredScopes` that are not present in `presentScopes`.
 *
 * @param requiredScopes - Scopes that must be present
 * @param presentScopes - Scopes that are actually present
 * @returns Array of missing scopes (empty if all required scopes are present)
 */
export const getMissingScopes = (
  requiredScopes: readonly string[],
  presentScopes: readonly string[]
): readonly string[] => {
  return requiredScopes.filter((scope) => !presentScopes.includes(scope));
};
