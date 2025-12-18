/**
 * Parses a scope claim into an array.
 * Handles both space-separated strings (RFC 6749) and arrays (ForgeRock AM).
 *
 * @param scope - Space-separated scope string or array of scopes
 * @returns Array of individual scopes
 */
export const parseScopes = (scope: string | readonly string[] | undefined): readonly string[] => {
  if (scope === undefined) {
    return [];
  }

  // Handle string format (RFC 6749 style)
  if (typeof scope === 'string') {
    return scope
      .split(' ')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
  }

  // Handle array format (ForgeRock AM style)
  return scope.map((s) => s.trim()).filter((s) => s.length > 0);
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
