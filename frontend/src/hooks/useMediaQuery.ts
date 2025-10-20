import { useState, useEffect } from 'react';

/**
 * Hook for responsive breakpoint detection
 * @param query - Media query string (e.g., "(min-width: 768px)")
 */
export const useMediaQuery = (query: string): boolean => {
  const [matches, setMatches] = useState<boolean>(false);

  useEffect(() => {
    const media = window.matchMedia(query);
    if (media.matches !== matches) {
      setMatches(media.matches);
    }

    const listener = () => setMatches(media.matches);
    media.addEventListener('change', listener);

    return () => media.removeEventListener('change', listener);
  }, [matches, query]);

  return matches;
};

/**
 * Tailwind breakpoint helpers
 */
export const useIsMobile = () => useMediaQuery('(max-width: 767px)');
export const useIsTablet = () =>
  useMediaQuery('(min-width: 768px) and (max-width: 1023px)');
export const useIsDesktop = () => useMediaQuery('(min-width: 1024px)');
