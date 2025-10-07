import React, { useState, useCallback } from 'react';

// Hook for programmatic context menu control
export const useContextMenu = () => {
  const [isVisible, setIsVisible] = useState(false);
  const [position, setPosition] = useState({ x: 0, y: 0 });

  const show = useCallback((x: number, y: number) => {
    setPosition({ x, y });
    setIsVisible(true);
  }, []);

  const hide = useCallback(() => {
    setIsVisible(false);
  }, []);

  const showAtElement = useCallback((element: HTMLElement) => {
    const rect = element.getBoundingClientRect();
    show(rect.left + rect.width / 2, rect.top + rect.height / 2);
  }, [show]);

  return {
    isVisible,
    position,
    show,
    hide,
    showAtElement,
  };
};

// Higher-order component for adding context menu to any component
export const withContextMenu = <P extends object>(
  Component: React.ComponentType<P>
) => {
  return (props: P) => {
    // Implementation placeholder
    return <Component {...props} />;
  };
};
