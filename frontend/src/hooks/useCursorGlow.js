import { useEffect, useRef } from "react";

/**
 * High-performance hook for cursor spotlight and magnetic hover interaction.
 * Directly updates CSS custom properties and handles DOM translations via requestAnimationFrame.
 */
export function useCursorGlow({ magnetic = false, magneticStrength = 0.25 } = {}) {
  const ref = useRef(null);

  useEffect(() => {
    const element = ref.current;
    if (!element) return;

    let frameId = null;

    const handleMouseMove = (e) => {
      const rect = element.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;

      if (frameId) {
        cancelAnimationFrame(frameId);
      }

      frameId = requestAnimationFrame(() => {
        element.style.setProperty("--mouse-x", `${x}px`);
        element.style.setProperty("--mouse-y", `${y}px`);

        if (magnetic) {
          const centerX = rect.left + rect.width / 2;
          const centerY = rect.top + rect.height / 2;
          const deltaX = e.clientX - centerX;
          const deltaY = e.clientY - centerY;
          element.style.transform = `translate(${deltaX * magneticStrength}px, ${deltaY * magneticStrength}px)`;
        }
      });
    };

    const handleMouseEnter = () => {
      element.classList.add("cursor-hover");
      if (magnetic) {
        element.style.transition = "transform 0.1s cubic-bezier(0.25, 1, 0.5, 1)";
      }
    };

    const handleMouseLeave = () => {
      element.classList.remove("cursor-hover");
      if (frameId) {
        cancelAnimationFrame(frameId);
      }
      frameId = requestAnimationFrame(() => {
        if (magnetic) {
          element.style.transition = "transform 0.4s cubic-bezier(0.25, 1, 0.5, 1)";
          element.style.transform = "translate(0px, 0px)";
        }
      });
    };

    element.addEventListener("mousemove", handleMouseMove);
    element.addEventListener("mouseenter", handleMouseEnter);
    element.addEventListener("mouseleave", handleMouseLeave);

    return () => {
      element.removeEventListener("mousemove", handleMouseMove);
      element.removeEventListener("mouseenter", handleMouseEnter);
      element.removeEventListener("mouseleave", handleMouseLeave);
      if (frameId) {
        cancelAnimationFrame(frameId);
      }
    };
  }, [magnetic, magneticStrength]);

  return ref;
}
