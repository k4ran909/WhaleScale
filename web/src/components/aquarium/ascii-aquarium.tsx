import { useEffect, useRef } from "react";
import { startAquarium } from "./engine";

/** AsciiAquarium fills the window behind its siblings with the animated
 * ASCII aquarium; with reduced motion it shows a still frame. */
export function AsciiAquarium() {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    if (!ref.current) return;
    const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
    return startAquarium(ref.current, still);
  }, []);
  return <canvas ref={ref} aria-hidden="true" className="pointer-events-none fixed inset-0 z-0 block size-full" />;
}
