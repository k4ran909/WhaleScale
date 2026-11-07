// Motion curves shared by the animated sidebar. The component imports these
// from beui.dev's utilities, which weren't part of the copied component;
// these are equivalents: an ease-out for small fades, a drawer curve that
// starts fast and settles softly, and two springs.

/** A strong ease-out (fast start, gentle stop) for fades and small moves. */
export const EASE_OUT = [0.23, 1, 0.32, 1] as const;

/** The drawer curve (as in iOS sheets) for panels sliding in and out. */
export const EASE_DRAWER = [0.32, 0.72, 0, 1] as const;

/** Layout moves: the active highlight gliding between items. */
export const SPRING_LAYOUT = {
  type: "spring",
  stiffness: 500,
  damping: 40,
  mass: 0.8,
} as const;

/** Press feedback: a quick, slightly firm spring for whileTap. */
export const SPRING_PRESS = {
  type: "spring",
  stiffness: 600,
  damping: 32,
  mass: 0.6,
} as const;
