"use client";

import { motion, useReducedMotion } from "motion/react";
import {
  createElement,
  forwardRef,
  type HTMLAttributes,
  type PointerEvent,
  useState,
} from "react";
import { SPRING_LAYOUT } from "@/components/ui/animated-sidebar-utils/ease";
import { cn } from "@/lib/utils";

export interface SharedLayoutBgProps extends HTMLAttributes<HTMLElement> {
  /** The element to render (the sidebar menu uses "ul"). */
  as?: "ul" | "ol" | "div" | "nav";
  /** Pixels between the pill and the edges of the hovered item. */
  inset?: number;
  /** Classes for the pill itself (shape and colour). */
  pillClassName?: string;
  /** Classes for the box that moves to the hovered item (its size). */
  pillContainerClassName?: string;
}

/**
 * SharedLayoutBg is a list whose items share one hover highlight: a pill
 * that glides to whichever direct child the pointer is over and fades out
 * when it leaves. The pill sits behind the items (it's first in paint
 * order), so items need no extra styling.
 */
export const SharedLayoutBg = forwardRef<HTMLElement, SharedLayoutBgProps>(
  function SharedLayoutBg(
    {
      as = "div",
      inset = 0,
      pillClassName,
      pillContainerClassName,
      className,
      children,
      onPointerMove,
      onPointerLeave,
      ...props
    },
    forwardedRef,
  ) {
    const reduce = useReducedMotion() ?? false;
    const [hover, setHover] = useState<{ y: number; visible: boolean }>({
      y: 0,
      visible: false,
    });

    // In a list, the pill is a presentational list item: a <div> may not sit
    // directly inside <ul>.
    const Pill = as === "ul" || as === "ol" ? motion.li : motion.div;

    const track = (event: PointerEvent<HTMLElement>) => {
      onPointerMove?.(event);
      const root = event.currentTarget;
      // The hovered item is the root's direct child containing the target.
      let item = event.target as HTMLElement | null;
      while (item && item.parentElement !== root) item = item.parentElement;
      if (!item || item.dataset.pill === "true") return;
      setHover({ y: item.offsetTop, visible: true });
    };

    return createElement(
      as,
      {
        ...props,
        ref: forwardedRef,
        className: cn("relative", className),
        onPointerMove: track,
        onPointerLeave: (event: PointerEvent<HTMLElement>) => {
          onPointerLeave?.(event);
          setHover((h) => ({ ...h, visible: false }));
        },
      },
      <Pill
        aria-hidden="true"
        role="presentation"
        data-pill="true"
        initial={false}
        animate={{ y: hover.y, opacity: hover.visible ? 1 : 0 }}
        transition={
          reduce
            ? { duration: 0 }
            : { y: SPRING_LAYOUT, opacity: { duration: 0.15 } }
        }
        style={{ left: inset, right: inset }}
        className={cn(
          "pointer-events-none absolute inset-y-0",
          pillContainerClassName,
        )}
      >
        <div className={cn("absolute inset-0", pillClassName)} />
      </Pill>,
      children,
    );
  },
);
