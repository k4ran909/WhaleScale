import { CircleAlert, CircleCheck, Info, X } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { useEffect, useRef, useState } from "react";

/** Toasts: short messages that pop up in a corner and go away by
 * themselves, for the results of actions ("Saved", "Removed laptop") and
 * errors. Ongoing state (things waiting for approval) stays in banners on
 * the page. Call toast.success / toast.error / toast.info from anywhere. */

type Kind = "success" | "error" | "info";
type Item = { id: number; kind: Kind; text: string; ms: number; bump: number };

const durations: Record<Kind, number> = { success: 4000, info: 5000, error: 7000 };
const maxShown = 4;

let items: Item[] = [];
let nextID = 1;
const listeners = new Set<(items: Item[]) => void>();

function emit() {
  for (const l of listeners) l(items);
}

function push(kind: Kind, text: string) {
  text = text.trim();
  if (!text) return;
  // The same message again (a page retrying, a double click) restarts the
  // one already showing instead of stacking a copy.
  const same = items.find((t) => t.kind === kind && t.text === text);
  if (same) {
    items = items.map((t) => (t === same ? { ...t, bump: t.bump + 1 } : t));
  } else {
    items = [...items, { id: nextID++, kind, text, ms: durations[kind], bump: 0 }].slice(-maxShown);
  }
  emit();
}

function dismiss(id: number) {
  items = items.filter((t) => t.id !== id);
  emit();
}

export const toast = {
  success: (text: string) => push("success", text),
  error: (text: string) => push("error", text),
  info: (text: string) => push("info", text),
};

const icons: Record<Kind, typeof Info> = { success: CircleCheck, error: CircleAlert, info: Info };
const accents: Record<Kind, string> = {
  success: "text-[var(--ok,#16a34a)]",
  error: "text-[var(--bad,#dc2626)]",
  info: "text-foreground",
};

/** Toaster shows the toasts; render it once, at the root. */
export function Toaster() {
  const [list, setList] = useState<Item[]>(items);
  useEffect(() => {
    listeners.add(setList);
    return () => {
      listeners.delete(setList);
    };
  }, []);
  return (
    <div
      aria-live="polite"
      className="pointer-events-none fixed inset-x-0 bottom-0 z-[100] flex flex-col items-center gap-2 p-4 sm:inset-x-auto sm:right-0 sm:items-end"
      style={{ paddingBottom: "calc(1rem + env(safe-area-inset-bottom, 0px))" }}
    >
      <AnimatePresence initial={false}>
        {list.map((t) => (
          <ToastCard key={t.id} item={t} />
        ))}
      </AnimatePresence>
    </div>
  );
}

function ToastCard({ item }: { item: Item }) {
  const [paused, setPaused] = useState(false);
  const left = useRef(item.ms);
  const started = useRef(Date.now());
  // Counts down while the pointer isn't on it; a repeat of the same
  // message (bump) starts the count again.
  useEffect(() => {
    left.current = item.ms;
  }, [item.bump, item.ms]);
  useEffect(() => {
    if (paused) return;
    started.current = Date.now();
    const timer = setTimeout(() => dismiss(item.id), left.current);
    return () => {
      clearTimeout(timer);
      left.current -= Date.now() - started.current;
    };
  }, [paused, item.id, item.bump]);
  const Icon = icons[item.kind];
  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 16, scale: 0.97 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, x: 24, transition: { duration: 0.15 } }}
      transition={{ type: "spring", stiffness: 500, damping: 38 }}
      role={item.kind === "error" ? "alert" : "status"}
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
      className="pointer-events-auto flex w-full max-w-sm items-start gap-3 rounded-xl border border-border bg-background px-4 py-3 text-sm text-foreground shadow-lg shadow-black/10"
    >
      <Icon aria-hidden="true" className={`mt-0.5 size-4 shrink-0 ${accents[item.kind]}`} />
      <p className="m-0 min-w-0 flex-1 break-words leading-snug">{item.text}</p>
      <button
        type="button"
        aria-label="Dismiss"
        onClick={() => dismiss(item.id)}
        className="-m-1 shrink-0 cursor-pointer rounded-md border-0 bg-transparent p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
      >
        <X aria-hidden="true" className="size-3.5" />
      </button>
    </motion.div>
  );
}
