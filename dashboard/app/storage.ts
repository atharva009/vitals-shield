// Browser storage as an external store, so React reads it with useSyncExternalStore instead of setState-in-effect.
// The server snapshot is a sentinel: the static prerender and hydration render nothing until the client reads storage.

export const UNKNOWN = "\u0000unknown";
const EVENT = "vitalsshield-storage";

type Area = "session" | "local";

function area(a: Area): Storage {
  return a === "session" ? window.sessionStorage : window.localStorage;
}

export function subscribe(callback: () => void): () => void {
  window.addEventListener("storage", callback);
  window.addEventListener(EVENT, callback);
  return () => {
    window.removeEventListener("storage", callback);
    window.removeEventListener(EVENT, callback);
  };
}

export function read(a: Area, key: string): string | null {
  try {
    return area(a).getItem(key);
  } catch {
    return null;
  }
}

export function write(a: Area, key: string, value: string | null): void {
  try {
    if (value === null) area(a).removeItem(key);
    else area(a).setItem(key, value);
  } catch {
    // storage unavailable: the value just will not persist
  }
  window.dispatchEvent(new Event(EVENT));
}
