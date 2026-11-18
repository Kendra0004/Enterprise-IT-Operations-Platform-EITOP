import "@testing-library/jest-dom/vitest";

/**
 * Node ≥22 exposes a `localStorage` global getter that returns `undefined`
 * unless started with `--localstorage-file`, shadowing jsdom's
 * implementation. Install an in-memory stand-in for tests.
 */
if (typeof localStorage === "undefined" || localStorage === null) {
  const store = new Map<string, string>();
  const memoryStorage: Storage = {
    get length() {
      return store.size;
    },
    clear: () => store.clear(),
    getItem: (key: string) => store.get(key) ?? null,
    key: (index: number) => [...store.keys()][index] ?? null,
    removeItem: (key: string) => void store.delete(key),
    setItem: (key: string, value: string) => void store.set(key, value),
  };
  Object.defineProperty(globalThis, "localStorage", {
    value: memoryStorage,
    configurable: true,
    writable: true,
  });
}
