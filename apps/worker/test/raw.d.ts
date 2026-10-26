/** Vite's `?raw` imports, which the tests use to load sample emails without Node's file APIs. */
declare module "*?raw" {
  const content: string;
  export default content;
}
