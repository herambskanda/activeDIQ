import type { StorybookConfig } from "@storybook/react-vite";

// Design prototype only (T-0672). Stories and their sample fixtures are never part of `vite build`:
// the console bundle starts at index.html and nothing in src/app imports src/prototype.
const config: StorybookConfig = {
  stories: ["../src/prototype/**/*.stories.tsx"],
  addons: ["@storybook/addon-a11y"],
  framework: "@storybook/react-vite",
  core: { disableTelemetry: true },
};
export default config;
