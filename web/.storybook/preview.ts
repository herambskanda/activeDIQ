import type { Preview } from "@storybook/react-vite";

import "../src/ds/tokens.css";
import "../src/ds/base.css";
import "../src/ds/brand.css";

const preview: Preview = {
  parameters: { layout: "fullscreen", controls: { disable: true }, a11y: { test: "error" } },
};
export default preview;
