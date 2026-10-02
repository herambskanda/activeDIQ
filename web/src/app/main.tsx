import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import "../ds/tokens.css";
import "../ds/base.css";
import "../ds/brand.css";
import { Shell } from "./shell";

const root = document.getElementById("root");
if (!root) throw new Error("index.html has no #root element");

// The module list is generated from src/modules by tools/gen/modules once the first module exists.
createRoot(root).render(
  <StrictMode>
    <Shell modules={[]} />
  </StrictMode>,
);
