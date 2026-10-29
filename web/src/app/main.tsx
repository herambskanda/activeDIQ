import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import "../ds/tokens.css";
import "../ds/base.css";
import "../ds/brand.css";
import { webModules } from "./modules.gen";
import { Shell } from "./shell";

const root = document.getElementById("root");
if (!root) throw new Error("index.html has no #root element");

createRoot(root).render(
  <StrictMode>
    <Shell modules={webModules} />
  </StrictMode>,
);
