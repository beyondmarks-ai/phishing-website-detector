# Design System Specification: High-End Cybersecurity Editorial

## 1. Overview & Creative North Star
### The Creative North Star: "The Sovereign Sentinel"
This design system moves away from the chaotic "hacker-green on black" tropes of the cybersecurity industry. Instead, it adopts the persona of a **Sovereign Sentinel**: an authoritative, calm, and high-end editorial experience. It treats data like a prestige financial journal rather than a terminal.

To break the "standard dashboard" feel, this system utilizes **Intentional Asymmetry** and **Tonal Depth**. We prioritize breathing room over information density. By using massive `display-lg` typography alongside delicate `label-sm` technical data, we create a rhythmic "High-Low" contrast that feels bespoke and premium. Layouts should favor wide margins and overlapping elements to suggest a multi-layered, sophisticated defense architecture.

---

## 2. Colors & Surface Architecture
The palette is rooted in a "Command Center" aesthetic—deep, authoritative blues paired with surgical precision accents.

### The "No-Line" Rule
**Borders are prohibited for sectioning.** To define space, designers must use background color shifts. A `surface-container-low` section sitting on a `surface` background is the only acceptable way to denote global layout regions. Lines create visual noise; tonal shifts create "zones of focus."

### Surface Hierarchy & Nesting
We treat the UI as stacked sheets of fine paper. Use the following tiers to create natural depth:
*   **Background (`#f7f9fb`):** The canvas.
*   **Surface-Container-Low (`#f2f4f6`):** Secondary regions (e.g., sidebars or utility panels).
*   **Surface-Container-Lowest (`#ffffff`):** High-priority interactive cards and content modules.
*   **Surface-Bright:** Reserved for hover states or active selection focus.

### The "Glass & Gradient" Rule
To inject "soul" into the technical environment, main CTAs and Hero Data Visualizations should utilize subtle gradients transitioning from `primary` (#000000) to `primary_container` (#131b2e). For floating elements (modals, dropdowns), apply **Glassmorphism**: use a semi-transparent surface color with a `20px` backdrop-blur to allow the data underneath to bleed through softly.

---

## 3. Typography
The typography is the backbone of the "Editorial" feel. We pair the technical rigor of **Inter** with the architectural structure of **Space Grotesk**.

*   **Display & Headlines (Space Grotesk):** Use these for high-level security statuses and "at-a-glance" metrics. The slight technical quirk of Space Grotesk provides the "Security" vibe without looking dated.
*   **Body & Labels (Inter):** All functional data, logs, and descriptions use Inter for maximum legibility at small scales.

| Level | Token | Font | Size | Weight | Role |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Display** | `display-lg` | Space Grotesk | 3.5rem | Bold | Hero stats (e.g., Threat Score) |
| **Headline** | `headline-sm` | Space Grotesk | 1.5rem | Medium | Module titles |
| **Title** | `title-md` | Inter | 1.125rem | Semi-Bold | Card headers |
| **Body** | `body-md` | Inter | 0.875rem | Regular | Secondary data / Descriptions |
| **Label** | `label-sm` | Inter | 0.6875rem | Bold/Caps | Technical metadata / Micro-copy |

---

## 4. Elevation & Depth
In this system, "Elevation" is a feeling, not a drop-shadow effect.

### The Layering Principle
Depth is achieved by stacking. A `surface-container-lowest` (#FFFFFF) card placed on a `surface-container-low` (#F2F4F6) section creates a "lift" of exactly 1 level. This is the preferred method for 90% of the UI.

### Ambient Shadows
For floating components (Modals/Popovers), use an "Ambient Shadow":
*   **Blur:** 32px to 64px.
*   **Color:** `on-surface` (#191c1e) at **4% to 6% opacity**.
*   **Spread:** -4px (to keep the shadow "tucked" under the element).

### The "Ghost Border" Fallback
If accessibility requires a border (e.g., in high-contrast modes), use the **Ghost Border**: the `outline_variant` token at **15% opacity**. Never use 100% opaque lines for containment.

---

## 5. Components

### Buttons
*   **Primary:** `primary` background with `on_primary` text. No border. Soft 8px corner.
*   **Secondary:** `surface_container_high` background. Text is `on_surface`.
*   **Tertiary:** No background. `primary` text. Used for "Cancel" or "Dismiss."

### Cards & Lists
**Forbid the use of divider lines.** To separate list items, use 12px of vertical white space or a subtle `0.5rem` stagger in background tint. Cards must use the `DEFAULT` (8px) corner radius.

### Input Fields
Inputs should feel integrated. Use `surface_container_low` for the fill. The active state is denoted by a `2px` "Ghost Border" of the `primary` color and a subtle `2%` tint shift.

### Signature Component: The "Security Pulse"
For real-time logs, do not use a standard table. Use a **Stream Component**: A vertical layout where the `surface-container-lowest` cards slightly overlap each other by `4px`, creating a physical "shingled" effect that suggests a continuous flow of protected data.

---

## 6. Do's and Don'ts

### Do:
*   **Use Asymmetric Margins:** Give more space to the "Status" side of a dashboard than the "Settings" side to guide the eye.
*   **Use Mono Accents:** For IP addresses, hashes, and timestamps, use a Monospace font at `label-sm` to lean into the "technical" mood.
*   **Embrace "Empty" Space:** If a page only has three metrics, let them be large and centered. Do not feel the need to fill the screen with "empty" boxes.

### Don't:
*   **No "Pure" Grey Shadows:** Shadows should always be tinted with a hint of the `on-primary-fixed` blue.
*   **No Red Text for Errors:** Use the `error_container` as a background and `on_error_container` for the text. Pure red text on white is for amateur systems; we prefer "Integrated Alerting."
*   **No Icons in Boxes:** Icons should float freely next to their labels. Putting an icon in a small box creates "visual knots" that break the editorial flow.