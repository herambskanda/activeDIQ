import { ChoiceGroup, type ChoiceGroupProps } from "./radio-group";

export type SegmentedControlProps = ChoiceGroupProps;

/**
 * Preset chips: choose one of two to five short labels that change what a view shows (the report
 * presets, a period). A selected chip is marked by a check and a heavier border as well as colour.
 * Option descriptions are ignored; use RadioCardGroup when options need explaining.
 */
export function SegmentedControl(props: SegmentedControlProps) {
  return <ChoiceGroup {...props} variant="chip" />;
}
