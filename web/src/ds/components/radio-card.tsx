import { ChoiceGroup, type ChoiceGroupProps } from "./radio-group";

export type RadioCardGroupProps = ChoiceGroupProps;

/**
 * Pick one of a few options that each need a sentence of explanation: how a report runs (schedule
 * preset with its next run), how it is sent. Each option is a card with a radio, a title and a
 * description. For short labels without explanation use SegmentedControl; for six or more options, Select.
 */
export function RadioCardGroup(props: RadioCardGroupProps) {
  return <ChoiceGroup {...props} variant="card" />;
}
