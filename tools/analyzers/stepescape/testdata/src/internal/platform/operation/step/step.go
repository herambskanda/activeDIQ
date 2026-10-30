package step

type Step struct{ s *int }

func (s Step) Valid() error { return nil }
func Use(s Step)            { _ = s }
