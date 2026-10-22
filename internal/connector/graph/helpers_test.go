package graph_test

import (
	"errors"
	"fmt"

	"github.com/skenzeriq/activediq/internal/connector/graph"
)

func fmtV(v any) string    { return fmt.Sprintf("%v %s", v, v) }
func fmtPlus(v any) string { return fmt.Sprintf("%+v %#v", v, v) }

func asErr(err error, t **graph.Error) bool { return errors.As(err, t) }
