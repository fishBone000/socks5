package s5i

import "fmt"

type closable interface {
  Close() error
}

func err(err error, a ...any) error {
  if err == nil && len(a) == 0 {
    return nil
  }
  if err == nil {
    return fmt.Errorf("%s", fmt.Sprint(a...))
  }
  if len(a) == 0 {
    return err
  }
  return fmt.Errorf("%s: %w", fmt.Sprint(a...), err)
}
